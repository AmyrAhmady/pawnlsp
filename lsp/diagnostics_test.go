package lsp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	analysis "github.com/pawnkit/pawn-analysis"
	"github.com/pawnkit/pawn-analysis/preprocess"
	"github.com/pawnkit/pawn-analysis/sema"
	coresource "github.com/pawnkit/pawnkit-core/source"
	lintdiagnostic "github.com/pawnkit/pawnlint/pkg/diagnostic"
	"github.com/pawnkit/pawnlint/pkg/lint"
	"github.com/pawnkit/pawnlint/pkg/rules"
)

func TestWorkspaceDiagnosticsSkipsOpenDocuments(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.pwn")
	uri := coresource.FileURI(path).String()
	result := analysis.Analyze([]byte("main() { Missing(); }\n"), analysis.Options{
		URI:   coresource.URI(uri),
		Names: sema.MapResolver{},
	})
	if len(result.Diagnostics) == 0 {
		t.Fatal("analysis produced no diagnostic for the test source")
	}

	var output bytes.Buffer
	s := &server{
		out:       &output,
		documents: map[string]*document{uri: {URI: uri, Path: path, Root: root}},
		workspaces: map[string]*workspaceIndex{root: {
			root: root, ready: closedChannel(), diagnosticsReady: closedChannel(), graph: result,
		}},
	}
	readItems := func() []struct {
		URI string `json:"uri"`
	} {
		body, err := readFrame(bufio.NewReader(bytes.NewReader(output.Bytes())))
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Result struct {
				Items []struct {
					URI string `json:"uri"`
				} `json:"items"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		return response.Result.Items
	}

	if err := s.workspaceDiagnostics(context.Background(), json.RawMessage("1"), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if items := readItems(); len(items) != 0 {
		t.Fatalf("open document diagnostics = %#v, want none", items)
	}

	output.Reset()
	delete(s.documents, uri)
	if err := s.workspaceDiagnostics(context.Background(), json.RawMessage("2"), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	items := readItems()
	if len(items) != 1 || items[0].URI != uri {
		t.Fatalf("closed document diagnostics = %#v, want %q", items, uri)
	}
}

func TestEmptyDiagnosticsEncodeAsArray(t *testing.T) {
	body, err := json.Marshal(map[string]any{"items": dedupeDiagnostics(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"items":[]}` {
		t.Fatalf("response = %s", body)
	}
}

func TestCompilerAcceptedDeclarationsInDocumentDiagnostics(t *testing.T) {
	tests := []struct {
		name, text string
	}{
		{"explicit enum tags", "enum _:First { FirstValue }\nenum _:Second { SecondValue }\nmain() {}\n"},
		{"callback macro", `#define Callback:%0(%1) forward %0(%1); public %0(%1)
stock bool:Value() { return true; }
Callback:Run() return Value();
main() {}
`},
		{"command alias macro", `#define CMD:%1(%2) forward cmd_%1(%2); public cmd_%1(%2)
#define Link:%1->%2; CMD:%1() return cmd_%2();
CMD:flip() { return 1; }
Link:fl->flip;
main() {}
`},
		{"command macro return tag", `#define DECLARE:%1(%2) forward cmd_%1(%2); public cmd_%1(%2)
#define CMD:%1(%2) DECLARE:%1(%2)
native bool:SendMessage(playerid);
CMD:example(playerid) { return SendMessage(playerid); }
main() {}
`},
		{"textual macro in a case label", `#define HASH (_:HASH_TEXT:HASH_VALUE
#define HASH_TEXT:HASH_VALUE<%0> 1)
main() {
    switch (0) {
        case HASH<Next page>: return 1;
        default: return 0;
    }
}
`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uri := tempDocumentURI(t)
			var input, output bytes.Buffer
			frame(t, &input, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{}})
			frame(t, &input, map[string]any{"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": map[string]any{
				"textDocument": map[string]any{"uri": uri, "version": 1, "text": test.text},
			}})
			frame(t, &input, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "textDocument/diagnostic", "params": map[string]any{
				"textDocument": map[string]any{"uri": uri},
			}})
			frame(t, &input, map[string]any{"jsonrpc": "2.0", "method": "exit"})
			if err := Run(&input, &output); err != nil {
				t.Fatal(err)
			}

			reader := bufio.NewReader(&output)
			for {
				body, err := readFrame(reader)
				if err != nil {
					t.Fatalf("missing diagnostics response: %v", err)
				}
				var response struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
					Result struct {
						Kind  string          `json:"kind"`
						Items []lspDiagnostic `json:"items"`
					} `json:"result"`
				}
				if err := json.Unmarshal(body, &response); err != nil {
					t.Fatal(err)
				}
				if response.Method != "" || string(response.ID) != "2" {
					continue
				}
				if response.Result.Kind != "full" || len(response.Result.Items) != 0 {
					t.Fatalf("expected an empty full diagnostic report, got %s", body)
				}
				break
			}
		})
	}
}

func TestPreserveDiagnosticsShiftsOnlyUnaffectedFindings(t *testing.T) {
	items := lint.NewEngine(rules.Default()).LintFile(
		"test.pwn", []byte("main() { new a; a = a; new b; b = b; }\n"), lint.ProjectAnalysis,
		map[string]lintdiagnostic.Severity{"self-assignment": lintdiagnostic.SeverityWarning}, nil, nil,
	)
	if len(items) != 2 {
		t.Fatalf("lint findings = %#v, want two findings", items)
	}
	first, second := items[0], items[1]
	if first.RuleID != "self-assignment" || second.RuleID != "self-assignment" {
		t.Fatalf("lint findings = %#v", items)
	}
	insertAt := second.Range.Start.Offset - 1
	got := preserveDiagnostics(items, &preprocess.CompatibleEdit{
		Before: preprocess.ByteRange{Start: insertAt, End: insertAt},
		After:  preprocess.ByteRange{Start: insertAt, End: insertAt + 2},
	})
	if len(got) != 2 {
		t.Fatalf("preserved = %#v, want two findings", got)
	}
	if got[0].Range.Start.Offset != first.Range.Start.Offset || got[0].Range.End.Offset != first.Range.End.Offset {
		t.Fatalf("before finding = %#v", got[0])
	}
	if got[1].Range.Start.Offset != second.Range.Start.Offset+2 || got[1].Range.End.Offset != second.Range.End.Offset+2 {
		t.Fatalf("after finding = %#v", got[1])
	}
	if got := preserveDiagnostics(items, &preprocess.CompatibleEdit{
		Before: preprocess.ByteRange{Start: second.Range.Start.Offset, End: second.Range.End.Offset},
		After:  preprocess.ByteRange{Start: second.Range.Start.Offset, End: second.Range.Start.Offset},
	}); len(got) != 1 {
		t.Fatalf("overlapping findings = %#v, want one finding", got)
	}
}

func TestPreserveDiagnosticsRejectsWholeDocumentChanges(t *testing.T) {
	items := []lintdiagnostic.Diagnostic{{RuleID: "old"}}
	if got := preserveDiagnostics(items, nil); got != nil {
		t.Fatalf("preserved = %#v, want nil", got)
	}
}

func TestPreserveAnalysisShiftsRootFindings(t *testing.T) {
	result := analysis.Analyze([]byte("main() { Missing(); }\n"), analysis.Options{
		URI:   coresource.FileURI("test.pwn"),
		Names: sema.MapResolver{},
	})
	var originalStart coresource.Offset
	for _, item := range result.Diagnostics {
		if item.Primary.File == result.File {
			originalStart = item.Primary.Start
			break
		}
	}
	if originalStart == 0 {
		t.Fatalf("analysis diagnostics = %#v, want a root-file finding", result.Diagnostics)
	}

	got := preserveAnalysis(result, &preprocess.CompatibleEdit{
		Before: preprocess.ByteRange{Start: 0, End: 0},
		After:  preprocess.ByteRange{Start: 0, End: 2},
	})
	if got == nil || len(got.Diagnostics) == 0 {
		t.Fatalf("preserved analysis = %#v, want root finding", got)
	}
	if got.Diagnostics[0].Primary.Start != originalStart+2 {
		t.Fatalf("preserved start = %d, want %d", got.Diagnostics[0].Primary.Start, originalStart+2)
	}
}

func TestDedupeDiagnosticsIgnoresProducerCode(t *testing.T) {
	rng := lspRange{Start: position{Line: 4, Character: 2}, End: position{Line: 4, Character: 8}}
	items := []lspDiagnostic{
		{Code: "unreachable-code", Severity: 2, Range: rng, Message: "unreachable statement"},
		{Code: "pawn-analysis:sema/unreachable", Severity: 2, Range: rng, Message: "unreachable statement"},
		{Code: "other-rule", Severity: 2, Range: rng, Message: "a different finding"},
	}

	got := dedupeDiagnostics(items)
	if len(got) != 2 {
		t.Fatalf("deduplicated diagnostics = %#v, want two findings", got)
	}
	if got[0].Code != "unreachable-code" || got[1].Code != "other-rule" {
		t.Fatalf("deduplicated diagnostics = %#v", got)
	}
}

func TestDedupeDiagnosticsKeepsDifferentSeverities(t *testing.T) {
	rng := lspRange{Start: position{Line: 1, Character: 0}, End: position{Line: 1, Character: 3}}
	items := []lspDiagnostic{
		{Code: "warning-rule", Severity: 2, Range: rng, Message: "same text"},
		{Code: "error-rule", Severity: 1, Range: rng, Message: "same text"},
	}

	if got := dedupeDiagnostics(items); len(got) != len(items) {
		t.Fatalf("deduplicated diagnostics = %#v, want both severities", got)
	}
}

func TestMacroInvocationIndexFindsContainingSpan(t *testing.T) {
	index := macroInvocationIndex{
		spans:  []macroInvocationSpan{{start: 10, end: 20}, {start: 15, end: 17}, {start: 30, end: 40}},
		maxEnd: []int{20, 20, 40},
	}
	for _, test := range []struct {
		start int
		end   int
		want  bool
	}{
		{start: 10, end: 20, want: true},
		{start: 16, end: 18, want: true},
		{start: 30, end: 35, want: true},
		{start: 5, end: 10, want: false},
		{start: 21, end: 22, want: false},
	} {
		if got := index.contains(test.start, test.end); got != test.want {
			t.Errorf("contains(%d, %d) = %t, want %t", test.start, test.end, got, test.want)
		}
	}
}
