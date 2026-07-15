package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lazypower/magus-cli/internal/graph"
)

func TestRenderGraphPlainAndDOT(t *testing.T) {
	g := graph.New()
	g.AddEdge("/etc/a", "/etc/a/b", graph.Require, "directory containment")

	// Plain: prefixed with the source, edges listed, exit 0 (acyclic).
	var out, errw bytes.Buffer
	if code := renderGraph(&out, &errw, "src.bu", g, false); code != 0 {
		t.Fatalf("plain render code = %d, want 0", code)
	}
	if !strings.HasPrefix(out.String(), "src.bu → ") {
		t.Errorf("plain output not prefixed with source:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "/etc/a → /etc/a/b") {
		t.Errorf("plain output missing edge:\n%s", out.String())
	}

	// DOT: graphviz digraph.
	out.Reset()
	if code := renderGraph(&out, &errw, "src.bu", g, true); code != 0 {
		t.Fatalf("dot render code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "digraph magus {") {
		t.Errorf("dot output not a digraph:\n%s", out.String())
	}
}

func TestRenderGraphCycleIsInputBad(t *testing.T) {
	// A cyclic graph is input-bad (exit 1): the graph is still rendered, with the
	// cycle diagnostic on stderr.
	g := graph.New()
	g.AddEdge("a", "b", graph.Order, "one")
	g.AddEdge("b", "a", graph.Order, "two")

	var out, errw bytes.Buffer
	code := renderGraph(&out, &errw, "src.bu", g, false)
	if code != 1 {
		t.Fatalf("cyclic render code = %d, want 1", code)
	}
	if !strings.Contains(errw.String(), "dependency cycle") {
		t.Errorf("cycle diagnostic not on stderr:\n%s", errw.String())
	}
	// The graph is still shown so the operator can see the tangle.
	if !strings.Contains(out.String(), "a → b") {
		t.Errorf("graph not rendered alongside the cycle error:\n%s", out.String())
	}
}
