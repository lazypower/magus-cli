package applygraph

import (
	"strings"
	"testing"

	"github.com/lazypower/magus-cli/internal/graph"
)

func sampleGraph() *graph.Graph {
	g := graph.New()
	g.AddEdge("/etc/app", "/etc/app/x.env", graph.Require, "directory containment")
	g.AddEdge("/etc/app/x.env", "web.service", graph.Notify, "EnvironmentFile= reference")
	g.AddEdge("db.service", "web.service", graph.Order, "") // empty reason → kind fallback
	g.AddNode("lonely.service")
	return g
}

func TestDOT(t *testing.T) {
	dot := DOT(sampleGraph())
	if !strings.HasPrefix(dot, "digraph magus {") {
		t.Errorf("DOT should open a digraph:\n%s", dot)
	}
	if !strings.HasSuffix(strings.TrimSpace(dot), "}") {
		t.Errorf("DOT should close the brace:\n%s", dot)
	}
	// Every node emitted (so isolated ones draw), quoted.
	for _, n := range []string{`"/etc/app";`, `"lonely.service";`, `"web.service";`} {
		if !strings.Contains(dot, n) {
			t.Errorf("DOT missing node decl %s:\n%s", n, dot)
		}
	}
	// Edges carry provenance labels and kind-encoded styles.
	for _, e := range []string{
		`"/etc/app" -> "/etc/app/x.env" [label="directory containment", style=solid];`,
		`"/etc/app/x.env" -> "web.service" [label="EnvironmentFile= reference", style=dashed];`,
		`"db.service" -> "web.service" [label="order", style=dotted];`, // empty reason → kind
	} {
		if !strings.Contains(dot, e) {
			t.Errorf("DOT missing edge %s:\n%s", e, dot)
		}
	}
	// Structural: every non-decl edge line has an arrow.
	for line := range strings.SplitSeq(dot, "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "label=") && !strings.Contains(l, "->") {
			t.Errorf("edge line without arrow: %q", l)
		}
	}
}

func TestPlain(t *testing.T) {
	p := Plain(sampleGraph())
	if !strings.Contains(p, "5 nodes, 3 edges") {
		t.Errorf("plain header wrong:\n%s", p)
	}
	for _, want := range []string{
		"/etc/app → /etc/app/x.env  (directory containment) [require]",
		"/etc/app/x.env → web.service  (EnvironmentFile= reference) [notify]",
		"db.service → web.service  (order) [order]", // empty reason falls back to kind
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plain missing edge %q:\n%s", want, p)
		}
	}
	// Isolated node listed under its own heading.
	if !strings.Contains(p, "isolated:") || !strings.Contains(p, "  lonely.service") {
		t.Errorf("plain missing isolated node:\n%s", p)
	}
}

func TestRenderEmptyGraph(t *testing.T) {
	g := graph.New()
	if dot := DOT(g); !strings.Contains(dot, "digraph magus {") || !strings.Contains(dot, "}") {
		t.Errorf("empty DOT malformed:\n%s", dot)
	}
	if p := Plain(g); !strings.Contains(p, "0 nodes, 0 edges") {
		t.Errorf("empty plain wrong:\n%s", p)
	}
}
