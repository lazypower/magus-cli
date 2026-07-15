package applygraph

import (
	"fmt"
	"strings"

	"github.com/lazypower/magus-cli/internal/graph"
)

// DOT renders g as a Graphviz digraph. Edge labels carry the derivation
// provenance; edge style encodes the kind (notify dashed, require solid, order
// dotted) so a reader can see change-propagation vs ordering at a glance. Every
// node is emitted, so isolated resources (no dependencies) still appear.
func DOT(g *graph.Graph) string {
	var b strings.Builder
	b.WriteString("digraph magus {\n")
	b.WriteString("  rankdir=LR;\n")
	b.WriteString("  node [shape=box];\n")
	for _, n := range g.Nodes() {
		fmt.Fprintf(&b, "  %q;\n", n)
	}
	for _, e := range g.Edges() {
		fmt.Fprintf(&b, "  %q -> %q [label=%q, style=%s];\n", e.From, e.To, edgeLabel(e), dotStyle(e.Kind))
	}
	b.WriteString("}\n")
	return b.String()
}

// Plain lists the graph's edges with provenance and kind, one per line, plus any
// isolated nodes — the human-readable debugging view.
func Plain(g *graph.Graph) string {
	edges := g.Edges()
	nodes := g.Nodes()
	var b strings.Builder
	fmt.Fprintf(&b, "%d nodes, %d edges\n", len(nodes), len(edges))

	if len(edges) > 0 {
		b.WriteString("\n")
		for _, e := range edges {
			fmt.Fprintf(&b, "  %s → %s  (%s) [%s]\n", e.From, e.To, edgeLabel(e), e.Kind)
		}
	}

	inEdge := make(map[string]bool, len(nodes))
	for _, e := range edges {
		inEdge[e.From] = true
		inEdge[e.To] = true
	}
	var iso []string
	for _, n := range nodes {
		if !inEdge[n] {
			iso = append(iso, n)
		}
	}
	if len(iso) > 0 {
		b.WriteString("\nisolated:\n")
		for _, n := range iso {
			fmt.Fprintf(&b, "  %s\n", n)
		}
	}
	return b.String()
}

// edgeLabel is the edge's provenance, falling back to the kind name when a
// derivation left no reason.
func edgeLabel(e graph.Edge) string {
	if e.Reason != "" {
		return e.Reason
	}
	return e.Kind.String()
}

func dotStyle(k graph.Kind) string {
	switch k {
	case graph.Notify:
		return "dashed"
	case graph.Order:
		return "dotted"
	default: // Require
		return "solid"
	}
}
