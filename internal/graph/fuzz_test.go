package graph

import (
	"errors"
	"fmt"
	"testing"
)

// FuzzTopoSort drives arbitrary graphs (including cyclic ones) through TopoSort
// and asserts the core contract holds either way:
//
//   - success → the result is a permutation of the nodes and respects every edge;
//   - failure → it is a *CycleError, and every reported cycle is a genuine closed
//     loop whose edges all exist in the graph.
//
// It also checks Reverse round-trips (Reverse∘Reverse preserves the edge set).
func FuzzTopoSort(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{3, 0, 1, 0, 1, 2, 0})       // small chain
	f.Add([]byte{2, 0, 1, 0, 1, 0, 0})       // a→b and b→a (cycle)
	f.Add([]byte{4, 0, 0, 1, 1, 1, 2, 2, 3}) // self-loop + edges

	f.Fuzz(func(t *testing.T, data []byte) {
		g := decodeGraph(data)

		// Reverse must round-trip regardless of cyclicity.
		if rr := g.Reverse().Reverse(); !sameEdgeSet(rr, g) {
			t.Fatalf("Reverse∘Reverse changed the edge set\n got %+v\nwant %+v", rr.Edges(), g.Edges())
		}

		order, err := g.TopoSort()
		if err == nil {
			assertPermutation(t, g, order)
			assertRespectsEdges(t, g, order)
			return
		}

		var ce *CycleError
		if !errors.As(err, &ce) {
			t.Fatalf("non-cycle error from TopoSort: %T %v", err, err)
		}
		if len(ce.Cycles) == 0 {
			t.Fatal("CycleError with no cycles")
		}
		for _, cyc := range ce.Cycles {
			assertClosedLoop(t, g, cyc)
		}
	})
}

// decodeGraph turns fuzz bytes into a small graph. The first byte sets the node
// count (1..8, nodes "n0".."n7"); each following triple (from, to, kind) adds an
// edge, deliberately allowing self-loops and cycles.
func decodeGraph(data []byte) *Graph {
	g := New()
	n := 1
	if len(data) > 0 {
		n = int(data[0]%8) + 1
	}
	nodes := make([]string, n)
	for i := range nodes {
		nodes[i] = fmt.Sprintf("n%d", i)
		g.AddNode(nodes[i])
	}
	for i := 1; i+2 < len(data); i += 3 {
		from := nodes[int(data[i])%n]
		to := nodes[int(data[i+1])%n]
		kind := Kind(int(data[i+2]) % 3)
		g.AddEdge(from, to, kind, "")
	}
	return g
}

func sameEdgeSet(a, b *Graph) bool {
	ea, eb := a.Edges(), b.Edges()
	if len(ea) != len(eb) {
		return false
	}
	for i := range ea {
		if ea[i] != eb[i] {
			return false
		}
	}
	return true
}
