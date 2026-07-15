package graph

import (
	"sort"
	"strings"
)

// TopoSort returns the node IDs in a stable topological order — every edge's
// From precedes its To — with ties broken lexicographically by node ID so the
// order is identical run-to-run regardless of insertion order. It uses Kahn's
// algorithm over a lexicographically-ordered ready set.
//
// If the graph contains a cycle it returns a *CycleError naming the entangled
// resources and the provenance of each edge in the loop; the returned slice is
// nil in that case.
func (g *Graph) TopoSort() ([]string, error) {
	indeg := make(map[string]int, len(g.nodes))
	for n := range g.nodes {
		indeg[n] = 0
	}
	for _, e := range g.Edges() {
		indeg[e.To]++
	}

	// ready holds every in-degree-0 node, kept sorted so we always emit the
	// lexicographically smallest available node next.
	var ready []string
	for n, d := range indeg {
		if d == 0 {
			ready = append(ready, n)
		}
	}
	sort.Strings(ready)

	order := make([]string, 0, len(g.nodes))
	for len(ready) > 0 {
		n := ready[0]
		ready = ready[1:]
		order = append(order, n)
		for _, e := range g.outEdges(n) {
			indeg[e.To]--
			if indeg[e.To] == 0 {
				ready = sortedInsert(ready, e.To)
			}
		}
	}

	if len(order) < len(g.nodes) {
		// Whatever never reached in-degree 0 is tangled in a cycle.
		return nil, g.cycleError()
	}
	return order, nil
}

// sortedInsert inserts s into the already-sorted slice, keeping it sorted.
func sortedInsert(sorted []string, s string) []string {
	i := sort.SearchStrings(sorted, s)
	sorted = append(sorted, "")
	copy(sorted[i+1:], sorted[i:])
	sorted[i] = s
	return sorted
}

// CycleError reports one or more dependency cycles. Each element of Cycles is an
// ordered edge loop (edge[i].To == edge[i+1].From, and the last edge closes back
// to the first edge's From). Independent tangles are reported once each.
type CycleError struct {
	Cycles [][]Edge
}

// Error renders every cycle with each edge's provenance, e.g.:
//
//	dependency cycle:
//	  /etc/magus.d/a.env → ollama.container  (EnvironmentFile= reference)
//	  ollama.container → /etc/magus.d/a.env  (directory containment)
func (e *CycleError) Error() string {
	var b strings.Builder
	b.WriteString("dependency cycle:")
	for i, cyc := range e.Cycles {
		if i > 0 {
			b.WriteString("\n  ---")
		}
		for _, ed := range cyc {
			reason := ed.Reason
			if reason == "" {
				reason = ed.Kind.String()
			}
			b.WriteString("\n  ")
			b.WriteString(ed.From)
			b.WriteString(" → ")
			b.WriteString(ed.To)
			b.WriteString("  (")
			b.WriteString(reason)
			b.WriteString(")")
		}
	}
	return b.String()
}

// cycleError builds the CycleError by finding every non-trivial strongly
// connected component (each an independent tangle) and extracting one
// representative simple cycle from each, with a deterministic starting node so
// the diagnostic is stable run-to-run.
func (g *Graph) cycleError() *CycleError {
	var cycles [][]Edge
	for _, scc := range g.stronglyConnected() {
		switch {
		case len(scc) > 1:
			cycles = append(cycles, g.extractCycle(scc))
		case len(scc) == 1 && g.hasSelfLoop(scc[0]):
			cycles = append(cycles, g.extractCycle(scc))
		}
	}
	// Deterministic order across tangles: by the first edge of each cycle.
	sort.Slice(cycles, func(i, j int) bool {
		a, b := cycles[i][0], cycles[j][0]
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return &CycleError{Cycles: cycles}
}

func (g *Graph) hasSelfLoop(n string) bool {
	for _, e := range g.adj[n] {
		if e.To == n {
			return true
		}
	}
	return false
}

// stronglyConnected returns the SCCs of the graph via Tarjan's algorithm.
// Neighbors and roots are visited in lexicographic order so the decomposition —
// and thus the cycle extracted from each component — is deterministic.
func (g *Graph) stronglyConnected() [][]string {
	index := make(map[string]int, len(g.nodes))
	low := make(map[string]int, len(g.nodes))
	onStack := make(map[string]bool, len(g.nodes))
	var stack []string
	next := 0
	var sccs [][]string

	var strongconnect func(v string)
	strongconnect = func(v string) {
		index[v] = next
		low[v] = next
		next++
		stack = append(stack, v)
		onStack[v] = true

		for _, e := range g.outEdges(v) {
			w := e.To
			if _, seen := index[w]; !seen {
				strongconnect(w)
				if low[w] < low[v] {
					low[v] = low[w]
				}
			} else if onStack[w] {
				if index[w] < low[v] {
					low[v] = index[w]
				}
			}
		}

		if low[v] == index[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			sort.Strings(comp)
			sccs = append(sccs, comp)
		}
	}

	for _, v := range g.Nodes() {
		if _, seen := index[v]; !seen {
			strongconnect(v)
		}
	}
	return sccs
}

// extractCycle returns one simple cycle within a strongly connected component as
// an ordered edge loop. Walking from the component's lexicographically smallest
// node and always taking the smallest in-component out-edge, each step either
// reaches a node already on the path — closing the loop — or extends to a fresh
// one. Strong connectivity guarantees the walk closes without ever needing to
// back out: a node's in-component successor is always reachable back to the
// path. A single node with a self-loop yields a one-edge cycle.
func (g *Graph) extractCycle(scc []string) []Edge {
	inSCC := make(map[string]bool, len(scc))
	for _, n := range scc {
		inSCC[n] = true
	}
	nodes := append([]string(nil), scc...)
	sort.Strings(nodes)

	pos := map[string]int{} // node -> index in pathEdges when it was entered
	var pathEdges []Edge
	for u := nodes[0]; ; {
		pos[u] = len(pathEdges)
		e, ok := g.firstInSCCEdge(u, inSCC)
		if !ok {
			// Unreachable for a real SCC (every member lies on an in-component
			// cycle); guard against misuse rather than spin.
			return pathEdges
		}
		if idx, seen := pos[e.To]; seen {
			return append(append([]Edge(nil), pathEdges[idx:]...), e)
		}
		pathEdges = append(pathEdges, e)
		u = e.To
	}
}

// firstInSCCEdge returns u's smallest (deterministic) out-edge whose target is
// in the component, and whether one exists.
func (g *Graph) firstInSCCEdge(u string, inSCC map[string]bool) (Edge, bool) {
	for _, e := range g.outEdges(u) {
		if inSCC[e.To] {
			return e, true
		}
	}
	return Edge{}, false
}
