package graph

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// ---- helpers ---------------------------------------------------------------

// positions maps each node ID to its index in a topological order.
func positions(order []string) map[string]int {
	pos := make(map[string]int, len(order))
	for i, n := range order {
		pos[n] = i
	}
	return pos
}

// assertRespectsEdges fails if any edge's From does not precede its To in order.
func assertRespectsEdges(t *testing.T, g *Graph, order []string) {
	t.Helper()
	pos := positions(order)
	for _, e := range g.Edges() {
		pf, ok1 := pos[e.From]
		pt, ok2 := pos[e.To]
		if !ok1 || !ok2 {
			t.Fatalf("edge endpoint missing from order: %s→%s (order=%v)", e.From, e.To, order)
		}
		if pf >= pt {
			t.Errorf("order violates edge %s→%s: %s at %d, %s at %d\norder=%v",
				e.From, e.To, e.From, pf, e.To, pt, order)
		}
	}
}

// assertPermutation fails unless order is exactly the graph's node set, once each.
func assertPermutation(t *testing.T, g *Graph, order []string) {
	t.Helper()
	got := append([]string(nil), order...)
	sort.Strings(got)
	want := g.Nodes()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order is not a permutation of nodes\n got: %v\nwant: %v", got, want)
	}
}

// ---- types -----------------------------------------------------------------

func TestKindString(t *testing.T) {
	cases := map[Kind]string{Order: "order", Require: "require", Notify: "notify", Kind(99): "kind(99)"}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestAddEdgeIdempotentAndDistinctKinds(t *testing.T) {
	g := New()
	g.AddEdge("a", "b", Order, "first")
	g.AddEdge("a", "b", Order, "second")  // same (from,to,kind) → ignored, first reason kept
	g.AddEdge("a", "b", Notify, "notify") // distinct kind → new edge

	es := g.Edges()
	if len(es) != 2 {
		t.Fatalf("want 2 edges (order+notify), got %d: %+v", len(es), es)
	}
	// Edges() is sorted by (from,to,kind); Order(0) < Notify(2).
	if es[0].Kind != Order || es[0].Reason != "first" {
		t.Errorf("first edge = %+v, want Order/first (idempotent, keeps first reason)", es[0])
	}
	if es[1].Kind != Notify {
		t.Errorf("second edge kind = %v, want Notify", es[1].Kind)
	}
}

func TestAddNodeIsolatedSurvives(t *testing.T) {
	g := New()
	g.AddNode("lonely")
	g.AddEdge("a", "b", Order, "")
	order, err := g.TopoSort()
	if err != nil {
		t.Fatal(err)
	}
	assertPermutation(t, g, order) // "lonely" must be present
	if !g.HasNode("lonely") {
		t.Error("HasNode(lonely) = false")
	}
	if g.HasNode("nope") {
		t.Error("HasNode(nope) = true")
	}
}

func TestNodesAndEdgesSorted(t *testing.T) {
	g := New()
	g.AddEdge("z", "a", Order, "")
	g.AddEdge("m", "a", Require, "")
	if got := g.Nodes(); !reflect.DeepEqual(got, []string{"a", "m", "z"}) {
		t.Errorf("Nodes() = %v, want sorted", got)
	}
	es := g.Edges()
	if es[0].From != "m" || es[1].From != "z" {
		t.Errorf("Edges() not sorted by From: %+v", es)
	}
}

// ---- toposort --------------------------------------------------------------

func TestTopoSortRespectsEdges(t *testing.T) {
	// A small DAG: root → {b,c}; b,c → d; plus an isolated e.
	g := New()
	g.AddEdge("root", "b", Order, "")
	g.AddEdge("root", "c", Order, "")
	g.AddEdge("b", "d", Require, "")
	g.AddEdge("c", "d", Require, "")
	g.AddNode("e")

	order, err := g.TopoSort()
	if err != nil {
		t.Fatal(err)
	}
	assertPermutation(t, g, order)
	assertRespectsEdges(t, g, order)
}

func TestTopoSortStableTieBreak(t *testing.T) {
	// Diamond: a → {b,c} → d. With lexicographic tie-break the unique stable
	// order is a,b,c,d (b before c because b<c and both are ready together).
	g := New()
	g.AddEdge("a", "b", Order, "")
	g.AddEdge("a", "c", Order, "")
	g.AddEdge("b", "d", Order, "")
	g.AddEdge("c", "d", Order, "")

	order, err := g.TopoSort()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a", "b", "c", "d"}; !reflect.DeepEqual(order, want) {
		t.Errorf("stable order = %v, want %v", order, want)
	}
}

func TestTopoSortEmptyAndSingle(t *testing.T) {
	if order, err := New().TopoSort(); err != nil || len(order) != 0 {
		t.Errorf("empty graph: order=%v err=%v, want [] nil", order, err)
	}
	g := New()
	g.AddNode("solo")
	if order, err := g.TopoSort(); err != nil || !reflect.DeepEqual(order, []string{"solo"}) {
		t.Errorf("single node: order=%v err=%v", order, err)
	}
}

// TestTopoSortDeterministicAcrossShuffledInsertion builds the SAME logical graph
// with many different node/edge insertion orders and asserts TopoSort returns a
// byte-identical order every time — the determinism the plan (B1) requires.
func TestTopoSortDeterministicAcrossShuffledInsertion(t *testing.T) {
	type ed struct {
		from, to string
		kind     Kind
	}
	edges := []ed{
		{"build", "test", Require},
		{"build", "lint", Order},
		{"test", "ship", Require},
		{"lint", "ship", Order},
		{"docs", "ship", Notify},
	}
	extraNodes := []string{"orphan1", "orphan2"}

	build := func(perm []int, nodePerm []int) []string {
		g := New()
		for _, i := range nodePerm {
			g.AddNode(extraNodes[i])
		}
		for _, i := range perm {
			e := edges[i]
			g.AddEdge(e.from, e.to, e.kind, "")
		}
		order, err := g.TopoSort()
		if err != nil {
			t.Fatalf("unexpected cycle: %v", err)
		}
		return order
	}

	// Reference order from the natural insertion order.
	ref := build([]int{0, 1, 2, 3, 4}, []int{0, 1})

	// A spread of shuffled insertion orders (deterministic, no RNG needed).
	perms := [][]int{
		{4, 3, 2, 1, 0},
		{2, 0, 4, 1, 3},
		{1, 3, 0, 4, 2},
		{3, 4, 0, 2, 1},
	}
	nodePerms := [][]int{{1, 0}, {0, 1}}
	for _, p := range perms {
		for _, np := range nodePerms {
			if got := build(p, np); !reflect.DeepEqual(got, ref) {
				t.Fatalf("insertion order changed result:\nperm=%v nodePerm=%v\n got=%v\nref=%v", p, np, got, ref)
			}
		}
	}
	// And the order is genuinely valid.
	g := New()
	for _, e := range edges {
		g.AddEdge(e.from, e.to, e.kind, "")
	}
	assertRespectsEdges(t, g, ref)
}

// ---- reverse ---------------------------------------------------------------

func TestReverse(t *testing.T) {
	g := New()
	g.AddEdge("dir", "file", Require, "containment")
	g.AddEdge("file", "svc", Notify, "EnvironmentFile=")
	g.AddNode("isolated")

	r := g.Reverse()

	// Isolated nodes carry over.
	if !r.HasNode("isolated") {
		t.Error("Reverse dropped the isolated node")
	}
	// Every edge flipped, kind + reason preserved.
	want := []Edge{
		{From: "file", To: "dir", Kind: Require, Reason: "containment"},
		{From: "svc", To: "file", Kind: Notify, Reason: "EnvironmentFile="},
	}
	if got := r.Edges(); !reflect.DeepEqual(got, want) {
		t.Errorf("Reverse edges = %+v, want %+v", got, want)
	}
	// Reverse of reverse restores the original edge set.
	if got := r.Reverse().Edges(); !reflect.DeepEqual(got, g.Edges()) {
		t.Errorf("Reverse∘Reverse changed edges:\n got %+v\nwant %+v", got, g.Edges())
	}
}

func TestReverseIsDeleteOrder(t *testing.T) {
	// Create order: dir → file → svc. Delete order must be the reverse:
	// svc torn down before file before dir.
	g := New()
	g.AddEdge("dir", "file", Require, "")
	g.AddEdge("file", "svc", Require, "")

	del, err := g.Reverse().TopoSort()
	if err != nil {
		t.Fatal(err)
	}
	pos := positions(del)
	if !(pos["svc"] < pos["file"] && pos["file"] < pos["dir"]) {
		t.Errorf("delete order not reversed: %v", del)
	}
}

// ---- cycles ----------------------------------------------------------------

func TestCycleTwoNode(t *testing.T) {
	g := New()
	g.AddEdge("a.env", "ollama.container", Notify, "EnvironmentFile= reference")
	g.AddEdge("ollama.container", "a.env", Require, "directory containment")

	order, err := g.TopoSort()
	if order != nil {
		t.Errorf("cyclic graph returned an order: %v", order)
	}
	var ce *CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T %v, want *CycleError", err, err)
	}
	if len(ce.Cycles) != 1 {
		t.Fatalf("want 1 cycle, got %d: %+v", len(ce.Cycles), ce.Cycles)
	}
	msg := err.Error()
	for _, want := range []string{
		"dependency cycle:",
		"a.env → ollama.container  (EnvironmentFile= reference)",
		"ollama.container → a.env  (directory containment)",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("cycle render missing %q:\n%s", want, msg)
		}
	}
}

func TestCycleSelfLoop(t *testing.T) {
	g := New()
	g.AddEdge("x", "x", Order, "self")
	_, err := g.TopoSort()
	var ce *CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *CycleError", err)
	}
	if len(ce.Cycles) != 1 || len(ce.Cycles[0]) != 1 || ce.Cycles[0][0].From != "x" || ce.Cycles[0][0].To != "x" {
		t.Errorf("self-loop cycle = %+v, want single x→x edge", ce.Cycles)
	}
}

func TestCycleThreeNodeReportedOnce(t *testing.T) {
	g := New()
	g.AddEdge("a", "b", Order, "")
	g.AddEdge("b", "c", Order, "")
	g.AddEdge("c", "a", Order, "")

	_, err := g.TopoSort()
	var ce *CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *CycleError", err)
	}
	if len(ce.Cycles) != 1 {
		t.Fatalf("3-node single tangle reported %d times, want once: %+v", len(ce.Cycles), ce.Cycles)
	}
	if got := len(ce.Cycles[0]); got != 3 {
		t.Errorf("cycle length = %d, want 3", got)
	}
	assertClosedLoop(t, g, ce.Cycles[0])
}

func TestMultipleDisjointCyclesReportedOnce(t *testing.T) {
	g := New()
	// Two independent 2-cycles + one acyclic tail hanging off the second.
	g.AddEdge("a", "b", Order, "")
	g.AddEdge("b", "a", Order, "")
	g.AddEdge("p", "q", Require, "")
	g.AddEdge("q", "p", Require, "")
	g.AddEdge("q", "tail", Order, "") // tail is not in any cycle

	_, err := g.TopoSort()
	var ce *CycleError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *CycleError", err)
	}
	if len(ce.Cycles) != 2 {
		t.Fatalf("want 2 disjoint cycles, got %d: %+v", len(ce.Cycles), ce.Cycles)
	}
	// Deterministic order: the {a,b} tangle sorts before {p,q}.
	if ce.Cycles[0][0].From != "a" {
		t.Errorf("cycles not deterministically ordered: %+v", ce.Cycles)
	}
	for _, cyc := range ce.Cycles {
		assertClosedLoop(t, g, cyc)
	}
}

// TestCycleErrorRenderMultiple checks the multi-tangle separator renders.
func TestCycleErrorRenderMultiple(t *testing.T) {
	ce := &CycleError{Cycles: [][]Edge{
		{{From: "a", To: "b", Kind: Order, Reason: ""}, {From: "b", To: "a", Kind: Order}},
		{{From: "p", To: "q"}, {From: "q", To: "p"}},
	}}
	msg := ce.Error()
	if !strings.Contains(msg, "\n  ---") {
		t.Errorf("multi-cycle separator missing:\n%s", msg)
	}
	// Empty reason falls back to the kind name.
	if !strings.Contains(msg, "a → b  (order)") {
		t.Errorf("empty-reason edge should fall back to kind:\n%s", msg)
	}
}

// assertClosedLoop verifies a reported cycle is a real closed edge loop in g:
// consecutive edges chain (To==next.From), the last closes to the first, and
// every edge actually exists in the graph.
func assertClosedLoop(t *testing.T, g *Graph, cyc []Edge) {
	t.Helper()
	if len(cyc) == 0 {
		t.Fatal("empty cycle")
	}
	real := make(map[string]bool)
	for _, e := range g.Edges() {
		real[fmt.Sprintf("%s\x00%s\x00%d", e.From, e.To, e.Kind)] = true
	}
	for i, e := range cyc {
		if !real[fmt.Sprintf("%s\x00%s\x00%d", e.From, e.To, e.Kind)] {
			t.Errorf("cycle edge %s→%s (%v) not in graph", e.From, e.To, e.Kind)
		}
		next := cyc[(i+1)%len(cyc)]
		if e.To != next.From {
			t.Errorf("cycle not closed: edge %d To=%s but next From=%s", i, e.To, next.From)
		}
	}
}

// ---- property: random DAGs -------------------------------------------------

// TestPropertyTopoSortRespectsAllEdges builds many random DAGs (edges only from
// earlier to later in a fixed permutation, guaranteeing acyclicity) and asserts
// TopoSort always succeeds, returns a permutation of nodes, and respects every
// edge.
func TestPropertyTopoSortRespectsAllEdges(t *testing.T) {
	// Deterministic LCG so the property runs the same every time (no RNG import,
	// and Math.random-style nondeterminism is unavailable to us anyway).
	seed := uint64(0x9E3779B97F4A7C15)
	rnd := func() uint64 { seed = seed*6364136223846793005 + 1442695040888963407; return seed >> 11 }

	for trial := range 300 {
		n := int(rnd()%8) + 2 // 2..9 nodes
		nodes := make([]string, n)
		for i := range nodes {
			nodes[i] = fmt.Sprintf("n%02d", i)
		}
		g := New()
		for _, id := range nodes {
			g.AddNode(id)
		}
		// Only add edges i→j with i<j (in the fixed index order) → acyclic.
		for i := range n {
			for j := i + 1; j < n; j++ {
				if rnd()%3 == 0 {
					g.AddEdge(nodes[i], nodes[j], Kind(rnd()%3), "")
				}
			}
		}
		order, err := g.TopoSort()
		if err != nil {
			t.Fatalf("trial %d: acyclic graph reported a cycle: %v", trial, err)
		}
		assertPermutation(t, g, order)
		assertRespectsEdges(t, g, order)
	}
}
