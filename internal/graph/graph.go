// Package graph is a small, dependency-free directed graph over string node IDs
// with typed, provenance-carrying edges. It is the ordering core for
// `magus apply`.
//
// Apply today runs a fixed phase pipeline (deletes → writes → one daemon-reload
// → service ops). That is a hardcoded topological order over an *implicit*
// dependency graph. This package makes the graph explicit so ordering, change
// propagation, and delete-reversal become derived structure rather than
// hand-sequenced phases — see docs/adr-0002-apply-graph.md.
//
// The package is deliberately pure: it knows nothing about files, units, or
// systemd. Callers attach meaning to node IDs and edge kinds; this package only
// orders them deterministically and refuses cycles. Edge-derivation over the
// magus IR (B2) and graph-driven execution (B3) build on top of it.
package graph

import (
	"sort"
	"strconv"
)

// Kind classifies the dependency relation an edge expresses. All three kinds
// impose the same *ordering* constraint (From is scheduled before To); they
// differ only in the failure/refresh semantics the executor (B3) reads off
// them. Keeping the kind on the edge lets a single graph carry ordering,
// requirement, and change-propagation relations at once.
type Kind int

const (
	// Order: To runs after From if both are scheduled; no failure coupling.
	// Borrowed from systemd After=.
	Order Kind = iota
	// Require: ordering plus failure propagation — if From fails, To is
	// skipped. systemd Requires= / Terraform's poisoned-descendant walker.
	Require
	// Notify: if From *changed* (create/update, not adopt/skip), To's refresh
	// is scheduled. Puppet notify / Salt watch.
	Notify
)

func (k Kind) String() string {
	switch k {
	case Order:
		return "order"
	case Require:
		return "require"
	case Notify:
		return "notify"
	default:
		return "kind(" + strconv.Itoa(int(k)) + ")"
	}
}

// Edge is a directed dependency from From to To. Reason is human-facing
// provenance ("EnvironmentFile= reference", "directory containment") surfaced in
// cycle diagnostics so an operator can see *why* two resources are entangled.
type Edge struct {
	From   string
	To     string
	Kind   Kind
	Reason string
}

// Graph is a directed graph over string node IDs. The zero value is not usable;
// construct with New.
type Graph struct {
	nodes map[string]bool
	adj   map[string][]Edge // From -> its outgoing edges
	seen  map[string]bool   // (From,To,Kind) dedup keys, so AddEdge is idempotent
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]bool{},
		adj:   map[string][]Edge{},
		seen:  map[string]bool{},
	}
}

// AddNode registers a node with no edges. Idempotent. Isolated nodes are real
// work (a file with no dependencies still gets applied), so they must survive
// into the topological order.
func (g *Graph) AddNode(id string) { g.nodes[id] = true }

// AddEdge adds a From→To dependency of the given kind, auto-registering both
// endpoints. It is idempotent per (From, To, Kind): adding the same relation
// twice keeps the first reason and adds no duplicate. Distinct kinds between the
// same pair are distinct edges (a file can both order-before and notify a
// unit). A self-edge (From == To) is accepted and reported as a cycle by
// TopoSort — the caller's derivation is what's wrong, not this call.
func (g *Graph) AddEdge(from, to string, kind Kind, reason string) {
	g.AddNode(from)
	g.AddNode(to)
	key := from + "\x00" + to + "\x00" + strconv.Itoa(int(kind))
	if g.seen[key] {
		return
	}
	g.seen[key] = true
	g.adj[from] = append(g.adj[from], Edge{From: from, To: to, Kind: kind, Reason: reason})
}

// HasNode reports whether id is in the graph.
func (g *Graph) HasNode(id string) bool { return g.nodes[id] }

// Nodes returns all node IDs in lexicographic order.
func (g *Graph) Nodes() []string {
	out := make([]string, 0, len(g.nodes))
	for n := range g.nodes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Edges returns all edges in a deterministic (From, To, Kind) order.
func (g *Graph) Edges() []Edge {
	var out []Edge
	for _, es := range g.adj {
		out = append(out, es...)
	}
	sortEdges(out)
	return out
}

// Reverse returns a new graph with every edge reversed (To→From), preserving
// kind and reason and carrying all nodes over (including isolated ones). This is
// the delete/destroy order: consumers are torn down before the providers they
// depended on — the reverse of create order (Terraform's reverse-topo destroy).
func (g *Graph) Reverse() *Graph {
	r := New()
	for n := range g.nodes {
		r.AddNode(n)
	}
	for _, e := range g.Edges() {
		r.AddEdge(e.To, e.From, e.Kind, e.Reason)
	}
	return r
}

// outEdges returns node id's outgoing edges in deterministic order. It never
// returns the shared backing slice, so callers may sort/append freely.
func (g *Graph) outEdges(id string) []Edge {
	es := append([]Edge(nil), g.adj[id]...)
	sortEdges(es)
	return es
}

// sortEdges orders edges by (From, To, Kind) for run-to-run determinism.
func sortEdges(es []Edge) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].From != es[j].From {
			return es[i].From < es[j].From
		}
		if es[i].To != es[j].To {
			return es[i].To < es[j].To
		}
		return es[i].Kind < es[j].Kind
	})
}
