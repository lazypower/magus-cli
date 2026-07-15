package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lazypower/magus-cli/internal/applygraph"
	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/graph"
	"github.com/lazypower/magus-cli/internal/hostfs"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/policy"
	"github.com/lazypower/magus-cli/internal/status"
)

const graphUsage = `magus graph — show the apply-ordering graph magus derives from a plan

Usage: magus graph [--dot] [--policy <path>] [--manifest <path>] <butane-source>

Renders the dependency graph apply walks: which resources must settle before
others, where the single daemon-reload sits, and which config files notify
(restart) the services that consume them via EnvironmentFile=. Read-only — it
computes the same plan as 'magus plan' and derives the graph, touching nothing.

<butane-source> is either a local filesystem path or an http(s) URL.

Flags:
  --dot               Emit Graphviz DOT (pipe to 'dot -Tsvg' to draw it)
  --insecure-http     Allow fetching Butane over plain HTTP (https required by default)
  --policy <path>     Override policy file (default: /etc/magus/policy.yaml)
  --manifest <path>   Override manifest file (default: /var/lib/magus/manifest.json)

Exit codes:
  0   graph derived (acyclic)
  1   input-bad (parse error, policy/IR contradiction, or a dependency cycle)
`

func runGraph(args []string) int {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, graphUsage) }
	policyPath := fs.String("policy", policy.DefaultPath, "policy file path")
	manifestPath := fs.String("manifest", manifest.DefaultPath, "manifest file path")
	statusPath := fs.String("status", status.DefaultPath, "status observation file path")
	dot := fs.Bool("dot", false, "emit Graphviz DOT")
	insecureHTTP := fs.Bool("insecure-http", false, "allow fetching Butane over plain HTTP")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, graphUsage)
		return 1
	}
	source := fs.Arg(0)

	p, parsed, m, ok := loadReconcileInputs(*policyPath, *manifestPath, *statusPath, source, *insecureHTTP)
	if !ok {
		return 1
	}

	// Read-only, like plan: surface owned paths the policy now denies as
	// orphaned rather than persisting anything.
	policy.OrphanDenied(p, m, time.Now().UTC())

	plan, err := diff.ComputeWithPolicy(p, parsed, m, hostfs.OS())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	g := applygraph.Derive(plan, parsed)
	return renderGraph(os.Stdout, os.Stderr, source, g, *dot)
}

// renderGraph writes the graph (DOT or plain) and validates acyclicity. A cycle
// is input-bad (exit 1): the graph is still rendered so the operator can see it,
// with the cycle diagnostic on stderr.
func renderGraph(out, errw io.Writer, source string, g *graph.Graph, dot bool) int {
	if dot {
		fmt.Fprint(out, applygraph.DOT(g))
	} else {
		fmt.Fprintf(out, "%s → ", source)
		fmt.Fprint(out, applygraph.Plain(g))
	}
	if _, err := g.TopoSort(); err != nil {
		fmt.Fprintf(errw, "error: %v\n", err)
		return 1
	}
	return 0
}
