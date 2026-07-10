// Command magus is a day-2 reconciler for bootc / Fedora CoreOS hosts.
//
// magus consumes the IR subset of a Butane file and converges the running
// system toward the declared state. See docs/spec-reconciler.md for the
// authority model, manifest semantics, and equivalence rules.
package main

import (
	"fmt"
	"os"
)

// version and commit are stamped at build time via
// -ldflags "-X main.version=... -X main.commit=...". A host-deployed static
// binary with no version identifier is a support headache (UX6); `make build`
// injects them from git, and they default to dev/none for a plain `go build`.
var (
	version = "dev"
	commit  = "none"
)

const usage = `magus — Butane reconciler for Magus

Usage: magus <command> [flags]

Commands:
  validate    Parse a Butane source and check it against the policy
  plan        Show what apply would do
  apply       Reconcile the system toward the declared state
  status      Print reconciler state from the manifest
  adopt       Take over an existing path that differs from the IR
  reclaim     Restore an orphaned path to active reconciliation
  version     Print the magus version and commit

Run 'magus <command> -h' for command-specific flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cmd, args := os.Args[1], os.Args[2:]

	switch cmd {
	case "validate":
		os.Exit(runValidate(args))
	case "plan":
		os.Exit(runPlan(args))
	case "apply":
		os.Exit(runApply(args))
	case "status":
		os.Exit(runStatus(args))
	case "adopt":
		os.Exit(runAdopt(args))
	case "reclaim":
		os.Exit(runReclaim(args))
	case "version", "--version":
		fmt.Printf("magus %s (%s)\n", version, commit)
		os.Exit(0)
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "magus: unknown command %q\n\n%s", cmd, usage)
		os.Exit(1)
	}
}
