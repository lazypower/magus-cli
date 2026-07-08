package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lazypower/magus-cli/internal/diff"
	"github.com/lazypower/magus-cli/internal/hostfs"
	"github.com/lazypower/magus-cli/internal/lock"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/policy"
	"github.com/lazypower/magus-cli/internal/status"
)

const adoptUsage = `magus adopt — take over an existing path that differs from the IR

Usage: magus adopt [--yes] [--policy <path>] [--manifest <path>] <butane-source> <path>

<butane-source> is either a local filesystem path or an http(s) URL.

Adopt overwrites the existing content with the IR's content and records the
path in the manifest with origin=force-adopt. Use this when you want magus to
own a path you're willing to replace — terraform import with a write step.

Adoption of *matching* content (where on-disk already equals IR) happens
silently during 'magus apply' and does not require this command.

Flags:
  --yes               Skip the confirmation prompt
  --insecure-http     Allow fetching Butane over plain HTTP (https required by default)
  --policy <path>     Override policy file (default: /etc/magus/policy.yaml)
  --manifest <path>   Override manifest file (default: /var/lib/magus/manifest.json)
`

func runAdopt(args []string) int {
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, adoptUsage) }
	policyPath := fs.String("policy", policy.DefaultPath, "policy file path")
	manifestPath := fs.String("manifest", manifest.DefaultPath, "manifest file path")
	statusPath := fs.String("status", status.DefaultPath, "status observation file path (reserved-path check)")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	insecureHTTP := fs.Bool("insecure-http", false, "allow fetching Butane over plain HTTP")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 2 {
		fmt.Fprint(os.Stderr, adoptUsage)
		return 1
	}
	butanePath, target := fs.Arg(0), fs.Arg(1)

	// Serialize manifest mutation against a concurrent apply/adopt/reclaim.
	release, err := lock.Acquire(*manifestPath)
	if err != nil {
		if errors.Is(err, lock.ErrBusy) {
			fmt.Fprintln(os.Stderr, "error: another magus operation is in progress (manifest is locked)")
			return 1
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	defer func() { _ = release() }()

	p, parsed, m, ok := loadReconcileInputs(*policyPath, *manifestPath, *statusPath, butanePath, *insecureHTTP)
	if !ok {
		return 1
	}

	declared, ok := findDeclared(parsed, target)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: %s is not declared in %s\n", target, butanePath)
		return 1
	}

	w := hostfs.OS()
	st, err := w.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: stat %s: %v\n", target, err)
		return 1
	}
	if !st.Exists {
		fmt.Fprintf(os.Stderr, "error: %s does not exist on disk — use 'magus apply' to create it\n", target)
		return 1
	}

	if entry, exists := m.Get(target); exists {
		switch entry.State {
		case manifest.StateActive:
			fmt.Fprintf(os.Stderr, "error: %s is already managed by magus — use 'magus apply' to update\n", target)
			return 1
		case manifest.StateOrphaned:
			fmt.Fprintf(os.Stderr, "error: %s is orphaned — use 'magus reclaim' to restore reconciliation\n", target)
			return 1
		}
	}

	body, err := w.ReadFile(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read %s: %v\n", target, err)
		return 1
	}
	// Hash with the resource's equivalence rule (canonical for units/quadlets,
	// raw for files) so the match check and recorded hash agree with diff.
	onDisk := diff.HashContent(body, declared.diffKind)
	declared_ := diff.HashContent(declared.contents, declared.diffKind)

	if onDisk == declared_ {
		fmt.Fprintf(os.Stderr, "error: %s already matches the IR — 'magus apply' will adopt it silently\n", target)
		return 1
	}

	// Symlink-resolved containment BEFORE the prompt: a deliberate overwrite
	// must not be redirected outside authority through a symlinked ancestor, and
	// there's no point asking the operator to confirm something we'll refuse
	// (UX4).
	if r, ok := w.(hostfs.Resolver); ok {
		if _, reason := diff.ContainmentEscape(p, r, target); reason != "" {
			fmt.Fprintf(os.Stderr, "error: refusing to adopt %s: %s\n", target, reason)
			return 1
		}
	}

	fmt.Println("The path exists with content that differs from the IR.")
	fmt.Println()
	fmt.Printf("  - existing hash: %s\n", onDisk)
	fmt.Printf("  - declared hash: %s\n", declared_)
	fmt.Println()
	fmt.Println("Overwriting will replace the existing content with the IR's declared content.")

	if !*yes {
		if !confirmAction(os.Stdin, os.Stdout, fmt.Sprintf("\nTake over %s? [y/N] ", target)) {
			fmt.Println("Aborted.")
			return 0
		}
	}
	fmt.Println()

	if err := w.WriteFile(target, declared.contents, declared.mode, declared.uid, declared.gid); err != nil {
		fmt.Fprintf(os.Stderr, "error: write %s: %v\n", target, err)
		return 1
	}
	// A rewritten unit/quadlet is stale to systemd until daemon-reload.
	reloadAfterUnitWrite(declared.diffKind, target)
	m.PutActive(target, manifestKind(declared.diffKind), declared_, manifest.OriginForceAdopt, time.Now().UTC())
	if err := m.Save(*manifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: save manifest: %v\n", err)
		return 1
	}
	fmt.Printf("  ✓ %s  (rewrote, recorded in manifest)\n", target)
	return 0
}
