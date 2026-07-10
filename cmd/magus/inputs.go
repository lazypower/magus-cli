package main

import (
	"fmt"
	"os"

	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/manifest"
	"github.com/lazypower/magus-cli/internal/policy"
)

// loadInputs runs the shared command preamble: load the policy, load + translate
// the Butane source (surfacing warnings), and check the IR against the policy.
//
// The reserved-path set passed to policy.Check is the SAME for every command —
// {manifest, policy, status} — so an IR that declares one of magus's own state
// files is rejected identically whether it reaches validate, plan, or apply.
// That's the correctness point of the consolidation: plan previews exactly the
// reserved-path gate apply enforces, no surprises (D14). Callers present the
// returned violations; a load/parse error is returned as err.
func loadInputs(policyPath, manifestPath, statusPath, source string, insecureHTTP bool) (*policy.Policy, *ir.IR, []policy.Violation, error) {
	p, err := policy.Load(policyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, warnings, err := ir.LoadButane(source, insecureHTTP)
	if err != nil {
		return nil, nil, nil, err
	}
	printButaneWarnings(warnings)
	violations := policy.Check(p, parsed, manifestPath, policyPath, statusPath)
	return p, parsed, violations, nil
}

// loadReconcileInputs is loadInputs plus the manifest load, for the commands
// that reconcile against ownership (plan/apply/adopt/reclaim). It prints the
// error or policy violations and returns ok=false on any failure, so callers
// collapse the whole preamble to a single guarded call.
func loadReconcileInputs(policyPath, manifestPath, statusPath, source string, insecureHTTP bool) (*policy.Policy, *ir.IR, *manifest.Manifest, bool) {
	p, parsed, violations, err := loadInputs(policyPath, manifestPath, statusPath, source, insecureHTTP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return nil, nil, nil, false
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "error: %s\n", v)
		}
		return nil, nil, nil, false
	}
	m, err := manifest.Load(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return nil, nil, nil, false
	}
	return p, parsed, m, true
}
