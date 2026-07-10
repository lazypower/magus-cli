package diff

import (
	"github.com/lazypower/magus-cli/internal/ir"
	"github.com/lazypower/magus-cli/internal/systemd"
)

// ServiceOp is an enablement operation the plan says apply will perform on a
// unit. Unlike ResourceAction (which governs on-disk files), a ServiceAction
// governs a unit's *persistent enablement* — the state the spec reconciles on
// every apply, independent of whether the unit's file changed. Modeling it in
// the plan is what makes `plan` an honest preview and "Nothing to apply" true
// by construction (an enablement drift is a plan row, so it can't hide behind a
// clean file diff).
type ServiceOp string

const (
	// ServiceEnable — the unit is declared enabled but is not; apply will
	// `systemctl enable` it (or `enable --now` when the unit is new).
	ServiceEnable ServiceOp = "enable"
	// ServiceDisable — the unit is declared disabled but is enabled; apply
	// will `systemctl disable` it.
	ServiceDisable ServiceOp = "disable"
	// ServiceSkip — the declared enablement cannot be achieved (the unit is
	// masked, static, or not-found). Surfaced rather than silently ignored so
	// the operator's unachievable intent is visible instead of a false exit 0.
	ServiceSkip ServiceOp = "skip"
)

// ServiceAction is one enablement operation in the plan.
type ServiceAction struct {
	Unit   string
	Op     ServiceOp
	Reason string
}

// EnablementOp is the single decision authority for reconciling one EXISTING
// unit's enablement: given the IR's tri-state desired value and the unit's
// current systemd enablement, it returns the operation to perform (or "" for
// none). Both the planner (PlanServiceState, for preview + change count) and
// apply (for execution) call this so the two never diverge.
//
// desired follows ir.Unit.Enabled: nil → undeclared, magus does not touch it.
func EnablementOp(desired *bool, current systemd.Enablement) (ServiceOp, string) {
	if desired == nil {
		return "", ""
	}
	if *desired {
		switch current {
		case systemd.EnablementEnabled:
			return "", ""
		case systemd.EnablementDisabled, systemd.EnablementUnknown:
			return ServiceEnable, "declared enabled, currently " + string(current)
		case systemd.EnablementMasked:
			return ServiceSkip, "declared enabled but unit is masked; magus will not unmask"
		case systemd.EnablementStatic:
			return ServiceSkip, "declared enabled but unit is static; systemd cannot enable it"
		case systemd.EnablementNotFound:
			return ServiceSkip, "declared enabled but unit not found"
		}
		return "", ""
	}
	// Declared disabled. Act when the unit is enabled, and also when its state is
	// unknown — mirroring the enable branch, disable-on-unknown fails closed
	// toward the declared state (systemctl disable is a harmless no-op if the
	// unit is already disabled/static). Masked and not-found are already
	// not-running-by-enablement; nothing to do.
	if current == systemd.EnablementEnabled || current == systemd.EnablementUnknown {
		return ServiceDisable, "declared disabled, currently " + string(current)
	}
	return "", ""
}

// PlanServiceState appends enablement rows to plan by querying live systemd for
// each IR unit whose enablement is declared (Enabled != nil). It is read-only —
// `is-enabled` has no side effects, so plan stays side-effect-free.
//
// Units whose body is being created this apply are handled specially: their
// current enablement is not yet meaningful (the file isn't on disk), so a
// declared-enabled new unit yields a single ServiceEnable row (apply turns this
// into `enable --now` after the create). Existing units are decided by
// EnablementOp against their live state.
//
// When systemd is unavailable (dev host without systemctl), `is-enabled`
// errors and the unit is skipped — enablement simply isn't previewed rather
// than failing the whole plan. Quadlet generated services are never enabled
// (systemd refuses), so they produce no service rows.
func PlanServiceState(in *ir.IR, plan *Plan, sd systemd.Manager) {
	created := createdUnitBodies(plan)
	for _, u := range in.Units {
		if u.Enabled == nil {
			continue
		}
		if created[u.Name] {
			if *u.Enabled {
				plan.ServiceActions = append(plan.ServiceActions, ServiceAction{
					Unit:   u.Name,
					Op:     ServiceEnable,
					Reason: "declared enabled (new unit)",
				})
			}
			continue
		}
		status, err := sd.Show(u.Name)
		if err != nil {
			continue // systemd unavailable — can't preview enablement
		}
		if op, reason := EnablementOp(u.Enabled, status.Enablement); op != "" {
			plan.ServiceActions = append(plan.ServiceActions, ServiceAction{
				Unit:   u.Name,
				Op:     op,
				Reason: reason,
			})
		}
	}
}

// createdUnitBodies returns the set of unit names whose body file is being
// created this apply. A newly-created unit's enablement is reconciled off the
// create, not off its (not-yet-existing) on-disk state.
func createdUnitBodies(plan *Plan) map[string]bool {
	created := map[string]bool{}
	for _, a := range plan.Actions {
		if a.Kind == KindUnit && a.Action == ActionCreate && a.UnitName != "" &&
			UnitPath(a.UnitName) == a.Path {
			created[a.UnitName] = true
		}
	}
	return created
}

// HasServiceActions reports whether the plan carries any enablement operation —
// used to fold enablement into the "is there anything to do?" decision so an
// enablement-only drift is not mistaken for a converged no-op.
func (p *Plan) HasServiceActions() bool {
	return len(p.ServiceActions) > 0
}
