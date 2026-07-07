package systemd

import "testing"

func TestParseEnablement(t *testing.T) {
	cases := map[string]Enablement{
		"enabled":         EnablementEnabled,
		"enabled-runtime": EnablementEnabled,
		"alias":           EnablementEnabled,
		"indirect":        EnablementEnabled,
		"disabled":        EnablementDisabled,
		"masked":          EnablementMasked,
		"masked-runtime":  EnablementMasked,
		"static":          EnablementStatic,
		"transient":       EnablementStatic,
		"generated":       EnablementStatic,
		"Failed to get unit file state for x.service: No such file or directory": EnablementNotFound,
		"x.service is not loaded": EnablementNotFound,
		"some surprise output":    EnablementUnknown,
		"":                        EnablementUnknown,
	}
	for in, want := range cases {
		if got := parseEnablement(in); got != want {
			t.Errorf("parseEnablement(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseActiveState(t *testing.T) {
	for _, s := range []string{"active", "inactive", "failed", "activating", "deactivating", "reloading"} {
		if got := parseActiveState(s); got != s {
			t.Errorf("parseActiveState(%q) = %q, want it preserved", s, got)
		}
	}
	for _, s := range []string{"", "Failed to connect to bus", "garbage"} {
		if got := parseActiveState(s); got != "unknown" {
			t.Errorf("parseActiveState(%q) = %q, want unknown", s, got)
		}
	}
}

// TestFakeShowFallback checks the Fake's Show honors preloaded active state.
func TestFakeShowFallback(t *testing.T) {
	var m Manager = NewFake()
	f := m.(*Fake)
	f.SetActive("a.service", true)
	if s, _ := m.Show("a.service"); s.Active != "active" {
		t.Errorf("Show active from SetActive = %q, want active", s.Active)
	}
	f.SetActiveState("b.service", "failed")
	if s, _ := m.Show("b.service"); s.Active != "failed" {
		t.Errorf("Show active override = %q, want failed", s.Active)
	}
	if s, _ := m.Show("c.service"); s.Active != "inactive" {
		t.Errorf("Show active default = %q, want inactive", s.Active)
	}
}

// parseShow maps `systemctl show` output to a UnitStatus, matching is-enabled
// semantics for the enablement half (via LoadState + UnitFileState).
func TestParseShow(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		wantEnb Enablement
		wantAct string
	}{
		{"enabled-active",
			"LoadState=loaded\nUnitFileState=enabled\nActiveState=active\n",
			EnablementEnabled, "active"},
		{"disabled-inactive",
			"LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\n",
			EnablementDisabled, "inactive"},
		{"masked-by-loadstate",
			"LoadState=masked\nUnitFileState=masked\nActiveState=inactive\n",
			EnablementMasked, "inactive"},
		{"not-found",
			"LoadState=not-found\nUnitFileState=\nActiveState=inactive\n",
			EnablementNotFound, "inactive"},
		{"no-install-empty-is-static",
			"LoadState=loaded\nUnitFileState=\nActiveState=active\n",
			EnablementStatic, "active"},
		{"static-failed",
			"LoadState=loaded\nUnitFileState=static\nActiveState=failed\n",
			EnablementStatic, "failed"},
		{"garbage-lines-ignored",
			"junk\nUnitFileState=enabled\n\nActiveState=active",
			EnablementEnabled, "active"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseShow(c.out)
			if got.Enablement != c.wantEnb {
				t.Errorf("Enablement = %q, want %q", got.Enablement, c.wantEnb)
			}
			if got.Active != c.wantAct {
				t.Errorf("Active = %q, want %q", got.Active, c.wantAct)
			}
		})
	}
}
