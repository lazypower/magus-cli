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

// TestFakeManagerSatisfiesInterface is a compile-time + behavior check that the
// Fake honors the Manager contract for the observation-relevant methods.
func TestFakeActiveStateFallback(t *testing.T) {
	var m Manager = NewFake()
	f := m.(*Fake)
	f.SetActive("a.service", true)
	if s, _ := m.ActiveState("a.service"); s != "active" {
		t.Errorf("ActiveState fallback from SetActive = %q, want active", s)
	}
	f.SetActiveState("b.service", "failed")
	if s, _ := m.ActiveState("b.service"); s != "failed" {
		t.Errorf("ActiveState override = %q, want failed", s)
	}
	if s, _ := m.ActiveState("c.service"); s != "inactive" {
		t.Errorf("ActiveState default = %q, want inactive", s)
	}
}
