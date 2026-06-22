package ir

import "testing"

func TestQuadletGeneratedService(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"ollama.container", "ollama.service"},
		{"data.volume", "data-volume.service"},
		{"backend.network", "backend-network.service"},
	}
	for _, c := range cases {
		got, err := QuadletGeneratedService(c.name)
		if err != nil {
			t.Errorf("QuadletGeneratedService(%q): unexpected error %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("QuadletGeneratedService(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestQuadletGeneratedServiceRejectsUnsupported(t *testing.T) {
	for _, q := range []string{"app.pod", "app.kube", "app.image", "app.build", "noext"} {
		if _, err := QuadletGeneratedService(q); err == nil {
			t.Errorf("QuadletGeneratedService(%q): want error, got nil", q)
		}
	}
}
