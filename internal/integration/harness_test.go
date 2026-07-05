//go:build integration

// Package integration runs the real magus binary against a real bootc host
// inside a rootful podman container with systemd as PID 1. Unlike the unit
// suites (which drive diff/apply through in-memory fakes), this proves the
// apply/diff/status paths against an actual systemd + filesystem.
//
// Conformance target: registry.wabash.place/chuck/core-base (the FCOS-based
// substrate magus actually runs on). The image is selectable via MAGUS_IT_IMAGE.
// On a dev box without LAN registry access, point MAGUS_IT_IMAGE at a multiarch
// image that boots systemd, e.g. quay.io/fedora/fedora-coreos:stable — that is a
// dev bootstrap, NOT the conformance target.
//
// Build tag keeps this out of the default `go test ./...` gate (it needs podman
// and several GB of image). Run with: go test -tags integration ./internal/integration/
// or `make integration`.
package integration

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const defaultImage = "registry.wabash.place/chuck/core-base:latest"

// magusBin is the host path to the magus binary built for the container's
// architecture, populated by TestMain and copied into each container.
var magusBin string

// unavailable, when non-empty, is the reason the integration environment can't
// be reached; every test skips with it. Set in TestMain so the suite degrades
// to skips (not failures) on a machine without podman or the image.
var unavailable string

func image() string {
	if v := os.Getenv("MAGUS_IT_IMAGE"); v != "" {
		return v
	}
	return defaultImage
}

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("podman"); err != nil {
		unavailable = "podman not found on PATH"
		os.Exit(runMaybeSkip(m))
	}
	if err := ensureImage(image()); err != nil {
		unavailable = fmt.Sprintf("image %s unavailable: %v", image(), err)
		os.Exit(runMaybeSkip(m))
	}
	bin, cleanup, err := buildMagus(image())
	if err != nil {
		// A build failure is a real bug, not an environment gap — fail loud.
		fmt.Fprintf(os.Stderr, "integration: build magus failed: %v\n", err)
		os.Exit(1)
	}
	magusBin = bin
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// runMaybeSkip runs the suite even when unavailable is set so each test emits a
// visible SKIP (with the reason) rather than the suite silently passing.
func runMaybeSkip(m *testing.M) int { return m.Run() }

// ensureImage makes the target image present locally: a no-op if already
// pulled, otherwise a pull. We deliberately do NOT auto-build core-base from
// ../core-image here — that's a `just build` concern with its own credentials.
func ensureImage(ref string) error {
	if _, code := podman("image", "exists", ref); code == 0 {
		return nil
	}
	if out, code := podman("pull", ref); code != 0 {
		return fmt.Errorf("pull failed: %s", strings.TrimSpace(out))
	}
	return nil
}

// buildMagus cross-compiles the magus binary for the image's architecture and
// returns its host path plus a cleanup func. core-base is amd64; on an arm64
// dev box this cross-compiles, and the container runs it under emulation.
func buildMagus(ref string) (string, func(), error) {
	archOut, code := podman("image", "inspect", ref, "--format", "{{.Architecture}}")
	if code != 0 {
		return "", nil, fmt.Errorf("inspect arch: %s", strings.TrimSpace(archOut))
	}
	arch := strings.TrimSpace(archOut)

	dir, err := os.MkdirTemp("", "magus-it-")
	if err != nil {
		return "", nil, err
	}
	bin := dir + "/magus"

	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", bin,
		"github.com/lazypower/magus-cli/cmd/magus")
	cmd.Dir = ".." + string(os.PathSeparator) + ".." // module root from internal/integration
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		return "", nil, fmt.Errorf("%v: %s", err, out)
	}
	return bin, func() { os.RemoveAll(dir) }, nil
}

// podman runs a podman subcommand and returns combined output + exit code.
func podman(args ...string) (string, int) {
	out, err := exec.Command("podman", args...).CombinedOutput()
	return string(out), exitCode(err)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// container is one booted core-base instance for a single test. It owns
// lifecycle (start, readiness, teardown) and the exec/file helpers tests use.
type container struct {
	t    *testing.T
	name string
}

// newContainer boots a fresh privileged systemd container, waits for the
// manager to become responsive, and installs the magus binary at /usr/bin/magus.
// Skips the test if the environment is unavailable.
func newContainer(t *testing.T) *container {
	t.Helper()
	if unavailable != "" {
		t.Skip(unavailable)
	}
	name := "magus-it-" + sanitize(t.Name())
	_, _ = podman("rm", "-f", name) // clear any stale container from a prior run

	if out, code := podman("run", "-d", "--name", name,
		"--privileged", "--systemd=always", image()); code != 0 {
		t.Fatalf("podman run: %s", strings.TrimSpace(out))
	}
	c := &container{t: t, name: name}
	t.Cleanup(func() { _, _ = podman("rm", "-f", name) })

	c.waitReady()
	c.cp(magusBin, "/usr/bin/magus")
	return c
}

// waitReady polls until systemd's manager answers daemon-reload (exit 0). That
// is the readiness signal that matters — is-system-running can sit in "starting"
// for a long time under amd64 emulation while the manager is already usable.
func (c *container) waitReady() {
	c.t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if _, code := podman("exec", c.name, "systemctl", "daemon-reload"); code == 0 {
			return
		}
		time.Sleep(time.Second)
	}
	out, _ := podman("logs", c.name)
	c.t.Fatalf("systemd never became responsive in %s\nlogs:\n%s", c.name, out)
}

// cp copies a host file into the container.
func (c *container) cp(hostPath, containerPath string) {
	c.t.Helper()
	if out, code := podman("cp", hostPath, c.name+":"+containerPath); code != 0 {
		c.t.Fatalf("cp %s -> %s: %s", hostPath, containerPath, strings.TrimSpace(out))
	}
}

// exec runs a command inside the container, returning combined output + exit code.
func (c *container) exec(args ...string) (string, int) {
	full := append([]string{"exec", c.name}, args...)
	return podman(full...)
}

// magus runs the magus binary inside the container.
func (c *container) magus(args ...string) (string, int) {
	return c.exec(append([]string{"magus"}, args...)...)
}

// put writes content to a file inside the container (creating parent dirs).
func (c *container) put(path, content string) {
	c.t.Helper()
	dir := path[:strings.LastIndex(path, "/")]
	if dir != "" {
		if out, code := c.exec("mkdir", "-p", dir); code != 0 {
			c.t.Fatalf("mkdir %s: %s", dir, out)
		}
	}
	cmd := exec.Command("podman", "exec", "-i", c.name, "tee", path)
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		c.t.Fatalf("put %s: %v\n%s", path, err, out)
	}
}

// readFile returns a file's content from inside the container.
func (c *container) readFile(path string) string {
	c.t.Helper()
	out, code := c.exec("cat", path)
	if code != 0 {
		c.t.Fatalf("cat %s (exit %d): %s", path, code, out)
	}
	return out
}

// exists reports whether a path exists inside the container.
func (c *container) exists(path string) bool {
	_, code := c.exec("test", "-e", path)
	return code == 0
}

// mode returns the octal permission string (e.g. "644") of a path.
func (c *container) mode(path string) string {
	c.t.Helper()
	out, code := c.exec("stat", "-c", "%a", path)
	if code != 0 {
		c.t.Fatalf("stat %s: %s", path, out)
	}
	return strings.TrimSpace(out)
}

// isEnabled / isActive report systemd state for a unit (trimmed, may be
// "not-found", "inactive", etc.).
func (c *container) isEnabled(unit string) string {
	out, _ := c.exec("systemctl", "is-enabled", unit)
	return strings.TrimSpace(out)
}

func (c *container) isActive(unit string) string {
	out, _ := c.exec("systemctl", "is-active", unit)
	return strings.TrimSpace(out)
}

// sanitize makes a test name safe for a container name.
func sanitize(s string) string {
	return strings.NewReplacer("/", "-", " ", "-", "_", "-").Replace(strings.ToLower(s))
}
