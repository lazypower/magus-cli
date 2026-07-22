// Package ir is the intermediate representation magus consumes.
//
// The Butane file is the input format. The IR is the strict subset magus
// reconciles: storage.files, storage.directories, systemd.units. Anything
// outside this subset is invisible to magus — see docs/spec-reconciler.md
// "IR contract".
package ir

import (
	"fmt"
	"path/filepath"
	"strings"
)

// IR is the parsed, in-memory representation of a Butane file's reconcilable
// subset.
type IR struct {
	Files       []File
	Directories []Directory
	Units       []Unit
	Quadlets    []Quadlet
	Users       []User
	Groups      []Group
}

// User is a declared principal from Butane's passwd.users — a day-2 identity
// magus reconciles (see docs/adr-0003-principal-reconciliation.md). Only the v1
// consumed subset is carried; magus reconciles a principal only when policy's
// manage_users allowlist permits it.
//
// UID is *int so "not declared" (nil) is distinct from "declared uid 0" — the
// ADR requires a uid for every managed principal, enforced at validate. UID and
// PrimaryGroup and HomeDir are the principal's *identity* (immutable after
// create); Shell and supplementary Groups are mutable and reconciled each apply.
//
// HasPassword / HasSSHKeys record that the Butane declared password_hash or
// ssh_authorized_keys — both deferred in v1. They are refused at validate for a
// *managed* principal (a workload account is not a login account); on an
// unmanaged principal they are Ignition's concern and ignored.
type User struct {
	Name         string
	UID          *int
	PrimaryGroup string
	Groups       []string
	Shell        string
	HomeDir      string
	System       bool
	HasPassword  bool
	HasSSHKeys   bool
}

// Group is a declared principal from Butane's passwd.groups. GID is *int for the
// same not-declared-vs-declared-zero reason as User.UID.
type Group struct {
	Name   string
	GID    *int
	System bool
}

// File is a declared regular file under storage.files.
//
// UID and GID are *int rather than int so the IR can distinguish "owned by
// nobody in particular — let the writer decide" (nil) from "explicitly owned
// by user 0" (non-nil pointer to 0). This mirrors Ignition's actual semantic
// and lets magus run as a non-root user during development without forcing
// every fixture to enumerate ownership.
type File struct {
	Path     string
	Mode     uint32
	UID      *int
	GID      *int
	Contents []byte
}

// Directory is a declared directory under storage.directories. Same UID/GID
// semantics as File.
type Directory struct {
	Path string
	Mode uint32
	UID  *int
	GID  *int
}

// Unit is a declared systemd unit. If DropIns is non-empty, the unit is
// extended via drop-ins rather than (or in addition to) replacing the unit
// file itself.
//
// Enabled is *bool, not bool, to preserve Ignition/Butane's tri-state
// `enabled` semantic. This is load-bearing: a unit declared only to attach a
// drop-in (or one that simply omits `enabled`) must NOT have its enablement
// touched — collapsing nil to false would make magus actively `systemctl
// disable` a service it was only extending.
//
//	nil   → enablement is not declared; magus does not reconcile it
//	true  → magus ensures the unit is enabled
//	false → magus ensures the unit is disabled
type Unit struct {
	Name     string
	Enabled  *bool
	Contents string
	DropIns  []DropIn
}

// DropIn is a systemd drop-in fragment. Magus places all drop-ins as
// 10-magus.conf so they sort predictably.
type DropIn struct {
	Name     string
	Contents string
}

// Quadlet is a podman-managed container declaration auto-promoted from a
// storage.files entry whose path falls under /etc/containers/systemd/ and
// whose extension is one of v1's supported quadlet types (.container,
// .volume, .network). The systemd-quadlet generator runs at daemon-reload
// time and materializes a .service from each quadlet source — that .service
// is what magus enables, starts, and (on content change) restarts.
//
// Name is the basename of Path (e.g., "ollama.container"). The generated
// .service name is derived from Name via QuadletGeneratedService.
type Quadlet struct {
	Path     string
	Name     string
	Mode     uint32
	UID      *int
	GID      *int
	Contents []byte
}

// UnitNameFromPath recovers the systemd unit name from a managed path. It
// returns the unit's name for both unit-body paths
// (/etc/systemd/system/foo.service) and drop-in paths
// (/etc/systemd/system/foo.service.d/10-magus.conf). Lives in ir so the policy
// gate can derive unit names without importing diff.
func UnitNameFromPath(p string) string {
	parent := filepath.Base(filepath.Dir(p))
	if strings.HasSuffix(parent, ".d") {
		return strings.TrimSuffix(parent, ".d")
	}
	return filepath.Base(p)
}

// QuadletGeneratedService returns the .service name the systemd-quadlet
// generator materializes from a quadlet source name. v1 supported types:
//
//	foo.container → foo.service
//	foo.volume    → foo-volume.service
//	foo.network   → foo-network.service
//
// Unsupported types return an empty string and a non-nil error so callers can
// surface a clear message rather than guess. This lives in ir (not diff) so
// both diff/apply and the policy gate can derive the generated-service name
// without an import cycle.
func QuadletGeneratedService(quadletName string) (string, error) {
	ext := filepath.Ext(quadletName)
	base := strings.TrimSuffix(quadletName, ext)
	switch ext {
	case ".container":
		return base + ".service", nil
	case ".volume":
		return base + "-volume.service", nil
	case ".network":
		return base + "-network.service", nil
	}
	return "", fmt.Errorf("unsupported quadlet type: %s", ext)
}
