package main

import (
	"runtime/debug"
	"strings"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Version, Commit = versionFromBuildInfo(info, Version, Commit)
	}
}

// versionFromBuildInfo fills in a version and commit that were not set at link time
// from the build information the Go toolchain embeds in every binary. A plain
// `go build` in a git checkout records the module version (from the tag, or a
// pseudo-version) and the VCS revision, so a binary built without the Makefile's
// -ldflags still reports what it was built from. Values set at link time win.
func versionFromBuildInfo(info *debug.BuildInfo, version, commit string) (string, string) {
	if version == "dev" {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			version = strings.TrimPrefix(v, "v")
		}
	}

	if commit == "unknown" {
		var revision string
		var modified bool
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		if revision != "" {
			if len(revision) > 7 {
				revision = revision[:7]
			}
			if modified {
				revision += "-dirty"
			}
			commit = revision
		}
	}

	return version, commit
}
