package main

import (
	"runtime/debug"
	"testing"
)

func TestVersionFromBuildInfo(t *testing.T) {
	tagged := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.3.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "25186841b74d05539facfdd1d9530545a307b4f3"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
	dirty := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.3.1-0.20261120120000-abcdef123456+dirty"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abcdef1234567890"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	noVCS := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}

	tests := []struct {
		name                  string
		info                  *debug.BuildInfo
		version, commit       string
		wantVersion, wantComm string
	}{
		{"tagged build", tagged, "dev", "unknown", "0.3.0", "2518684"},
		{"dirty tree", dirty, "dev", "unknown", "0.3.1-0.20261120120000-abcdef123456+dirty", "abcdef1-dirty"},
		{"no vcs info", noVCS, "dev", "unknown", "dev", "unknown"},
		{"ldflags win", tagged, "9.9.9", "fffffff", "9.9.9", "fffffff"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, c := versionFromBuildInfo(tt.info, tt.version, tt.commit)
			if v != tt.wantVersion || c != tt.wantComm {
				t.Errorf("got (%q, %q), want (%q, %q)", v, c, tt.wantVersion, tt.wantComm)
			}
		})
	}
}
