package config

import (
	"testing"

	"www.velocidex.com/golang/velociraptor/constants"
)

func TestGetVersionReportsRelease(t *testing.T) {
	saved := release_version
	defer func() { release_version = saved }()

	release_version = ""
	if v := GetVersion(); v.Name != "velociraptor" || v.Version != constants.VERSION {
		t.Fatalf("development build: got %v %v", v.Name, v.Version)
	}

	release_version = "1.0.6"
	if v := GetVersion(); v.Name != AgentName || v.Version != "1.0.6" {
		t.Fatalf("release build: got %v %v", v.Name, v.Version)
	}
}
