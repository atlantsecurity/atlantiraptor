package config

// release_version is the Atlantiraptor release this binary was built
// as (for example "1.0.3"). Release builds set it with
//
//	-ldflags '-X www.velocidex.com/golang/velociraptor/config.release_version=1.0.3'
//
// Development builds leave it empty; the self-updater then never
// installs anything on its own (see services/selfupdate).
var release_version string

// ReleaseVersion returns the Atlantiraptor release version, or "" for
// a development build.
func ReleaseVersion() string {
	return release_version
}
