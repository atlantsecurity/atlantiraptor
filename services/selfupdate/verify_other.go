//go:build !windows

package selfupdate

// Only Windows builds are Authenticode signed, and only Windows can
// check that signature against its trusted roots, so other platforms
// report updates but never install them.
const installSupported = false

func verifyTrust(path string) error {
	return errUnsupported
}
