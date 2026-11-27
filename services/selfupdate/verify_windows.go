//go:build windows

package selfupdate

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// installSupported reports whether this platform can verify and
// install updates.
const installSupported = true

// verifyTrust asks Windows to verify the file's Authenticode signature
// against the machine's trusted roots, with revocation checks.
func verifyTrust(path string) error {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	data := &windows.WinTrustData{
		Size:             uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: path16,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return verifyErr
}
