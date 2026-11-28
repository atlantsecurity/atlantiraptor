package selfupdate

import "strings"

// DefaultAgentService is the Windows service the Atlantiraptor MSI and
// the Deploy install script create.
const DefaultAgentService = "Atlantiraptor"

// ServiceBinaryFromCommandLine returns the program of a Windows service
// command line such as
//
//	"C:\Program Files\Atlant Security\Atlantiraptor\Atlantiraptor.exe" --config "..." service run
//
// An unquoted path is taken up to the first ".exe" (paths with spaces
// are ambiguous without quotes).
func ServiceBinaryFromCommandLine(command_line string) string {
	s := strings.TrimSpace(command_line)
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end < 0 {
			return ""
		}
		return s[1 : end+1]
	}
	lower := strings.ToLower(s)
	if i := strings.Index(lower, ".exe"); i >= 0 {
		return s[:i+4]
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}
