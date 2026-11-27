package selfupdate

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// semver is a plain MAJOR.MINOR.PATCH release number. Pre-release and
// build suffixes are not accepted: only full releases are installed.
type semver [3]int

func parseVersion(s string) (semver, bool) {
	var v semver
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		if p == "" || len(p) > 6 {
			return v, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || strconv.Itoa(n) != p {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func (self semver) Less(other semver) bool {
	for i := range self {
		if self[i] != other[i] {
			return self[i] < other[i]
		}
	}
	return false
}

func (self semver) String() string {
	return fmt.Sprintf("%d.%d.%d", self[0], self[1], self[2])
}

var errUnsupported = errors.New("installing updates is only supported on Windows servers")
