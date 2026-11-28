package api

// Fleet health aggregates, computed on the server so the console does
// not have to download every client record to count them.

import (
	"sort"
	"strings"
	"time"
)

const (
	fleetOnlineWindow = 15 * time.Minute
	fleetDay          = 24 * time.Hour
)

// The few client fields the fleet page needs.
type fleetClient struct {
	ClientId   string `json:"client_id"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Version    string `json:"version"`
	LastSeenAt uint64 `json:"last_seen_at"` // microseconds
}

type fleetVersionCount struct {
	OS      string `json:"os"`
	Version string `json:"version"`
	Count   int    `json:"count"`
}

type fleetSummary struct {
	Total        int                 `json:"total"`
	Online       int                 `json:"online"`
	Quiet7Count  int                 `json:"quiet_7_count"`
	Quiet30Count int                 `json:"quiet_30_count"`
	Quiet7       []fleetClient       `json:"quiet_7"`
	Quiet30      []fleetClient       `json:"quiet_30"`
	Versions     []fleetVersionCount `json:"versions"`
}

func fleetOS(c fleetClient) string {
	return strings.ToLower(strings.TrimSpace(c.OS))
}

func fleetVersion(c fleetClient) string {
	if c.Version == "" {
		return "unknown"
	}
	return c.Version
}

func fleetLastSeen(c fleetClient) time.Time {
	return time.UnixMicro(int64(c.LastSeenAt))
}

// summarizeFleet counts clients by state and version. The quiet lists
// hold at most max_listed hosts each, longest quiet first; the counts
// always cover every client.
func summarizeFleet(clients []fleetClient, now time.Time, max_listed int) fleetSummary {
	res := fleetSummary{
		Total:    len(clients),
		Quiet7:   []fleetClient{},
		Quiet30:  []fleetClient{},
		Versions: []fleetVersionCount{},
	}

	type key struct{ os, version string }
	counts := map[key]int{}

	for _, c := range clients {
		counts[key{fleetOS(c), fleetVersion(c)}]++

		age := now.Sub(fleetLastSeen(c))
		switch {
		case age < fleetOnlineWindow:
			res.Online++
		case age >= 30*fleetDay:
			res.Quiet30 = append(res.Quiet30, c)
		case age >= 7*fleetDay:
			res.Quiet7 = append(res.Quiet7, c)
		}
	}

	res.Quiet7Count = len(res.Quiet7)
	res.Quiet30Count = len(res.Quiet30)
	res.Quiet7 = oldestFirst(res.Quiet7, max_listed)
	res.Quiet30 = oldestFirst(res.Quiet30, max_listed)

	for k, n := range counts {
		res.Versions = append(res.Versions, fleetVersionCount{OS: k.os, Version: k.version, Count: n})
	}
	sort.Slice(res.Versions, func(i, j int) bool {
		a, b := res.Versions[i], res.Versions[j]
		if a.OS != b.OS {
			return a.OS < b.OS
		}
		return a.Version < b.Version
	})
	return res
}

func oldestFirst(hosts []fleetClient, max int) []fleetClient {
	sorted := append([]fleetClient{}, hosts...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].LastSeenAt < sorted[j].LastSeenAt
	})
	if len(sorted) > max {
		sorted = sorted[:max]
	}
	return sorted
}

// filterFleetClients returns the IDs of the clients of one OS that run
// any of the given versions (the console works out which versions are
// outdated).
func filterFleetClients(clients []fleetClient, os string, versions []string) []string {
	want := map[string]bool{}
	for _, v := range versions {
		want[v] = true
	}
	os = strings.ToLower(os)
	res := []string{}
	for _, c := range clients {
		if fleetOS(c) == os && c.Version != "" && want[c.Version] {
			res = append(res, c.ClientId)
		}
	}
	return res
}
