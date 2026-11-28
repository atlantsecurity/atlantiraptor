package api

import (
	"testing"
	"time"

	"www.velocidex.com/golang/velociraptor/vtesting/assert"
)

func fleetHost(id, os, version string, seenAgo time.Duration, now time.Time) fleetClient {
	return fleetClient{
		ClientId:   id,
		Hostname:   "host-" + id,
		OS:         os,
		Version:    version,
		LastSeenAt: uint64(now.Add(-seenAgo).UnixNano() / 1000),
	}
}

func TestFleetSummaryCountsAndBuckets(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	day := 24 * time.Hour
	clients := []fleetClient{
		fleetHost("C.1", "windows", "1.0.6", time.Minute, now),
		fleetHost("C.2", "windows", "1.0.5", 2*time.Hour, now),
		fleetHost("C.3", "linux", "0.77.4", 10*day, now),
		fleetHost("C.4", "windows", "", 40*day, now),
		fleetHost("C.5", "Windows", "1.0.6", 31*day, now),
	}

	s := summarizeFleet(clients, now, 200)

	assert.Equal(t, 5, s.Total)
	assert.Equal(t, 1, s.Online)
	assert.Equal(t, 1, s.Quiet7Count)
	assert.Equal(t, 2, s.Quiet30Count)
	assert.Equal(t, []string{"C.3"}, ids(s.Quiet7))
	// Longest quiet first.
	assert.Equal(t, []string{"C.4", "C.5"}, ids(s.Quiet30))

	// The histogram groups by OS (lower case) and version; an empty
	// version counts as "unknown".
	got := map[string]int{}
	for _, v := range s.Versions {
		got[v.OS+"/"+v.Version] = v.Count
	}
	assert.Equal(t, map[string]int{
		"windows/1.0.6":   2,
		"windows/1.0.5":   1,
		"windows/unknown": 1,
		"linux/0.77.4":    1,
	}, got)
}

func TestFleetSummaryCapsQuietLists(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clients := []fleetClient{}
	for i := 0; i < 10; i++ {
		clients = append(clients, fleetHost(string(rune('a'+i)), "linux", "1", time.Duration(40+i)*24*time.Hour, now))
	}
	s := summarizeFleet(clients, now, 3)
	assert.Equal(t, 10, s.Quiet30Count)
	assert.Equal(t, 3, len(s.Quiet30))
}

func TestFleetOutdatedFilter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clients := []fleetClient{
		fleetHost("C.1", "windows", "1.0.6", time.Minute, now),
		fleetHost("C.2", "windows", "1.0.5", time.Minute, now),
		fleetHost("C.3", "linux", "1.0.5", time.Minute, now),
		fleetHost("C.4", "Windows", "1.0.4", time.Minute, now),
	}
	assert.Equal(t, []string{"C.2", "C.4"},
		filterFleetClients(clients, "windows", []string{"1.0.5", "1.0.4"}))
	assert.Equal(t, []string{}, filterFleetClients(clients, "darwin", []string{"1.0.5"}))
}

func ids(hosts []fleetClient) []string {
	res := []string{}
	for _, h := range hosts {
		res = append(res, h.ClientId)
	}
	return res
}

func TestOneOffLookupLimit(t *testing.T) {
	assert.Equal(t, 6, oneOffLookupLimit(0))
	assert.Equal(t, 255, oneOffLookupLimit(250))
	assert.Equal(t, maxOneOffClients+5, oneOffLookupLimit(50000))
}
