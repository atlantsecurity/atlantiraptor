package agentupdate

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"www.velocidex.com/golang/velociraptor/config"
	"www.velocidex.com/golang/velociraptor/services/selfupdate"
)

// The rollout logic, kept free of I/O so it can be tested on its own.

const (
	PhaseCanary = "canary"
	PhaseAll    = "all"
	PhasePaused = "paused"

	StateUpgrading = "upgrading"
	StateRetry     = "retry"
	StateFailed    = "failed"
	StateUpgraded  = "upgraded"

	// An agent counts as online if it was seen this recently. Only
	// online agents are sent the upgrade, so an attempt's clock starts
	// when the agent can actually run it.
	onlineWindow = 15 * time.Minute

	// After this long, look at the collection that was scheduled.
	checkAfter = 10 * time.Minute
	// A collection that finished this long ago without the agent
	// reporting the new version failed (the new agent did not stay up
	// and was rolled back, or the swap failed).
	finishedGrace = 30 * time.Minute
	// A collection that never ran within this long failed.
	stuckAfter = 24 * time.Hour

	MaxAttempts  = 3
	retryAfter   = 6 * time.Hour
	maxPerTick   = 200
	maxFailedRow = 100

	// The canary passes when at most this share of its attempts failed.
	canaryMaxFailurePercent = 20
)

// clientView is what the rollout needs to know about one client.
type clientView struct {
	OrgId    string
	ClientId string
	Hostname string
	OS       string
	Name     string // agent name, "Atlantiraptor" for release builds
	Version  string // agent version
	LastSeen time.Time
	Excluded bool
}

func (self clientView) key() string {
	return self.OrgId + "/" + self.ClientId
}

// atlantiraptorVersion is the release an agent runs, or "" for agents
// that do not report one (built before they reported it, or
// development builds).
func (self clientView) atlantiraptorVersion() string {
	if !strings.EqualFold(self.Name, config.AgentName) {
		return ""
	}
	v, ok := selfupdate.ParseVersion(self.Version)
	if !ok {
		return ""
	}
	return v
}

func (self clientView) label() string {
	if v := self.atlantiraptorVersion(); v != "" {
		return v
	}
	if self.Version == "" {
		return "unknown"
	}
	name := self.Name
	if name == "" {
		name = "agent"
	}
	return name + " " + self.Version + " (before automatic upgrades)"
}

// ClientState tracks one client through a rollout.
type ClientState struct {
	OrgId       string `json:"org_id"`
	ClientId    string `json:"client_id"`
	Hostname    string `json:"hostname,omitempty"`
	Canary      bool   `json:"canary,omitempty"`
	State       string `json:"state,omitempty"`
	FlowId      string `json:"flow_id,omitempty"`
	Attempts    int    `json:"attempts,omitempty"`
	LastAttempt int64  `json:"last_attempt,omitempty"`
	NextAttempt int64  `json:"next_attempt,omitempty"`
	FromVersion string `json:"from_version,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Rollout is the progress of upgrading agents to one version.
type Rollout struct {
	Target       string                  `json:"target"`
	Started      int64                   `json:"started"`
	Phase        string                  `json:"phase"`
	PhaseChanged int64                   `json:"phase_changed"`
	PausedReason string                  `json:"paused_reason,omitempty"`
	Clients      map[string]*ClientState `json:"clients,omitempty"`
}

func newRollout(target string, now time.Time, canary_percent int) *Rollout {
	phase := PhaseCanary
	if canary_percent <= 0 || canary_percent >= 100 {
		phase = PhaseAll
	}
	return &Rollout{
		Target:       target,
		Started:      now.Unix(),
		Phase:        phase,
		PhaseChanged: now.Unix(),
		Clients:      make(map[string]*ClientState),
	}
}

// canaryScore places a client in [0, 100) for this target, so each
// release picks a different, stable canary group.
func canaryScore(client_id, target string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(target + "/" + client_id))
	return h.Sum32() % 100
}

// flowResult is what the scheduled collection says.
type flowResult struct {
	State  string // "running", "finished", "error" or "missing"
	Status string
}

// tickInput is everything one round of the rollout looks at.
type tickInput struct {
	Now      time.Time
	Settings Settings
	Clients  []clientView
	// Looks up the collection scheduled for a client.
	Flow func(c *ClientState) flowResult
}

// Counts summarizes the fleet for the console.
type Counts struct {
	Clients     int            `json:"clients"`
	Windows     int            `json:"windows"`
	UpToDate    int            `json:"up_to_date"`
	Waiting     int            `json:"waiting"`
	Offline     int            `json:"offline"`
	Upgrading   int            `json:"upgrading"`
	Retrying    int            `json:"retrying"`
	Failed      int            `json:"failed"`
	Excluded    int            `json:"excluded"`
	Newer       int            `json:"newer"`
	Unsupported int            `json:"unsupported"`
	Canary      int            `json:"canary"`
	CanaryDone  int            `json:"canary_done"`
	Versions    map[string]int `json:"versions"`
	Platforms   map[string]int `json:"platforms"`
}

type FailedClient struct {
	OrgId    string `json:"org_id"`
	ClientId string `json:"client_id"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	Attempts int    `json:"attempts"`
	Error    string `json:"error"`
	FlowId   string `json:"flow_id,omitempty"`
}

type tickResult struct {
	Schedule []*ClientState
	Counts   Counts
	Failed   []FailedClient
	Events   []string
}

// needsUpgrade decides whether a Windows agent should get the target.
// Without a pinned version agents are only ever moved forward; with
// one they are moved to exactly that version.
func needsUpgrade(c clientView, target string, pinned bool) (needs bool, newer bool) {
	v := c.atlantiraptorVersion()
	if v == "" {
		return true, false
	}
	cmp, ok := selfupdate.CompareVersions(v, target)
	if !ok {
		return true, false
	}
	if cmp == 0 {
		return false, false
	}
	if cmp > 0 && !pinned {
		return false, true
	}
	return true, false
}

// tick advances the rollout by one round: it records what happened to
// scheduled upgrades, moves from the canary to everyone when the canary
// passed, and returns the clients to send the upgrade to now.
func (self *Rollout) tick(in tickInput) tickResult {
	now := in.Now
	res := tickResult{Counts: Counts{
		Versions:  make(map[string]int),
		Platforms: make(map[string]int),
	}}
	pinned := in.Settings.PinnedVersion != ""
	pct := in.Settings.CanaryPercent

	type candidate struct {
		view  clientView
		state *ClientState
		score uint32
	}
	var candidates []candidate
	seen := make(map[string]bool)
	newly_upgraded := 0

	for _, c := range in.Clients {
		res.Counts.Clients++
		os := strings.ToLower(c.OS)
		if os == "" {
			os = "unknown"
		}
		res.Counts.Platforms[os]++
		if os != "windows" {
			res.Counts.Unsupported++
			continue
		}
		res.Counts.Windows++
		res.Counts.Versions[c.label()]++

		key := c.key()
		seen[key] = true
		st := self.Clients[key]

		needs, newer := needsUpgrade(c, self.Target, pinned)
		if newer {
			res.Counts.Newer++
		}
		if !needs {
			res.Counts.UpToDate++
			if st != nil && st.State != StateUpgraded && st.Attempts > 0 {
				st.State = StateUpgraded
				st.Error = ""
				newly_upgraded++
			}
			if st != nil && st.Canary {
				res.Counts.Canary++
				res.Counts.CanaryDone++
			}
			continue
		}
		if c.Excluded {
			res.Counts.Excluded++
			continue
		}

		if st == nil {
			st = &ClientState{
				OrgId:    c.OrgId,
				ClientId: c.ClientId,
				Canary:   pct >= 100 || (pct > 0 && int(canaryScore(c.ClientId, self.Target)) < pct),
			}
			self.Clients[key] = st
		}
		st.Hostname = c.Hostname
		if st.Canary {
			res.Counts.Canary++
		}

		// Follow up on a scheduled upgrade.
		if st.State == StateUpgrading {
			self.followUp(st, c, now, in.Flow)
		}
		if st.State == StateRetry && now.Unix() >= st.NextAttempt {
			st.State = ""
		}

		switch st.State {
		case StateUpgrading:
			res.Counts.Upgrading++
		case StateRetry:
			res.Counts.Retrying++
		case StateFailed:
			res.Counts.Failed++
			if len(res.Failed) < maxFailedRow {
				res.Failed = append(res.Failed, FailedClient{
					OrgId: c.OrgId, ClientId: c.ClientId, Hostname: c.Hostname,
					Version: c.label(), Attempts: st.Attempts, Error: st.Error,
					FlowId: st.FlowId,
				})
			}
		case StateUpgraded, "":
			// Upgraded before but back on an old version (for example
			// reinstalled from an old package): start again.
			st.State = ""
			if now.Sub(c.LastSeen) > onlineWindow {
				res.Counts.Offline++
				continue
			}
			res.Counts.Waiting++
			candidates = append(candidates, candidate{
				view: c, state: st, score: canaryScore(c.ClientId, self.Target)})
		}
	}

	if newly_upgraded > 0 {
		res.Events = append(res.Events, fmt.Sprintf(
			"%d agents now run %v", newly_upgraded, self.Target))
	}

	// Forget clients that were deleted.
	for key := range self.Clients {
		if !seen[key] {
			delete(self.Clients, key)
		}
	}

	if self.Phase == PhaseCanary {
		// A small fleet can have no client in the canary percentage:
		// then the first waiting client by score is the canary.
		if res.Counts.Canary == 0 && len(candidates) > 0 {
			best := 0
			for i := range candidates {
				if candidates[i].score < candidates[best].score {
					best = i
				}
			}
			candidates[best].state.Canary = true
			res.Counts.Canary++
		}
		self.evaluateCanary(now, in.Settings, &res)
	}

	if self.Phase == PhasePaused {
		return res
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score < candidates[j].score
	})
	for _, cand := range candidates {
		if len(res.Schedule) >= maxPerTick {
			break
		}
		if self.Phase == PhaseCanary && !cand.state.Canary {
			continue
		}
		res.Schedule = append(res.Schedule, cand.state)
	}
	return res
}

func (self *Rollout) followUp(st *ClientState, c clientView, now time.Time,
	flow func(*ClientState) flowResult) {
	since := now.Sub(time.Unix(st.LastAttempt, 0))
	if since < checkAfter || flow == nil {
		return
	}
	r := flow(st)
	switch r.State {
	case "error":
		msg := r.Status
		if msg == "" {
			msg = "the upgrade collection failed"
		}
		self.attemptFailed(st, now, msg)
	case "missing":
		self.attemptFailed(st, now, "the upgrade collection is gone")
	case "finished":
		if since >= finishedGrace {
			self.attemptFailed(st, now, fmt.Sprintf(
				"the upgrade ran but the agent still reports %v (see agent-upgrade.log in the agent's folder)",
				c.label()))
		}
	default:
		if since >= stuckAfter {
			self.attemptFailed(st, now, "the upgrade collection did not complete within a day")
		}
	}
}

func (self *Rollout) attemptFailed(st *ClientState, now time.Time, msg string) {
	st.Error = msg
	if st.Attempts >= MaxAttempts {
		st.State = StateFailed
		return
	}
	st.State = StateRetry
	st.NextAttempt = now.Add(retryAfter).Unix()
}

func (self *Rollout) evaluateCanary(now time.Time, s Settings, res *tickResult) {
	soak := time.Duration(s.CanaryHours) * time.Hour
	if now.Sub(time.Unix(self.Started, 0)) < soak {
		return
	}
	attempted, failed, upgraded := 0, 0, 0
	for _, st := range self.Clients {
		if !st.Canary || st.Attempts == 0 {
			continue
		}
		attempted++
		switch {
		case st.State == StateUpgraded:
			upgraded++
		case st.State == StateFailed || st.Error != "":
			failed++
		}
	}
	if attempted > 0 && failed*100 > canaryMaxFailurePercent*attempted {
		self.setPhase(PhasePaused, now)
		self.PausedReason = fmt.Sprintf(
			"%d of %d canary upgrades to %v failed. Fix the cause, then resume the rollout or retry the failed agents.",
			failed, attempted, self.Target)
		res.Events = append(res.Events, "rollout paused: "+self.PausedReason)
		return
	}
	// Wait for at least one canary to succeed, unless there was no
	// canary to try (every canary agent offline or already current).
	if upgraded > 0 || attempted == 0 {
		self.setPhase(PhaseAll, now)
		res.Events = append(res.Events, fmt.Sprintf(
			"canary passed (%d of %d upgraded); upgrading every agent to %v",
			upgraded, attempted, self.Target))
	}
}

func (self *Rollout) setPhase(phase string, now time.Time) {
	self.Phase = phase
	self.PhaseChanged = now.Unix()
	if phase != PhasePaused {
		self.PausedReason = ""
	}
}

// scheduled records that the upgrade was sent to a client.
func (self *ClientState) scheduled(flow_id, from string, now time.Time) {
	self.State = StateUpgrading
	self.FlowId = flow_id
	self.Attempts++
	self.LastAttempt = now.Unix()
	self.NextAttempt = 0
	self.FromVersion = from
	self.Error = ""
}

// scheduleFailed records that the upgrade could not even be sent.
func (self *Rollout) scheduleFailed(st *ClientState, now time.Time, err error) {
	st.Attempts++
	st.LastAttempt = now.Unix()
	self.attemptFailed(st, now, "scheduling the upgrade: "+err.Error())
}
