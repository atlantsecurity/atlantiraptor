package agentupdate

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeBackend struct {
	mu        sync.Mutex
	clients   []clientView
	scheduled []string
	flows     map[string]flowResult // flow id -> result
	prepErr   error
	audits    []string
	n         int
}

func (self *fakeBackend) PrepareBinary(ctx context.Context, version string, cached *BinaryInfo) (*BinaryInfo, error) {
	if self.prepErr != nil {
		return nil, self.prepErr
	}
	return &BinaryInfo{Version: version, SHA256: "hash-" + version, Signer: "Atlant Security EOOD"}, nil
}

func (self *fakeBackend) PublishTool(ctx context.Context, bin *BinaryInfo) error { return nil }

func (self *fakeBackend) ListClients(ctx context.Context, exclude_label string) ([]clientView, error) {
	self.mu.Lock()
	defer self.mu.Unlock()
	return append([]clientView(nil), self.clients...), nil
}

func (self *fakeBackend) FlowResult(ctx context.Context, org_id, client_id, flow_id string) flowResult {
	self.mu.Lock()
	defer self.mu.Unlock()
	if r, ok := self.flows[flow_id]; ok {
		return r
	}
	return flowResult{State: "running"}
}

func (self *fakeBackend) Schedule(ctx context.Context, org_id, client_id, target string) (string, error) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.n++
	self.scheduled = append(self.scheduled, client_id)
	return fmt.Sprintf("F.%d", self.n), nil
}

func (self *fakeBackend) Audit(ctx context.Context, principal, op string, d map[string]interface{}) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.audits = append(self.audits, op)
}

func (self *fakeBackend) takeScheduled() []string {
	self.mu.Lock()
	defer self.mu.Unlock()
	s := self.scheduled
	self.scheduled = nil
	return s
}

// setVersion makes clients report a version, as they do after
// restarting on it.
func (self *fakeBackend) setVersion(ids []string, version string) {
	self.mu.Lock()
	defer self.mu.Unlock()
	want := make(map[string]bool)
	for _, id := range ids {
		want[id] = true
	}
	for i := range self.clients {
		if want[self.clients[i].ClientId] {
			self.clients[i].Name = "Atlantiraptor"
			self.clients[i].Version = version
		}
	}
}

func (self *fakeBackend) touch(now time.Time) {
	self.mu.Lock()
	defer self.mu.Unlock()
	for i := range self.clients {
		self.clients[i].LastSeen = now
	}
}

type testClock struct{ t time.Time }

func (self *testClock) now() time.Time      { return self.t }
func (self *testClock) add(d time.Duration) { self.t = self.t.Add(d) }

func newTestService(t *testing.T, b *fakeBackend, clock *testClock) *Service {
	s := newService(nil, b)
	s.state_path = filepath.Join(t.TempDir(), stateFileName)
	s.now = clock.now
	return s
}

func fleet(windows, linux int, now time.Time) []clientView {
	var out []clientView
	for i := 0; i < windows; i++ {
		out = append(out, clientView{OrgId: "root", ClientId: fmt.Sprintf("C.w%03d", i),
			Hostname: fmt.Sprintf("win%03d", i), OS: "windows",
			Name: "velociraptor", Version: "0.77.4", LastSeen: now})
	}
	for i := 0; i < linux; i++ {
		out = append(out, clientView{OrgId: "root", ClientId: fmt.Sprintf("C.l%03d", i),
			OS: "linux", Name: "velociraptor", Version: "0.77.4", LastSeen: now})
	}
	return out
}

func pinnedSettings(s *Service, version string) {
	s.settings.PinnedVersion = version
}

func TestCanaryThenEveryone(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	b := &fakeBackend{clients: fleet(100, 5, clock.t), flows: map[string]flowResult{}}
	s := newTestService(t, b, clock)
	pinnedSettings(s, "1.0.4")
	ctx := context.Background()

	s.Tick(ctx)
	canary := b.takeScheduled()
	if len(canary) < 1 || len(canary) > 30 {
		t.Fatalf("canary of %d agents", len(canary))
	}
	st := s.Status()
	if st.Phase != PhaseCanary || st.Counts.Windows != 100 || st.Counts.Unsupported != 5 {
		t.Fatalf("status %+v", st)
	}
	if st.Counts.Versions["velociraptor 0.77.4 (before automatic upgrades)"] != 100 {
		t.Errorf("versions %v", st.Counts.Versions)
	}

	// The canary upgrades; nothing more goes out during the soak.
	clock.add(time.Hour)
	b.touch(clock.t)
	b.setVersion(canary, "1.0.4")
	s.Tick(ctx)
	if got := b.takeScheduled(); len(got) != 0 {
		t.Fatalf("scheduled %d during the soak", len(got))
	}
	st = s.Status()
	if st.Counts.UpToDate != len(canary) || st.Counts.CanaryDone != len(canary) {
		t.Errorf("counts %+v", st.Counts)
	}

	// After the soak, everyone else.
	clock.add(24 * time.Hour)
	b.touch(clock.t)
	s.Tick(ctx)
	rest := b.takeScheduled()
	if len(rest) != 100-len(canary) {
		t.Fatalf("scheduled %d after the canary, want %d", len(rest), 100-len(canary))
	}
	if s.Status().Phase != PhaseAll {
		t.Errorf("phase %v", s.Status().Phase)
	}

	// Everyone reports the new version: done, and nothing is resent.
	clock.add(time.Hour)
	b.touch(clock.t)
	b.setVersion(rest, "1.0.4")
	s.Tick(ctx)
	if got := b.takeScheduled(); len(got) != 0 {
		t.Errorf("rescheduled %d", len(got))
	}
	if st := s.Status(); st.State != "done" || st.Counts.UpToDate != 100 {
		t.Errorf("status %v %+v", st.State, st.Counts)
	}

	// A new target starts a new rollout with a new canary.
	pinnedSettings(s, "1.0.5")
	clock.add(time.Hour)
	b.touch(clock.t)
	s.Tick(ctx)
	if got := b.takeScheduled(); len(got) == 0 || len(got) > 30 {
		t.Errorf("new canary of %d", len(got))
	}
	if st := s.Status(); st.Target != "1.0.5" || st.Phase != PhaseCanary {
		t.Errorf("status %+v", st)
	}
}

func TestCanaryFailurePausesAndRetries(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	b := &fakeBackend{clients: fleet(50, 0, clock.t), flows: map[string]flowResult{}}
	s := newTestService(t, b, clock)
	pinnedSettings(s, "1.0.4")
	ctx := context.Background()

	s.Tick(ctx)
	canary := b.takeScheduled()
	if len(canary) == 0 {
		t.Fatal("no canary")
	}
	// Every canary collection fails.
	for i := 1; i <= b.n; i++ {
		b.flows[fmt.Sprintf("F.%d", i)] = flowResult{State: "error", Status: "Refusing: signature untrusted"}
	}
	clock.add(25 * time.Hour)
	b.touch(clock.t)
	s.Tick(ctx)
	st := s.Status()
	if st.Phase != PhasePaused || st.State != "paused" || st.PausedReason == "" {
		t.Fatalf("not paused: %+v", st)
	}
	if got := b.takeScheduled(); len(got) != 0 {
		t.Errorf("scheduled %d while paused", len(got))
	}

	// Resume sends it to everyone else; the failed canary agents get
	// their next attempt when it is due.
	if _, err := s.Resume(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	b.flows = map[string]flowResult{}
	s.Tick(ctx)
	if got := b.takeScheduled(); len(got) != 50-len(canary) {
		t.Errorf("after resume scheduled %d, want %d", len(got), 50-len(canary))
	}
	clock.add(retryAfter)
	b.touch(clock.t)
	s.Tick(ctx)
	if got := b.takeScheduled(); len(got) != len(canary) {
		t.Errorf("retries scheduled %d, want %d", len(got), len(canary))
	}
}

func TestAttemptsThenFailed(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	b := &fakeBackend{clients: fleet(1, 0, clock.t), flows: map[string]flowResult{}}
	s := newTestService(t, b, clock)
	pinnedSettings(s, "1.0.4")
	s.settings.CanaryPercent = 0
	ctx := context.Background()

	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		s.Tick(ctx)
		if got := b.takeScheduled(); len(got) != 1 {
			t.Fatalf("attempt %d: scheduled %v", attempt, got)
		}
		// The collection finished but the agent came back on the old
		// version (rolled back).
		b.flows[fmt.Sprintf("F.%d", b.n)] = flowResult{State: "finished"}
		clock.add(time.Hour)
		b.touch(clock.t)
		s.Tick(ctx)
		if got := b.takeScheduled(); len(got) != 0 {
			t.Fatalf("attempt %d: rescheduled immediately", attempt)
		}
		clock.add(retryAfter)
		b.touch(clock.t)
	}
	s.Tick(ctx)
	st := s.Status()
	if st.Counts.Failed != 1 || len(st.Failed) != 1 || st.Failed[0].Attempts != MaxAttempts {
		t.Fatalf("status %+v", st)
	}
	if got := b.takeScheduled(); len(got) != 0 {
		t.Errorf("failed agent rescheduled: %v", got)
	}

	if _, err := s.RetryFailed(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	s.Tick(ctx)
	if got := b.takeScheduled(); len(got) != 1 {
		t.Errorf("retry scheduled %v", got)
	}
}

func TestSkipsExcludedOfflineAndSmallFleetCanary(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	clients := fleet(3, 0, clock.t)
	clients[0].Excluded = true
	clients[1].LastSeen = clock.t.Add(-2 * time.Hour)
	b := &fakeBackend{clients: clients, flows: map[string]flowResult{}}
	s := newTestService(t, b, clock)
	pinnedSettings(s, "1.0.4")
	s.Tick(context.Background())

	// Only C.w002 is eligible, and a fleet this small still gets a canary.
	got := b.takeScheduled()
	if len(got) != 1 || got[0] != "C.w002" {
		t.Fatalf("scheduled %v", got)
	}
	st := s.Status()
	if st.Counts.Excluded != 1 || st.Counts.Offline != 1 || st.Counts.Upgrading != 1 {
		t.Errorf("counts %+v", st.Counts)
	}
}

func TestNoDowngradeUnlessPinned(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := clientView{OrgId: "root", ClientId: "C.1", OS: "windows",
		Name: "Atlantiraptor", Version: "1.0.6", LastSeen: now}
	r := newRollout("1.0.5", now, 0)
	res := r.tick(tickInput{Now: now, Settings: Settings{Enabled: true}, Clients: []clientView{c}})
	if len(res.Schedule) != 0 || res.Counts.Newer != 1 || res.Counts.UpToDate != 1 {
		t.Errorf("unpinned: %+v", res)
	}
	r = newRollout("1.0.5", now, 0)
	res = r.tick(tickInput{Now: now, Settings: Settings{Enabled: true, PinnedVersion: "1.0.5"},
		Clients: []clientView{c}})
	if len(res.Schedule) != 1 {
		t.Errorf("pinned: %+v", res)
	}
}

func TestDisabledAndDevelopmentServer(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	b := &fakeBackend{clients: fleet(5, 0, clock.t)}
	s := newTestService(t, b, clock)

	// Tests run as a development build: no target without a pin.
	s.Tick(context.Background())
	if st := s.Status(); st.State != "idle" || st.Reason == "" || len(b.takeScheduled()) != 0 {
		t.Errorf("dev build: %+v", st)
	}

	pinnedSettings(s, "1.0.4")
	s.settings.Enabled = false
	s.Tick(context.Background())
	if st := s.Status(); st.State != "disabled" || len(b.takeScheduled()) != 0 {
		t.Errorf("disabled: %+v", st)
	}

	t.Setenv(DisableEnv, "1")
	s.settings.Enabled = true
	s.Tick(context.Background())
	if st := s.Status(); st.State != "disabled" || !st.DisabledByEnv {
		t.Errorf("env: %+v", st)
	}
}

func TestBinaryFailureStopsRollout(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	b := &fakeBackend{clients: fleet(5, 0, clock.t),
		prepErr: errors.New("signed by \"CN=Someone\", not Atlant Security EOOD")}
	s := newTestService(t, b, clock)
	pinnedSettings(s, "1.0.4")
	s.Tick(context.Background())
	st := s.Status()
	if st.State != "error" || st.LastError == "" || len(b.takeScheduled()) != 0 {
		t.Errorf("status %+v", st)
	}
}

func TestSettingsValidateAndPersist(t *testing.T) {
	for _, bad := range []Settings{
		{PinnedVersion: "latest"}, {PinnedVersion: "1.0"},
		{CanaryPercent: -1}, {CanaryPercent: 101},
		{CanaryHours: MaxCanaryHours + 1},
	} {
		if _, err := bad.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}

	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	b := &fakeBackend{}
	s := newTestService(t, b, clock)
	_, err := s.SetSettings(context.Background(), Settings{
		Enabled: false, PinnedVersion: "v1.2.3", CanaryPercent: 25, CanaryHours: 6,
		ExcludeLabel: " frozen "}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	s2 := newService(nil, b)
	s2.state_path = s.state_path
	s2.load()
	got := s2.settings
	if got.Enabled || got.PinnedVersion != "1.2.3" || got.CanaryPercent != 25 ||
		got.CanaryHours != 6 || got.ExcludeLabel != "frozen" || got.UpdatedBy != "admin" {
		t.Errorf("reloaded %+v", got)
	}
	if len(b.audits) != 1 || b.audits[0] != "agent_update_settings" {
		t.Errorf("audits %v", b.audits)
	}
}
