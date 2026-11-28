package usermessages

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func unix(s string) int64 {
	t, _ := time.Parse(time.RFC3339, s)
	return t.Unix()
}

func row(ts, from, msg string) *Row {
	return &Row{
		Timestamp: json.RawMessage(`"` + ts + `"`),
		From:      from,
		Message:   json.RawMessage(msg),
	}
}

const advisory = `{"title":"CVE-2026-132797 Velociraptor Child orgs can use server artifacts to escalate privilege","link":"https://docs.velociraptor.app/announcements/advisories/cve-2026-132797/","date":"2026-11-27T00:00:00Z"}`

func TestParseAdvisory(t *testing.T) {
	m := Parse(row("2026-11-28T03:27:14Z", "VelociraptorServer", advisory))
	assert.Equal(t, "CVE-2026-132797 Velociraptor Child orgs can use server artifacts to escalate privilege", m.Title)
	assert.Equal(t, "https://docs.velociraptor.app/announcements/advisories/cve-2026-132797/", m.Link)
	assert.Equal(t, "docs.velociraptor.app", m.LinkHost)
	assert.Equal(t, []string{"CVE-2026-132797"}, m.CVEs)
	assert.Equal(t, CategorySecurity, m.Category)
	assert.Equal(t, SeverityCritical, m.Severity) // "privilege escalation" wording
	assert.False(t, m.FromUser)
	assert.Equal(t, unix("2026-11-28T03:27:14Z"), m.FirstSeen)
	assert.Equal(t, unix("2026-11-27T00:00:00Z"), m.Published)
	assert.Empty(t, m.Fields)
}

func TestUnsafeLinksAreNotClickable(t *testing.T) {
	for _, link := range []string{
		"javascript:alert(1)", "data:text/html,x", "//evil.example/x",
		"https://user:pw@evil.example/", "file:///etc/passwd", "not a url",
	} {
		b, _ := json.Marshal(map[string]string{"title": "x", "link": link})
		m := Parse(row("2026-11-28T03:27:14Z", "mallory", string(b)))
		assert.Empty(t, m.Link, link)
		// Still visible as text.
		assert.Equal(t, "link", m.Fields[0].Key, link)
		assert.Equal(t, link, m.Fields[0].Value)
	}
}

func TestUserMessages(t *testing.T) {
	m := Parse(row("2026-11-28T03:27:14Z", "alice", `"Please check host DC01 before noon"`))
	assert.Equal(t, "Please check host DC01 before noon", m.Title)
	assert.Equal(t, CategoryMessage, m.Category)
	assert.Equal(t, SeverityInfo, m.Severity)
	assert.True(t, m.FromUser)

	m = Parse(row("2026-11-28T03:27:14Z", "alice", `{"hunt":"H.123","note":"done"}`))
	assert.Equal(t, "hunt: H.123", m.Title)
	assert.Len(t, m.Fields, 2)

	m = Parse(row("2026-11-28T03:27:14Z", "alice", `{"title":"Disk full","severity":"High","Details":"C: 99%"}`))
	assert.Equal(t, SeverityCritical, m.Severity)
	assert.Equal(t, "C: 99%", m.Summary)
}

func TestBuildGroupsAndMarks(t *testing.T) {
	other := `{"title":"Velociraptor 0.76 released","link":"https://docs.velociraptor.app/blog/2026/v076/","date":"2026-11-20T00:00:00Z"}`
	rows := []*Row{
		row("2026-11-28T03:27:14Z", "VelociraptorServer", advisory),
		row("2026-11-28T03:27:14Z", "VelociraptorServer", advisory),
		row("2026-11-28T03:27:15Z", "VelociraptorServer", advisory),
		row("2026-11-27T01:00:00Z", "VelociraptorServer", other),
	}

	s := Build(rows, nil, false)
	assert.Equal(t, 2, s.Total)
	assert.Equal(t, 2, s.Unread)
	assert.Equal(t, 3, s.Items[0].Count)
	assert.Equal(t, unix("2026-11-28T03:27:14Z"), s.Items[0].FirstSeen)
	assert.Equal(t, unix("2026-11-28T03:27:15Z"), s.Items[0].LastSeen)
	assert.Equal(t, CategoryAnnouncement, s.Items[1].Category)

	T := unix("2026-11-28T03:27:15Z")
	adv := s.Items[0].ID
	blog := s.Items[1].ID

	// Read one, dismiss the other.
	s = Build(rows, []*Mark{
		{Time: T+100, Action: ActionRead, ID: adv},
		{Time: T+100, Action: ActionDismiss, ID: blog},
	}, false)
	assert.Equal(t, 1, s.Total)
	assert.Equal(t, 0, s.Unread)
	assert.Equal(t, 1, s.Dismissed)
	assert.Len(t, s.Items, 1)

	s = Build(rows, []*Mark{
		{Time: T+100, Action: ActionDismiss, ID: blog},
		{Time: T+200, Action: ActionRestore, ID: blog},
	}, false)
	assert.Equal(t, 0, s.Dismissed)

	// Read all, then the advisory arrives again later: unread again.
	later := append(rows, row("2026-11-29T00:00:00Z", "VelociraptorServer", advisory))
	s = Build(later, []*Mark{{Time: T+100, Action: ActionRead, ID: AllIDs}}, false)
	assert.Equal(t, 1, s.Unread)
	assert.Equal(t, adv, s.Items[0].ID)
	assert.False(t, s.Items[0].Read)
	assert.True(t, s.Items[1].Read)

	// Unread after read all.
	s = Build(rows, []*Mark{
		{Time: T+100, Action: ActionRead, ID: AllIDs},
		{Time: T+101, Action: ActionUnread, ID: blog},
	}, false)
	assert.Equal(t, 1, s.Unread)

	// Dismissed items can still be listed.
	s = Build(rows, []*Mark{{Time: T+100, Action: ActionDismiss, ID: AllIDs}}, true)
	assert.Len(t, s.Items, 2)
	assert.Equal(t, 0, s.Total)
	assert.True(t, s.Items[0].Dismissed)
}

func TestSameLinkFromDifferentSendersGroups(t *testing.T) {
	rows := []*Row{
		row("2026-11-28T03:27:14Z", "VelociraptorServer", advisory),
		row("2026-11-28T03:27:14Z", "AtlantiraptorServer", advisory),
	}
	assert.Len(t, Build(rows, nil, false).Items, 1)
}

// The advisory feed of our own docs site: one page, one anchor per CVE.
func TestAnchorLinksAreDistinct(t *testing.T) {
	a := `{"title":"CVE-2026-130319 Multiple VQL plugins missing permission enforcement","link":"https://atlantsecurity.github.io/atlantiraptor/security/advisories/#cve-2026-130319","date":"2026-11-27T00:00:00Z"}`
	b := `{"title":"CVE-2026-129966 Server panic (DoS) via crafted request","link":"https://atlantsecurity.github.io/atlantiraptor/security/advisories/#cve-2026-129966","date":"2026-11-27T00:00:00Z"}`
	s := Build([]*Row{
		row("2026-11-28T03:27:14Z", "VelociraptorServer", a),
		row("2026-11-28T03:27:14Z", "VelociraptorServer", b),
		row("2026-11-28T03:27:14Z", "VelociraptorServer", a),
	}, nil, false)
	assert.Len(t, s.Items, 2)
	for _, m := range s.Items {
		assert.Equal(t, CategorySecurity, m.Category)
		assert.Contains(t, m.Link, "#cve-")
	}
}
