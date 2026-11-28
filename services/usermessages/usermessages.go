// Package usermessages turns the raw console notifications of a user
// (rows of Timestamp, From, Message written by user_message()) into
// something a person can read and act on.
//
// The notifications file stays the append-only source of truth, so
// everything that writes messages (user_message(), the RSS monitor,
// third party artifacts) keeps working. On top of it:
//
//   - Identical messages are grouped: the same advisory delivered once
//     per org, or re-sent by a restarted monitor, shows once with a
//     count.
//   - Each group gets a readable title, summary, severity, category,
//     the CVE ids it mentions and a link that is safe to open (http and
//     https only: any user can message any other user, so a link is
//     untrusted input).
//   - Read and dismissed marks are kept per user in a second append-only
//     log (NotificationState). A mark covers what was received up to the
//     time it was made, so a message that arrives again later shows as
//     new again.
package usermessages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store"
	vjson "www.velocidex.com/golang/velociraptor/json"
	"www.velocidex.com/golang/velociraptor/paths"
	"www.velocidex.com/golang/velociraptor/paths/artifacts"
	"www.velocidex.com/golang/velociraptor/result_sets"
	"www.velocidex.com/golang/velociraptor/services"
	"www.velocidex.com/golang/velociraptor/utils"
)

const (
	// Only the most recent rows are considered. A user with more than
	// this many notifications has stopped reading them anyway.
	MaxRows = 5000

	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"

	CategorySecurity     = "security"
	CategoryAnnouncement = "announcement"
	CategoryMessage      = "message"

	ActionRead    = "read"
	ActionUnread  = "unread"
	ActionDismiss = "dismiss"
	ActionRestore = "restore"

	// A mark on this id applies to every message received before it.
	AllIDs = "*"
)

// The names the server uses when it sends a message itself (server
// artifacts run as the server's principal).
var serverSenders = map[string]bool{
	"":                    true,
	"VelociraptorServer":  true,
	"AtlantiraptorServer": true,
}

var (
	cveRegex       = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)
	criticalRegex  = regexp.MustCompile(`(?i)(\bcritical\b|remote code|\brce\b|arbitrary code|escalat|actively exploited|authentication bypass)`)
	warningRegex   = regexp.MustCompile(`(?i)\b(warning|vulnerab|bypass|denial of service|dos|traversal|leak|expire|failed|error)`)
	advisoryRegex  = regexp.MustCompile(`(?i)/(advisories|security|cve)/`)
	titleFields    = []string{"title", "subject", "name", "message", "text", "summary", "description", "body"}
	summaryFields  = []string{"summary", "description", "body", "text", "message", "content", "details"}
	linkFields     = []string{"link", "url", "href"}
	dateFields     = []string{"date", "pubDate", "published", "time", "timestamp"}
	severityFields = []string{"severity", "level", "priority"}
)

// A raw row of the notifications result set.
type Row struct {
	Timestamp json.RawMessage `json:"Timestamp"`
	From      string          `json:"From"`
	Message   json.RawMessage `json:"Message"`
}

// A read or dismissed mark (a row of the NotificationState log).
type Mark struct {
	Time   int64  `json:"time"`
	Action string `json:"action"`
	ID     string `json:"id"`
}

type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// One message as the console shows it: identical deliveries grouped.
type Message struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Summary   string   `json:"summary,omitempty"`
	Link      string   `json:"link,omitempty"`
	LinkHost  string   `json:"link_host,omitempty"`
	Published int64    `json:"published,omitempty"`
	From      string   `json:"from"`
	FromUser  bool     `json:"from_user"`
	Severity  string   `json:"severity"`
	Category  string   `json:"category"`
	CVEs      []string `json:"cves,omitempty"`
	Fields    []Field  `json:"fields,omitempty"`
	Raw       string   `json:"raw"`

	FirstSeen int64 `json:"first_seen"`
	LastSeen  int64 `json:"last_seen"`
	Count     int   `json:"count"`

	Read      bool `json:"read"`
	Dismissed bool `json:"dismissed"`
}

type Summary struct {
	Items     []*Message `json:"items"`
	Unread    int        `json:"unread"`
	Total     int        `json:"total"`
	Dismissed int        `json:"dismissed"`
}

func parseTime(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return parseTimeString(s)
	}
	var n float64
	if json.Unmarshal(raw, &n) == nil {
		return normalizeEpoch(n)
	}
	return 0
}

func normalizeEpoch(n float64) int64 {
	switch {
	case n > 1e17:
		return int64(n / 1e9)
	case n > 1e14:
		return int64(n / 1e6)
	case n > 1e11:
		return int64(n / 1e3)
	}
	return int64(n)
}

func parseTimeString(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC1123Z, time.RFC1123,
		"2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Unix()
		}
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return normalizeEpoch(n)
	}
	return 0
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	case time.Time:
		return t.UTC().Format(time.RFC3339)
	case *time.Time:
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// SafeLink returns the link if it is an absolute http(s) URL.
func SafeLink(s string) (link, host string) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil {
		return "", ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.String(), u.Hostname()
	}
	return "", ""
}

func firstField(m *ordereddict.Dict, used map[string]bool, names []string) (string, string) {
	for _, name := range names {
		if used[name] {
			continue
		}
		for _, k := range m.Keys() {
			if !strings.EqualFold(k, name) || used[k] {
				continue
			}
			v, _ := m.Get(k)
			s := strings.TrimSpace(stringify(v))
			if s != "" {
				return k, s
			}
		}
	}
	return "", ""
}

func shortHash(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:8])
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) > max {
		r := []rune(s)
		s = strings.TrimSpace(string(r[:max-1])) + "…"
	}
	return s
}

// Parse turns a row into a message (count 1, no marks applied).
func Parse(row *Row) *Message {
	ts := parseTime(row.Timestamp)
	from := strings.TrimSpace(row.From)
	msg := &Message{
		From:      from,
		FromUser:  !serverSenders[from],
		FirstSeen: ts,
		LastSeen:  ts,
		Count:     1,
	}

	dict := ordereddict.NewDict()
	raw := strings.TrimSpace(string(row.Message))
	if strings.HasPrefix(raw, "{") && dict.UnmarshalJSON(row.Message) == nil {
		if pretty, err := json.MarshalIndent(dict, "", "  "); err == nil {
			msg.Raw = string(pretty)
		}
	} else {
		// A plain string or other value.
		var s string
		if json.Unmarshal(row.Message, &s) != nil {
			s = raw
		}
		dict.Set("message", s)
		msg.Raw = s
	}

	used := map[string]bool{}
	if k, v := firstField(dict, used, linkFields); k != "" {
		used[k] = true
		msg.Link, msg.LinkHost = SafeLink(v)
		if msg.Link == "" {
			// Not a web link: keep it visible as text, never clickable.
			used[k] = false
		}
	}
	if k, v := firstField(dict, used, dateFields); k != "" {
		if t := parseTimeString(v); t > 0 {
			used[k] = true
			msg.Published = t
		}
	}
	if k, v := firstField(dict, used, titleFields); k != "" {
		used[k] = true
		msg.Title = oneLine(v, 300)
		// A long free text message: title is its start, the summary
		// keeps all of it.
		if len([]rune(strings.TrimSpace(v))) > 300 || strings.Contains(strings.TrimSpace(v), "\n") {
			msg.Summary = strings.TrimSpace(v)
		}
	}
	if msg.Summary == "" {
		if k, v := firstField(dict, used, summaryFields); k != "" {
			used[k] = true
			msg.Summary = v
		}
	}
	severity := ""
	if k, v := firstField(dict, used, severityFields); k != "" {
		used[k] = true
		severity = normalizeSeverity(v)
	}
	category := ""
	if k, v := firstField(dict, used, []string{"category", "type"}); k != "" {
		switch strings.ToLower(v) {
		case CategorySecurity, CategoryAnnouncement, CategoryMessage:
			used[k] = true
			category = strings.ToLower(v)
		}
	}

	for _, k := range dict.Keys() {
		if used[k] {
			continue
		}
		v, _ := dict.Get(k)
		s := stringify(v)
		if strings.TrimSpace(s) == "" {
			continue
		}
		msg.Fields = append(msg.Fields, Field{Key: k, Value: s})
	}

	if msg.Title == "" {
		switch {
		case len(msg.Fields) > 0:
			msg.Title = oneLine(msg.Fields[0].Key+": "+msg.Fields[0].Value, 300)
		case msg.Link != "":
			msg.Title = msg.Link
		case msg.FromUser:
			msg.Title = "Message from " + from
		default:
			msg.Title = "Server notification"
		}
	}

	seen := map[string]bool{}
	for _, c := range cveRegex.FindAllString(msg.Title+" "+msg.Summary, -1) {
		c = strings.ToUpper(c)
		if !seen[c] {
			seen[c] = true
			msg.CVEs = append(msg.CVEs, c)
		}
	}

	if category == "" {
		switch {
		case len(msg.CVEs) > 0 || advisoryRegex.MatchString(msg.Link) ||
			strings.Contains(strings.ToLower(msg.Title), "advisory"):
			category = CategorySecurity
		case msg.FromUser:
			category = CategoryMessage
		default:
			category = CategoryAnnouncement
		}
	}
	msg.Category = category

	if severity == "" {
		text := msg.Title + " " + msg.Summary
		switch {
		case category == CategorySecurity && criticalRegex.MatchString(text):
			severity = SeverityCritical
		case category == CategorySecurity:
			severity = SeverityWarning
		case warningRegex.MatchString(text):
			severity = SeverityWarning
		default:
			severity = SeverityInfo
		}
	}
	msg.Severity = severity

	// The identity of a message for grouping. A link names a page, so
	// the same link is the same message whoever sent it and whatever
	// the title says now; otherwise the sender and the full content.
	if msg.Link != "" {
		msg.ID = shortHash("link", strings.TrimRight(msg.Link, "/"))
	} else {
		msg.ID = shortHash("content", from, msg.Raw)
	}
	return msg
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "high", "error", "severe", "urgent", "p1", "1":
		return SeverityCritical
	case "warning", "warn", "medium", "moderate", "p2", "2":
		return SeverityWarning
	case "":
		return ""
	}
	return SeverityInfo
}

var severityRank = map[string]int{SeverityCritical: 2, SeverityWarning: 1, SeverityInfo: 0}

// Build groups the rows and applies the marks. Items are newest first.
func Build(rows []*Row, marks []*Mark, include_dismissed bool) *Summary {
	groups := map[string]*Message{}
	order := []*Message{}
	for _, row := range rows {
		m := Parse(row)
		g, pres := groups[m.ID]
		if !pres {
			groups[m.ID] = m
			order = append(order, m)
			continue
		}
		g.Count++
		if m.FirstSeen > 0 && (g.FirstSeen == 0 || m.FirstSeen < g.FirstSeen) {
			g.FirstSeen = m.FirstSeen
		}
		if m.LastSeen >= g.LastSeen {
			// Keep the latest wording (titles get corrected upstream).
			first := g.FirstSeen
			count := g.Count
			*g = *m
			g.FirstSeen = first
			g.Count = count
		}
		if severityRank[m.Severity] > severityRank[g.Severity] {
			g.Severity = m.Severity
		}
	}

	// Latest mark time per id and kind.
	read_at := map[string]int64{}
	dismissed_at := map[string]int64{}
	for _, mark := range marks {
		switch mark.Action {
		case ActionRead:
			read_at[mark.ID] = mark.Time
		case ActionUnread:
			read_at[mark.ID] = -1
		case ActionDismiss:
			dismissed_at[mark.ID] = mark.Time
		case ActionRestore:
			dismissed_at[mark.ID] = -1
		}
	}
	applies := func(at map[string]int64, m *Message) bool {
		if t, pres := at[m.ID]; pres {
			if t < 0 {
				return false
			}
			if m.LastSeen <= t {
				return true
			}
		}
		t, pres := at[AllIDs]
		return pres && t >= 0 && m.LastSeen <= t
	}

	result := &Summary{Items: []*Message{}}
	for _, m := range order {
		// An explicit unread or restore beats an earlier "all" mark.
		m.Read = applies(read_at, m)
		if t, pres := read_at[m.ID]; pres && t < 0 {
			m.Read = false
		}
		m.Dismissed = applies(dismissed_at, m)
		if t, pres := dismissed_at[m.ID]; pres && t < 0 {
			m.Dismissed = false
		}
		if m.Dismissed {
			result.Dismissed++
			if !include_dismissed {
				continue
			}
		} else {
			result.Total++
			if !m.Read {
				result.Unread++
			}
		}
		result.Items = append(result.Items, m)
	}

	sort.SliceStable(result.Items, func(i, j int) bool {
		return result.Items[i].LastSeen > result.Items[j].LastSeen
	})
	return result
}

// Messages live in the root org: users are global.
func rootConfig() (*config_proto.Config, error) {
	org_manager, err := services.GetOrgManager()
	if err != nil {
		return nil, err
	}
	return org_manager.GetOrgConfig(services.ROOT_ORG_ID)
}

func readRows(ctx context.Context, config_obj *config_proto.Config,
	username string) ([]*Row, error) {
	file_store_factory := file_store.GetFileStore(config_obj)
	reader, err := result_sets.NewResultSetReader(file_store_factory,
		paths.NewUserPathManager(username).Notifications())
	if err != nil {
		return nil, nil
	}
	defer reader.Close()

	if total := reader.TotalRows(); total > MaxRows {
		if err := reader.SeekToRow(total - MaxRows); err != nil {
			return nil, err
		}
	}

	blobs, err := reader.JSON(ctx)
	if err != nil {
		return nil, nil
	}
	rows := []*Row{}
	for blob := range blobs {
		row := &Row{}
		if json.Unmarshal(blob, row) == nil {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func readMarks(ctx context.Context, config_obj *config_proto.Config,
	username string) []*Mark {
	file_store_factory := file_store.GetFileStore(config_obj)
	reader, err := result_sets.NewResultSetReader(file_store_factory,
		paths.NewUserPathManager(username).NotificationState())
	if err != nil {
		return nil
	}
	defer reader.Close()

	blobs, err := reader.JSON(ctx)
	if err != nil {
		return nil
	}
	marks := []*Mark{}
	for blob := range blobs {
		mark := &Mark{}
		if json.Unmarshal(blob, mark) == nil && mark.ID != "" {
			marks = append(marks, mark)
		}
	}
	return marks
}

// List returns the user's messages.
func List(ctx context.Context, username string, include_dismissed bool) (*Summary, error) {
	config_obj, err := rootConfig()
	if err != nil {
		return nil, err
	}
	rows, err := readRows(ctx, config_obj, username)
	if err != nil {
		return nil, err
	}
	return Build(rows, readMarks(ctx, config_obj, username), include_dismissed), nil
}

// UnreadCount is the number for the bell in the top bar.
func UnreadCount(ctx context.Context, username string) int {
	summary, err := List(ctx, username, false)
	if err != nil {
		return 0
	}
	return summary.Unread
}

var validID = regexp.MustCompile(`^([0-9a-f]{16}|\*)$`)

// Mark records read, unread, dismiss or restore for the ids (or AllIDs).
func MarkMessages(ctx context.Context, username, action string, ids []string) error {
	switch action {
	case ActionRead, ActionUnread, ActionDismiss, ActionRestore:
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	if len(ids) == 0 {
		return errors.New("no messages given")
	}
	if len(ids) > MaxRows {
		return errors.New("too many messages")
	}

	config_obj, err := rootConfig()
	if err != nil {
		return err
	}
	journal, err := services.GetJournal(config_obj)
	if err != nil {
		return err
	}

	now := utils.GetTime().Now().Unix()
	rows := make([]*ordereddict.Dict, 0, len(ids))
	for _, id := range ids {
		if !validID.MatchString(id) {
			return fmt.Errorf("invalid message id %q", id)
		}
		rows = append(rows, ordereddict.NewDict().
			Set("time", now).
			Set("action", action).
			Set("id", id))
	}

	err = journal.AppendToResultSet(config_obj,
		paths.NewUserPathManager(username).NotificationState(),
		rows, artifacts.USER_MANAGER)
	if err != nil {
		return err
	}
	return compactIfLarge(ctx, config_obj, username)
}

// Clear removes every message and mark of the user. (Not through
// SetUserOptions: that would also reset the user's other options.)
func Clear(ctx context.Context, username string) error {
	config_obj, err := rootConfig()
	if err != nil {
		return err
	}
	file_store_factory := file_store.GetFileStore(config_obj)
	writer, err := result_sets.NewResultSetWriter(file_store_factory,
		paths.NewUserPathManager(username).Notifications(),
		vjson.DefaultEncOpts(), utils.SyncCompleter, result_sets.TruncateMode)
	if err != nil {
		return err
	}
	writer.Close()
	return rewriteMarks(config_obj, username, nil)
}

// The marks log only grows; once it is large, rewrite it keeping the
// latest mark per id and kind.
func compactIfLarge(ctx context.Context, config_obj *config_proto.Config, username string) error {
	marks := readMarks(ctx, config_obj, username)
	if len(marks) < 4*MaxRows {
		return nil
	}
	latest := map[string]*Mark{}
	keys := []string{}
	for _, m := range marks {
		kind := "read"
		if m.Action == ActionDismiss || m.Action == ActionRestore {
			kind = "dismiss"
		}
		key := kind + "/" + m.ID
		if _, pres := latest[key]; !pres {
			keys = append(keys, key)
		}
		latest[key] = m
	}
	compacted := make([]*Mark, 0, len(keys))
	for _, k := range keys {
		compacted = append(compacted, latest[k])
	}
	return rewriteMarks(config_obj, username, compacted)
}

func rewriteMarks(config_obj *config_proto.Config, username string, marks []*Mark) error {
	file_store_factory := file_store.GetFileStore(config_obj)
	writer, err := result_sets.NewResultSetWriter(file_store_factory,
		paths.NewUserPathManager(username).NotificationState(),
		vjson.DefaultEncOpts(), utils.SyncCompleter, result_sets.TruncateMode)
	if err != nil {
		return err
	}
	defer writer.Close()
	for _, m := range marks {
		writer.Write(ordereddict.NewDict().
			Set("time", m.Time).
			Set("action", m.Action).
			Set("id", m.ID))
	}
	return nil
}
