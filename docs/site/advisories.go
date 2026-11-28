package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// The security advisories page and its RSS feed are generated from
// docs/site/advisories.yaml. Servers poll the feed
// (Server.Monitoring.RSSFeeds) and show new items to their users.
const (
	advisoriesData = "docs/site/advisories.yaml"
	advisoriesPage = "security/advisories"
	advisoriesFeed = advisoriesPage + "/index.xml"
)

type Advisory struct {
	ID            string  `yaml:"id"`
	Title         string  `yaml:"title"`
	Date          string  `yaml:"date"`
	Severity      string  `yaml:"severity"`
	Score         float64 `yaml:"score"`
	FixedIn       string  `yaml:"fixed_in"`
	UpstreamFixed string  `yaml:"upstream_fixed"`
	Summary       string  `yaml:"summary"`
}

func loadAdvisories(root string) ([]Advisory, error) {
	data, err := os.ReadFile(filepath.Join(root, advisoriesData))
	if err != nil {
		return nil, err
	}
	var file struct {
		Advisories []Advisory `yaml:"advisories"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", advisoriesData, err)
	}
	seen := make(map[string]bool)
	for _, a := range file.Advisories {
		if a.ID == "" || a.Title == "" || a.FixedIn == "" {
			return nil, fmt.Errorf("%s: %q needs id, title and fixed_in", advisoriesData, a.ID)
		}
		if seen[a.ID] {
			return nil, fmt.Errorf("%s: duplicate id %q", advisoriesData, a.ID)
		}
		seen[a.ID] = true
		if _, err := time.Parse("2006-01-02", a.Date); err != nil {
			return nil, fmt.Errorf("%s: %s: date must be YYYY-MM-DD", advisoriesData, a.ID)
		}
	}
	return file.Advisories, nil
}

func advisoryAnchor(a Advisory) string {
	return strings.ToLower(a.ID)
}

// generateAdvisories appends the advisory list to the hand-written
// security/advisories page and writes the RSS feed next to it.
func (self *Site) generateAdvisories() error {
	page, pres := self.byPath[advisoriesPage]
	if !pres {
		return fmt.Errorf("nav.yaml must list %s", advisoriesPage)
	}

	advisories, err := loadAdvisories(self.Opts.Root)
	if err != nil {
		return err
	}

	md := &strings.Builder{}
	md.WriteString(page.Markdown)
	md.WriteString("\n## All advisories {#all}\n\n| Advisory | Severity | Published | Fixed in |\n|---|---|---|---|\n")
	for _, a := range advisories {
		fmt.Fprintf(md, "| [%s](#%s) %s | %s | %s | %s |\n",
			a.ID, advisoryAnchor(a), mdEscapeCell(a.Title),
			severityText(a), a.Date, a.FixedIn)
	}
	md.WriteString("\n")

	for _, a := range advisories {
		fmt.Fprintf(md, "### %s: %s {#%s}\n\n", a.ID, a.Title, advisoryAnchor(a))
		fmt.Fprintf(md, "**Severity:** %s · **Published:** %s · **Fixed in:** Atlantiraptor %s",
			severityText(a), a.Date, a.FixedIn)
		if a.UpstreamFixed != "" {
			fmt.Fprintf(md, " (upstream Velociraptor %s)", a.UpstreamFixed)
		}
		md.WriteString("\n\n")
		if a.Summary != "" {
			md.WriteString(strings.TrimSpace(a.Summary) + "\n\n")
		}
	}
	page.Markdown = md.String()

	feed, err := self.advisoriesRSS(page, advisories)
	if err != nil {
		return err
	}
	self.files[advisoriesFeed] = feed
	return nil
}

func severityText(a Advisory) string {
	if a.Severity == "" {
		return "-"
	}
	if a.Score > 0 {
		return fmt.Sprintf("%s (%.1f)", a.Severity, a.Score)
	}
	return a.Severity
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	PubDate     string `xml:"pubDate"`
	Description string `xml:"description"`
}

type rssChannel struct {
	Title         string    `xml:"title"`
	Link          string    `xml:"link"`
	Description   string    `xml:"description"`
	Language      string    `xml:"language"`
	LastBuildDate string    `xml:"lastBuildDate,omitempty"`
	Items         []rssItem `xml:"item"`
}

type rssDoc struct {
	XMLName xml.Name   `xml:"rss"`
	Version string     `xml:"version,attr"`
	Channel rssChannel `xml:"channel"`
}

// advisoriesRSS renders the feed. The guid is the advisory's page
// link, which never changes, so servers notify about each advisory
// once.
func (self *Site) advisoriesRSS(page *Page, advisories []Advisory) ([]byte, error) {
	pageURL := self.PageURL(page.Path)
	doc := rssDoc{
		Version: "2.0",
		Channel: rssChannel{
			Title:       "Atlantiraptor security advisories",
			Link:        pageURL,
			Description: "Security advisories for Atlantiraptor by Atlant Security.",
			Language:    "en",
		},
	}
	var latest time.Time
	for _, a := range advisories {
		date, _ := time.Parse("2006-01-02", a.Date)
		if date.After(latest) {
			latest = date
		}
		link := pageURL + "#" + advisoryAnchor(a)
		desc := fmt.Sprintf("Severity: %s. Fixed in Atlantiraptor %s.", severityText(a), a.FixedIn)
		if a.Summary != "" {
			desc += " " + strings.TrimSpace(a.Summary)
		}
		doc.Channel.Items = append(doc.Channel.Items, rssItem{
			Title:       a.ID + " " + a.Title,
			Link:        link,
			GUID:        link,
			PubDate:     date.UTC().Format(time.RFC1123Z),
			Description: desc,
		})
	}
	if !latest.IsZero() {
		doc.Channel.LastBuildDate = latest.UTC().Format(time.RFC1123Z)
	}

	buf := &bytes.Buffer{}
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(buf)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	buf.WriteString("\n")
	return buf.Bytes(), nil
}
