package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/russross/blackfriday/v2"
	"gopkg.in/yaml.v3"
)

// DefaultSiteURL is where the documentation is published (GitHub
// Pages for this repository). The product links here too; see
// constants.DocsURL.
const DefaultSiteURL = "https://atlantsecurity.github.io/atlantiraptor/"

// RepoURL is used for "edit this page" links and for links to files
// in the repository.
const RepoURL = "https://github.com/atlantsecurity/atlantiraptor"

//go:embed assets
var assetsFS embed.FS

//go:embed templates/page.html
var pageTemplate string

type Options struct {
	Root      string
	Out       string
	URL       string
	CLIBinary string
	DocsIndex string
}

// Page is one HTML page of the site.
type Page struct {
	// Path relative to the site root, without leading or trailing
	// slash. "" is the home page.
	Path        string
	Title       string
	Description string
	Section     string
	// Search tag used by the console's documentation search.
	Tag string
	// Markdown source (after front matter), used for the search indexes.
	Markdown string
	// Rendered body.
	HTML template.HTML
	// Source file relative to the repository root, for "edit" links.
	Source string
	// Pages shown in the sidebar have InNav set.
	InNav bool
	TOC   []TOCEntry
	// Set by the generators for long reference pages.
	NoTOC bool
}

type TOCEntry struct {
	ID, Title string
	Level     int
}

type NavSection struct {
	Title string    `yaml:"title"`
	Pages []NavPage `yaml:"pages"`
}

type NavPage struct {
	Path   string `yaml:"path"`
	Source string `yaml:"source"`
	Title  string `yaml:"title"`
}

type Nav struct {
	Sections []NavSection `yaml:"sections"`
}

type Site struct {
	Opts     Options
	BasePath string
	Nav      Nav
	Pages    []*Page
	byPath   map[string]*Page
	// Repository source file -> site path, used to rewrite links
	// between Markdown files that live outside docs/site/content.
	sourceMap map[string]string
	files     map[string][]byte
}

func Build(opts Options) (*Site, error) {
	if !strings.HasSuffix(opts.URL, "/") {
		opts.URL += "/"
	}
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, err
	}

	site := &Site{
		Opts:      opts,
		BasePath:  u.Path,
		byPath:    make(map[string]*Page),
		sourceMap: make(map[string]string),
		files:     make(map[string][]byte),
	}

	navData, err := os.ReadFile(filepath.Join(opts.Root, "docs/site/nav.yaml"))
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(navData, &site.Nav)
	if err != nil {
		return nil, fmt.Errorf("nav.yaml: %w", err)
	}

	// Hand written pages, in navigation order.
	for _, section := range site.Nav.Sections {
		for _, np := range section.Pages {
			src := np.Source
			if src == "" {
				name := np.Path
				if name == "" {
					name = "index"
				}
				src = "docs/site/content/" + name + ".md"
			}
			site.sourceMap[src] = np.Path
		}
	}

	for si := range site.Nav.Sections {
		section := &site.Nav.Sections[si]
		for pi := range section.Pages {
			np := &section.Pages[pi]
			src := np.Source
			if src == "" {
				name := np.Path
				if name == "" {
					name = "index"
				}
				src = "docs/site/content/" + name + ".md"
			}
			page, err := site.loadMarkdownPage(src, np.Path)
			if err != nil {
				return nil, err
			}
			// A nav title only renames the sidebar link, except for
			// pages taken from elsewhere in the repository.
			if np.Title == "" {
				np.Title = page.Title
			} else if np.Source != "" {
				page.Title = np.Title
			}
			page.Section = section.Title
			page.InNav = true
			page.Tag = "Docs"
			if strings.HasPrefix(np.Path, "kb/") {
				page.Tag = "KB"
			}
			site.addPage(page)
		}
	}

	// Generated reference sections.
	generators := []func() error{
		site.generateVQLReference,
		site.generateArtifactReference,
		site.generateConfigReference,
		site.generateCLIReference,
		site.generateRESTReference,
	}
	for _, g := range generators {
		if err := g(); err != nil {
			return nil, err
		}
	}

	for _, p := range site.Pages {
		if p.HTML == "" {
			p.HTML = site.renderMarkdown(p.Markdown, p.Source)
		}
		if !p.NoTOC {
			p.TOC = extractTOC(string(p.HTML))
		}
	}

	if err := site.write(); err != nil {
		return nil, err
	}
	return site, nil
}

func (self *Site) addPage(p *Page) {
	if _, pres := self.byPath[p.Path]; pres {
		panic("duplicate page " + p.Path)
	}
	self.Pages = append(self.Pages, p)
	self.byPath[p.Path] = p
}

var frontMatterRegex = regexp.MustCompile(`(?s)\A---\n(.*?)\n---\n`)
var firstHeadingRegex = regexp.MustCompile(`(?m)\A\s*# +(.+)\n`)

func (self *Site) loadMarkdownPage(src, sitePath string) (*Page, error) {
	data, err := os.ReadFile(filepath.Join(self.Opts.Root, src))
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	page := &Page{Path: sitePath, Source: src}

	if m := frontMatterRegex.FindStringSubmatch(text); m != nil {
		fm := struct {
			Title       string `yaml:"title"`
			Description string `yaml:"description"`
		}{}
		if err := yaml.Unmarshal([]byte(m[1]), &fm); err != nil {
			return nil, fmt.Errorf("%s: front matter: %w", src, err)
		}
		page.Title = fm.Title
		page.Description = fm.Description
		text = text[len(m[0]):]
	}

	// The page template prints the title, so drop a leading H1.
	if m := firstHeadingRegex.FindStringSubmatch(text); m != nil {
		if page.Title == "" {
			page.Title = strings.TrimSpace(m[1])
		}
		text = text[len(m[0]):]
	}
	if page.Title == "" {
		return nil, fmt.Errorf("%s: no title", src)
	}
	page.Markdown = strings.TrimSpace(text) + "\n"
	return page, nil
}

var (
	hrefRegex    = regexp.MustCompile(`(href|src)="([^"]*)"`)
	calloutRegex = regexp.MustCompile(`<blockquote>\s*<p><strong>(Note|Tip|Warning|Important|Atlantiraptor)(:?)</strong>:?`)
	headingRegex = regexp.MustCompile(`<h([23]) id="([^"]+)">(.*?)</h[23]>`)
	tagRegex     = regexp.MustCompile(`<[^>]+>`)
	figureRegex  = regexp.MustCompile(`<p><img src="([^"]*)" alt="([^"]*)" title="([^"]*)" ?/?></p>`)
)

func (self *Site) renderMarkdown(md, source string) template.HTML {
	out := blackfriday.Run([]byte(md), blackfriday.WithExtensions(
		blackfriday.CommonExtensions|blackfriday.AutoHeadingIDs|
			blackfriday.Footnotes))

	res := hrefRegex.ReplaceAllStringFunc(string(out), func(m string) string {
		sm := hrefRegex.FindStringSubmatch(m)
		return sm[1] + `="` + self.rewriteLink(html.UnescapeString(sm[2]), source) + `"`
	})

	res = calloutRegex.ReplaceAllStringFunc(res, func(m string) string {
		sm := calloutRegex.FindStringSubmatch(m)
		kind := strings.ToLower(sm[1])
		return `<blockquote class="callout callout-` + kind + `"><p><strong>` + sm[1] + `</strong>`
	})

	// A paragraph holding only an image with a title becomes a figure
	// with that title as its caption.
	res = figureRegex.ReplaceAllString(res,
		`<figure><a href="$1"><img loading="lazy" src="$1" alt="$2" /></a><figcaption>$3</figcaption></figure>`)
	res = strings.ReplaceAll(res, "<img src=", `<img loading="lazy" src=`)

	// Tables can be wider than the column on phones.
	res = strings.ReplaceAll(res, "<table>", `<div class="table-wrap"><table>`)
	res = strings.ReplaceAll(res, "</table>", `</table></div>`)
	return template.HTML(res)
}

// rewriteLink turns site-absolute links ("/deployment/server/") into
// links under the site's base path, and relative links to Markdown
// files elsewhere in the repository into site or GitHub links.
func (self *Site) rewriteLink(link, source string) string {
	switch {
	case strings.HasPrefix(link, DefaultSiteURL):
		// Absolute links to the published site (artifact and VQL
		// descriptions use them, since the console shows those too)
		// stay inside this build, so they are checked and work in a
		// local preview.
		return html.EscapeString(self.BasePath + strings.TrimPrefix(link, DefaultSiteURL))

	case link == "" || strings.HasPrefix(link, "#") ||
		strings.Contains(link, "://") || strings.HasPrefix(link, "mailto:") ||
		strings.HasPrefix(link, "//"):
		return html.EscapeString(link)

	case strings.HasPrefix(link, "/"):
		return html.EscapeString(self.BasePath + strings.TrimPrefix(link, "/"))
	}

	// Relative link: resolve against the source file in the repository.
	frag := ""
	if idx := strings.Index(link, "#"); idx >= 0 {
		frag = link[idx:]
		link = link[:idx]
	}
	target := path.Clean(path.Join(path.Dir(source), link))
	if sitePath, pres := self.sourceMap[target]; pres {
		return html.EscapeString(self.pageURLPath(sitePath) + frag)
	}
	return html.EscapeString(RepoURL + "/tree/master/" + target + frag)
}

func (self *Site) pageURLPath(sitePath string) string {
	if sitePath == "" {
		return self.BasePath
	}
	return self.BasePath + sitePath + "/"
}

func (self *Site) PageURL(sitePath string) string {
	if sitePath == "" {
		return self.Opts.URL
	}
	return self.Opts.URL + sitePath + "/"
}

func extractTOC(body string) (res []TOCEntry) {
	for _, m := range headingRegex.FindAllStringSubmatch(body, -1) {
		level := 2
		if m[1] == "3" {
			level = 3
		}
		res = append(res, TOCEntry{
			ID:    m[2],
			Title: html.UnescapeString(tagRegex.ReplaceAllString(m[3], "")),
			Level: level,
		})
	}
	if len(res) < 2 {
		return nil
	}
	return res
}

type navView struct {
	Title  string
	Open   bool
	Groups []navLink
}

type navLink struct {
	Title, URL string
	Current    bool
}

type pageView struct {
	Page        *Page
	Base        string
	SiteURL     string
	Nav         []navView
	Crumbs      []navLink
	Prev, Next  *navLink
	EditURL     string
	Description string
	Year        string
}

func (self *Site) navFor(current *Page) ([]navView, *navLink, *navLink) {
	var res []navView
	var flat []navLink
	var curIdx = -1

	currentNav := current.Path
	// Generated reference pages highlight their section's index.
	for _, prefix := range []string{"reference/vql", "reference/artifacts"} {
		if strings.HasPrefix(current.Path, prefix+"/") {
			currentNav = prefix
		}
	}

	for _, s := range self.navSections() {
		nv := navView{Title: s.Title}
		for _, np := range s.Pages {
			l := navLink{Title: np.Title, URL: self.pageURLPath(np.Path),
				Current: np.Path == currentNav}
			if l.Current {
				nv.Open = true
				curIdx = len(flat)
			}
			nv.Groups = append(nv.Groups, l)
			flat = append(flat, l)
		}
		res = append(res, nv)
	}

	var prev, next *navLink
	if curIdx >= 0 && currentNav == current.Path {
		if curIdx > 0 {
			p := flat[curIdx-1]
			prev = &p
		}
		if curIdx < len(flat)-1 {
			n := flat[curIdx+1]
			next = &n
		}
	}
	return res, prev, next
}

// navSections is the sidebar: the hand-written sections from nav.yaml
// followed by the generated reference section.
func (self *Site) navSections() []NavSection {
	res := append([]NavSection{}, self.Nav.Sections...)
	res = append(res, NavSection{
		Title: "Reference",
		Pages: []NavPage{
			{Path: "reference/vql", Title: "VQL plugins and functions"},
			{Path: "reference/artifacts", Title: "Built-in artifacts"},
			{Path: "reference/config", Title: "Configuration file"},
			{Path: "reference/cli", Title: "Command line"},
			{Path: "reference/api", Title: "Integration REST API"},
		},
	})
	return res
}

func (self *Site) write() error {
	tmpl, err := template.New("page").Funcs(template.FuncMap{
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
	}).Parse(pageTemplate)
	if err != nil {
		return err
	}

	if err := os.RemoveAll(self.Opts.Out); err != nil {
		return err
	}

	for _, p := range self.Pages {
		nav, prev, next := self.navFor(p)
		view := pageView{
			Page:        p,
			Base:        self.BasePath,
			SiteURL:     self.Opts.URL,
			Nav:         nav,
			Prev:        prev,
			Next:        next,
			Description: p.Description,
			Year:        "2026",
		}
		if view.Description == "" {
			view.Description = p.Title + " - Atlantiraptor documentation by Atlant Security."
		}
		if p.Source != "" && !strings.HasPrefix(p.Source, "generated:") {
			view.EditURL = RepoURL + "/blob/master/" + p.Source
		}
		view.Crumbs = self.crumbs(p)

		buf := &bytes.Buffer{}
		if err := tmpl.Execute(buf, view); err != nil {
			return fmt.Errorf("%s: %w", p.Path, err)
		}
		self.files[path.Join(p.Path, "index.html")] = buf.Bytes()
	}

	// 404 page for GitHub Pages.
	if home, pres := self.byPath[""]; pres {
		nf := *home
		nf.Title = "Page not found"
		nf.HTML = template.HTML(`<p>This page does not exist. It may have moved: try the search box above, or start from the <a href="` +
			self.BasePath + `">documentation home</a>.</p>`)
		nf.TOC = nil
		nav, _, _ := self.navFor(&nf)
		buf := &bytes.Buffer{}
		if err := tmpl.Execute(buf, pageView{Page: &nf, Base: self.BasePath,
			SiteURL: self.Opts.URL, Nav: nav, Year: "2026",
			Description: "Page not found"}); err != nil {
			return err
		}
		self.files["404.html"] = buf.Bytes()
	}

	// Static assets.
	entries, err := assetsFS.ReadDir("assets")
	if err != nil {
		return err
	}
	for _, e := range entries {
		data, err := assetsFS.ReadFile("assets/" + e.Name())
		if err != nil {
			return err
		}
		self.files["assets/"+e.Name()] = data
	}

	// Screenshots and other images (docs/site/images).
	imgDir := filepath.Join(self.Opts.Root, "docs/site/images")
	imgs, err := os.ReadDir(imgDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, e := range imgs {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(imgDir, e.Name()))
		if err != nil {
			return err
		}
		self.files["images/"+e.Name()] = data
	}

	// Website search index.
	idx, err := self.searchIndex()
	if err != nil {
		return err
	}
	self.files["search-index.json"] = idx
	self.files[".nojekyll"] = nil
	self.files["sitemap.xml"] = self.sitemap()
	self.files["robots.txt"] = []byte("User-agent: *\nAllow: /\nSitemap: " + self.Opts.URL + "sitemap.xml\n")

	names := make([]string, 0, len(self.files))
	for name := range self.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		full := filepath.Join(self.Opts.Out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(full, self.files[name], 0644); err != nil {
			return err
		}
	}
	return nil
}

func (self *Site) crumbs(p *Page) (res []navLink) {
	if p.Path == "" {
		return nil
	}
	res = append(res, navLink{Title: "Docs", URL: self.BasePath})
	parts := strings.Split(p.Path, "/")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[:i], "/")
		if pp, pres := self.byPath[parent]; pres {
			res = append(res, navLink{Title: pp.Title, URL: self.pageURLPath(parent)})
		}
	}
	return res
}

func (self *Site) sitemap() []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, p := range self.Pages {
		fmt.Fprintf(buf, "  <url><loc>%s</loc></url>\n", html.EscapeString(self.PageURL(p.Path)))
	}
	buf.WriteString("</urlset>\n")
	return buf.Bytes()
}

type searchEntry struct {
	Title   string `json:"t"`
	URL     string `json:"u"`
	Section string `json:"s"`
	Text    string `json:"x"`
}

var (
	mdNoiseRegex = regexp.MustCompile("[`*_#>|\\[\\]]+|\\(([^)]*)\\)")
	spaceRegex   = regexp.MustCompile(`\s+`)
)

func plainText(md string, limit int) string {
	text := mdNoiseRegex.ReplaceAllString(md, " ")
	text = spaceRegex.ReplaceAllString(text, " ")
	text = strings.TrimSpace(text)
	if len(text) > limit {
		text = text[:limit]
		// Do not cut a UTF-8 sequence in half.
		for len(text) > 0 && !isRuneStart(text[len(text)-1]) {
			text = text[:len(text)-1]
		}
		if len(text) > 0 {
			text = text[:len(text)-1]
		}
	}
	return text
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

func (self *Site) searchIndex() ([]byte, error) {
	var entries []searchEntry
	for _, p := range self.Pages {
		limit := 6000
		if p.Tag != "Docs" && p.Tag != "KB" {
			limit = 600
		}
		section := p.Section
		entries = append(entries, searchEntry{
			Title:   p.Title,
			URL:     self.pageURLPath(p.Path),
			Section: section,
			Text:    plainText(p.Markdown, limit),
		})
	}
	return json.Marshal(entries)
}
