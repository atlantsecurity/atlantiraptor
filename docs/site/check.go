package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Velocidex/velociraptor-site-search/api"
)

var (
	linkRegex = regexp.MustCompile(`(?:href|src)="([^"]*)"`)
	idRegex   = regexp.MustCompile(`id="([^"]+)"`)
)

// DocsIndexFile is where the docs workflow publishes the console's
// search index (Server.Internal.ToolDependencies downloads it).
const DocsIndexFile = "docs_index_v1.zip"

// CheckLinks reports links inside the site that point to a page or an
// anchor that does not exist.
func (self *Site) CheckLinks() (problems []string) {
	ids := make(map[string]map[string]bool)
	for name, data := range self.files {
		if !strings.HasSuffix(name, ".html") {
			continue
		}
		set := make(map[string]bool)
		for _, m := range idRegex.FindAllSubmatch(data, -1) {
			set[string(m[1])] = true
		}
		ids[name] = set
	}

	names := make([]string, 0, len(self.files))
	for name := range self.files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if !strings.HasSuffix(name, ".html") || name == "404.html" {
			continue
		}
		data := self.files[name]
		for _, m := range linkRegex.FindAllSubmatch(data, -1) {
			link := strings.ReplaceAll(string(m[1]), "&amp;", "&")
			target, frag := link, ""
			if idx := strings.Index(link, "#"); idx >= 0 {
				target, frag = link[:idx], link[idx+1:]
			}
			if strings.HasPrefix(frag, "/") {
				// A console route quoted in a description.
				continue
			}
			var file string
			switch {
			case target == "":
				file = name
			case strings.HasPrefix(target, self.BasePath):
				rel := strings.TrimPrefix(target, self.BasePath)
				if rel == "" || strings.HasSuffix(rel, "/") {
					file = rel + "index.html"
				} else {
					file = rel
				}
			default:
				continue
			}
			// The console's search index is written after the check
			// (-docs-index) and published next to the pages.
			if file == DocsIndexFile {
				continue
			}
			if _, pres := self.files[file]; !pres {
				problems = append(problems, fmt.Sprintf("%s: link to missing page %s", name, link))
				continue
			}
			if frag != "" && strings.HasSuffix(file, ".html") && !ids[file][frag] {
				problems = append(problems, fmt.Sprintf("%s: link to missing anchor %s", name, link))
			}
		}
	}
	return problems
}

// WriteDocsIndex writes the zip file that the console's documentation
// search downloads as the DocsIndex tool (services/docs). It is a
// Bleve index of every page, built with the same library the server
// uses to read it.
func (self *Site) WriteDocsIndex(output string) error {
	dir, err := os.MkdirTemp("", "docs_index")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	indexDir := filepath.Join(dir, "index")
	mapping, err := api.BuildIndexMapping()
	if err != nil {
		return err
	}
	index, err := api.NewIndex(indexDir, mapping)
	if err != nil {
		return err
	}

	ranks := map[string]int{"Docs": 100, "KB": 60, "VQLReference": 50, "Artifacts": 20}
	for _, p := range self.Pages {
		crumbs, _ := json.Marshal(self.indexCrumbs(p))
		page := &api.Page{
			Title:       p.Title,
			Menutitle:   p.Title,
			Url:         self.PageURL(p.Path),
			Text:        self.absoluteLinks(p.Markdown),
			Tags:        []string{p.Tag},
			BreadCrumbs: string(crumbs),
			Rank:        ranks[p.Tag],
			Type:        "page",
		}
		if page.Rank == 0 {
			page.Rank = 10
		}
		id := p.Path
		if id == "" {
			id = "/"
		}
		if err := index.Index(id, page); err != nil {
			index.Close()
			return err
		}
	}
	index.Close()
	if err := api.PurgeCache(); err != nil {
		return err
	}

	return zipDir(indexDir, output)
}

func (self *Site) indexCrumbs(p *Page) []api.BreadCrumb {
	res := []api.BreadCrumb{}
	for _, c := range self.crumbs(p) {
		res = append(res, api.BreadCrumb{
			Url:  self.Opts.URL + strings.TrimPrefix(c.URL, self.BasePath),
			Name: c.Title,
		})
	}
	return res
}

var mdLinkRegex = regexp.MustCompile(`\]\((/[^)]*)\)`)

// absoluteLinks makes site links in Markdown absolute, since the
// console renders the text outside the website.
func (self *Site) absoluteLinks(md string) string {
	return mdLinkRegex.ReplaceAllStringFunc(md, func(m string) string {
		sm := mdLinkRegex.FindStringSubmatch(m)
		return "](" + self.Opts.URL + strings.TrimPrefix(sm[1], "/") + ")"
	})
}

func zipDir(dir, output string) error {
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	fd, err := os.Create(output)
	if err != nil {
		return err
	}
	defer fd.Close()

	zw := zip.NewWriter(fd)
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
	if err != nil {
		return err
	}
	return zw.Close()
}
