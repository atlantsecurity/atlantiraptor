package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------
// VQL reference from docs/references/vql.yaml

type vqlArg struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
	Repeated    bool   `yaml:"repeated"`
}

type vqlEntry struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Type        string            `yaml:"type"`
	Args        []vqlArg          `yaml:"args"`
	Category    string            `yaml:"category"`
	Metadata    map[string]string `yaml:"metadata"`
	Platforms   []string          `yaml:"platforms"`
	Version     int               `yaml:"version"`
}

var vqlCategoryTitles = map[string]string{
	"popular":      "Popular",
	"basic":        "Basic",
	"server":       "Server",
	"windows":      "Windows",
	"linux":        "Linux",
	"parsers":      "Parsers",
	"event":        "Event plugins",
	"plugin":       "Plugins",
	"other":        "Other",
	"experimental": "Experimental",
}

func mdEscapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "\n\n"); idx > 0 {
		s = s[:idx]
	}
	s = strings.ReplaceAll(s, "\n", " ")
	if idx := strings.Index(s, ". "); idx > 0 && idx < 220 {
		s = s[:idx+1]
	}
	if len(s) > 240 {
		s = s[:237] + "..."
	}
	// Code fences or headings in a summary break the table.
	if strings.Contains(s, "```") || strings.HasPrefix(s, "#") {
		return ""
	}
	return s
}

func (self *Site) generateVQLReference() error {
	data, err := os.ReadFile(filepath.Join(self.Opts.Root, "docs/references/vql.yaml"))
	if err != nil {
		return err
	}
	var entries []vqlEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("vql.yaml: %w", err)
	}

	// A name can be both a plugin and a function: they share a page.
	byName := make(map[string][]vqlEntry)
	var names []string
	for _, e := range entries {
		if _, pres := byName[e.Name]; !pres {
			names = append(names, e.Name)
		}
		byName[e.Name] = append(byName[e.Name], e)
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})

	index := &strings.Builder{}
	index.WriteString(`VQL, the query language of Atlantiraptor, is extended by plugins (which
produce rows, used after ` + "`FROM`" + `) and functions (which return a single
value). This reference lists every plugin and function built into this
version, generated from the source code. To learn the language itself,
start with [VQL fundamentals](/vql/fundamentals/).

`)
	byCategory := make(map[string][]string)
	for _, name := range names {
		cat := byName[name][0].Category
		if cat == "" {
			cat = "other"
		}
		byCategory[cat] = append(byCategory[cat], name)
	}
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	order := map[string]int{"popular": 0, "basic": 1, "parsers": 2, "server": 3,
		"windows": 4, "linux": 5, "event": 6, "plugin": 7, "experimental": 8, "other": 9}
	sort.Slice(cats, func(i, j int) bool {
		oi, ok := order[cats[i]]
		if !ok {
			oi = 50
		}
		oj, ok := order[cats[j]]
		if !ok {
			oj = 50
		}
		if oi != oj {
			return oi < oj
		}
		return cats[i] < cats[j]
	})

	fmt.Fprintf(index, "There are %d entries, grouped by category below.\n\n", len(names))
	for _, c := range cats {
		title := vqlCategoryTitles[c]
		if title == "" {
			title = strings.Title(c)
		}
		fmt.Fprintf(index, "## %s {#%s}\n\n| Name | Type | Summary |\n|---|---|---|\n", title, c)
		for _, name := range byCategory[c] {
			var types []string
			for _, e := range byName[name] {
				types = append(types, e.Type)
			}
			fmt.Fprintf(index, "| [%s](/reference/vql/%s/) | %s | %s |\n",
				name, strings.ToLower(name), strings.Join(types, ", "),
				mdEscapeCell(firstSentence(byName[name][0].Description)))
		}
		index.WriteString("\n")
	}

	self.addPage(&Page{
		Path:     "reference/vql",
		Title:    "VQL plugins and functions",
		Section:  "Reference",
		Tag:      "VQLReference",
		Markdown: index.String(),
		Source:   "docs/references/vql.yaml",
		NoTOC:    true,
	})

	for _, name := range names {
		md := &strings.Builder{}
		for _, e := range byName[name] {
			if len(byName[name]) > 1 {
				fmt.Fprintf(md, "## %s %s {#%s}\n\n", e.Name, strings.ToLower(e.Type), strings.ToLower(e.Type))
			}
			typeLine := "**Type:** " + e.Type
			if e.Category != "" {
				typeLine += " · **Category:** " + e.Category
			}
			md.WriteString(typeLine + "\n\n")

			desc := strings.TrimSpace(e.Description)
			if desc != "" {
				md.WriteString(desc + "\n\n")
			}

			if len(e.Args) > 0 {
				md.WriteString("| Argument | Type | Description |\n|---|---|---|\n")
				for _, a := range e.Args {
					t := a.Type
					if a.Repeated {
						t = "list of " + t
					}
					req := ""
					if a.Required {
						req = " (required)"
					}
					fmt.Fprintf(md, "| `%s` | %s%s | %s |\n", a.Name, mdEscapeCell(t), req,
						mdEscapeCell(a.Description))
				}
				md.WriteString("\n")
			}

			if perm := e.Metadata["permissions"]; perm != "" {
				fmt.Fprintf(md, "**Required permissions:** %s\n\n",
					strings.ReplaceAll(perm, ",", ", "))
			}
			if len(e.Platforms) > 0 {
				fmt.Fprintf(md, "**Platforms:** %s\n\n", platformSummary(e.Platforms))
			}
			if f := e.Metadata["File"]; f != "" {
				fmt.Fprintf(md, "Source: [`%s`](%s/blob/master/%s)\n\n", f, RepoURL, f)
			}
		}
		self.addPage(&Page{
			Path:     "reference/vql/" + strings.ToLower(name),
			Title:    name,
			Section:  "Reference",
			Tag:      "VQLReference",
			Markdown: md.String(),
			Source:   "docs/references/vql.yaml",
			NoTOC:    true,
		})
	}
	return nil
}

func platformSummary(platforms []string) string {
	seen := make(map[string]bool)
	var res []string
	for _, p := range platforms {
		os := strings.SplitN(p, "_", 2)[0]
		switch os {
		case "windows":
			os = "Windows"
		case "linux":
			os = "Linux"
		case "darwin":
			os = "macOS"
		case "freebsd":
			os = "FreeBSD"
		}
		if !seen[os] {
			seen[os] = true
			res = append(res, os)
		}
	}
	return strings.Join(res, ", ")
}

// ---------------------------------------------------------------------
// Artifact reference from artifacts/definitions

type artifactParam struct {
	Name        string      `yaml:"name"`
	Type        string      `yaml:"type"`
	Default     interface{} `yaml:"default"`
	Description string      `yaml:"description"`
	Friendly    string      `yaml:"friendly_name"`
}

type artifactSource struct {
	Name         string `yaml:"name"`
	Description  string `yaml:"description"`
	Precondition string `yaml:"precondition"`
	Query        string `yaml:"query"`
	Notebook     []struct {
		Type     string `yaml:"type"`
		Template string `yaml:"template"`
	} `yaml:"notebook"`
}

type artifactTool struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	Version  string `yaml:"version"`
	Filename string `yaml:"filename"`
}

type artifactDef struct {
	Name                string                 `yaml:"name"`
	Description         string                 `yaml:"description"`
	Author              string                 `yaml:"author"`
	Type                string                 `yaml:"type"`
	Precondition        string                 `yaml:"precondition"`
	Reference           []string               `yaml:"reference"`
	Parameters          []artifactParam        `yaml:"parameters"`
	Sources             []artifactSource       `yaml:"sources"`
	Tools               []artifactTool         `yaml:"tools"`
	RequiredPermissions []string               `yaml:"required_permissions"`
	ImpliedPermissions  []string               `yaml:"implied_permissions"`
	Resources           map[string]interface{} `yaml:"resources"`

	file string
	raw  string
}

var artifactTypeTitles = map[string]string{
	"CLIENT":       "Client",
	"CLIENT_EVENT": "Client event (monitoring)",
	"SERVER":       "Server",
	"SERVER_EVENT": "Server event (monitoring)",
	"NOTEBOOK":     "Notebook template",
	"INTERNAL":     "Internal",
}

func artifactSlug(name string) string {
	return strings.ToLower(name)
}

func (self *Site) loadArtifacts() ([]*artifactDef, error) {
	var res []*artifactDef
	root := filepath.Join(self.Opts.Root, "artifacts/definitions")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !(strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		a := &artifactDef{}
		if err := yaml.Unmarshal(data, a); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if a.Name == "" {
			return nil
		}
		rel, _ := filepath.Rel(self.Opts.Root, p)
		a.file = filepath.ToSlash(rel)
		a.raw = string(data)
		a.Type = strings.ToUpper(a.Type)
		if a.Type == "" {
			a.Type = "CLIENT"
		}
		res = append(res, a)
		return nil
	})
	sort.Slice(res, func(i, j int) bool {
		return strings.ToLower(res[i].Name) < strings.ToLower(res[j].Name)
	})
	return res, err
}

func formatDefault(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		t = strings.TrimSpace(t)
		if strings.Contains(t, "\n") || len(t) > 80 {
			return "(see the artifact source)"
		}
		if t == "" {
			return ""
		}
		return "`" + strings.ReplaceAll(t, "`", "'") + "`"
	default:
		return "`" + strings.TrimSpace(fmt.Sprint(t)) + "`"
	}
}

func (self *Site) generateArtifactReference() error {
	artifacts, err := self.loadArtifacts()
	if err != nil {
		return err
	}

	groups := make(map[string][]*artifactDef)
	var groupNames []string
	for _, a := range artifacts {
		g := strings.SplitN(a.Name, ".", 2)[0]
		if _, pres := groups[g]; !pres {
			groupNames = append(groupNames, g)
		}
		groups[g] = append(groups[g], a)
	}
	sort.Strings(groupNames)

	index := &strings.Builder{}
	fmt.Fprintf(index, `Atlantiraptor ships with %d artifacts. Each one is a packaged VQL query
with a description and parameters. This list is generated from the
definitions in this version of the server, so it matches what you see
under **Artifacts** in the console. To learn how artifacts work and how to
write your own, see [Artifacts](/artifacts/).

Groups: `, len(artifacts))
	var links []string
	for _, g := range groupNames {
		links = append(links, fmt.Sprintf("[%s](#%s)", g, strings.ToLower(g)))
	}
	index.WriteString(strings.Join(links, " · ") + "\n\n")

	for _, g := range groupNames {
		fmt.Fprintf(index, "## %s {#%s}\n\n| Artifact | Type | Summary |\n|---|---|---|\n", g, strings.ToLower(g))
		for _, a := range groups[g] {
			fmt.Fprintf(index, "| [%s](/reference/artifacts/%s/) | %s | %s |\n",
				a.Name, artifactSlug(a.Name), artifactTypeTitles[a.Type],
				mdEscapeCell(firstSentence(a.Description)))
		}
		index.WriteString("\n")
	}

	self.addPage(&Page{
		Path:     "reference/artifacts",
		Title:    "Built-in artifacts",
		Section:  "Reference",
		Tag:      "Artifacts",
		Markdown: index.String(),
		Source:   "generated:artifacts",
		NoTOC:    true,
	})

	for _, a := range artifacts {
		md := &strings.Builder{}
		fmt.Fprintf(md, "**Type:** %s", artifactTypeTitles[a.Type])
		if a.Author != "" {
			fmt.Fprintf(md, " · **Author:** %s", strings.TrimSpace(a.Author))
		}
		md.WriteString("\n\n")

		if d := strings.TrimSpace(a.Description); d != "" {
			md.WriteString(d + "\n\n")
		}

		if len(a.RequiredPermissions) > 0 {
			fmt.Fprintf(md, "**Required permissions:** %s\n\n", strings.Join(a.RequiredPermissions, ", "))
		}
		if len(a.ImpliedPermissions) > 0 {
			fmt.Fprintf(md, "**Implied permissions:** %s\n\n", strings.Join(a.ImpliedPermissions, ", "))
		}
		if p := strings.TrimSpace(a.Precondition); p != "" {
			fmt.Fprintf(md, "**Precondition:** `%s`\n\n", strings.ReplaceAll(strings.Join(strings.Fields(p), " "), "`", "'"))
		}

		if len(a.Parameters) > 0 {
			md.WriteString("## Parameters\n\n| Name | Type | Default | Description |\n|---|---|---|---|\n")
			for _, p := range a.Parameters {
				t := p.Type
				if t == "" {
					t = "string"
				}
				desc := p.Description
				if desc == "" {
					desc = p.Friendly
				}
				fmt.Fprintf(md, "| `%s` | %s | %s | %s |\n", p.Name, t,
					mdEscapeCell(formatDefault(p.Default)), mdEscapeCell(desc))
			}
			md.WriteString("\n")
		}

		if len(a.Tools) > 0 {
			md.WriteString("## Tools\n\nThis artifact uses these external tools, managed by the server's tool inventory (see [Managing external tools](/artifacts/tools/)):\n\n")
			for _, t := range a.Tools {
				line := "- `" + t.Name + "`"
				if t.Version != "" {
					line += " version " + t.Version
				}
				if t.URL != "" {
					line += " from <" + t.URL + ">"
				}
				md.WriteString(line + "\n")
			}
			md.WriteString("\n")
		}

		if len(a.Reference) > 0 {
			md.WriteString("## References\n\n")
			for _, r := range a.Reference {
				r = strings.TrimSpace(r)
				if strings.HasPrefix(r, "http") {
					md.WriteString("- <" + r + ">\n")
				} else {
					md.WriteString("- " + r + "\n")
				}
			}
			md.WriteString("\n")
		}

		md.WriteString("## Source\n\n")
		fmt.Fprintf(md, "Defined in [`%s`](%s/blob/master/%s).\n\n```yaml\n%s\n```\n",
			a.file, RepoURL, a.file, strings.TrimRight(strings.ReplaceAll(a.raw, "```", "` ` `"), "\n"))

		self.addPage(&Page{
			Path:     "reference/artifacts/" + artifactSlug(a.Name),
			Title:    a.Name,
			Section:  "Reference",
			Tag:      "Artifacts",
			Markdown: md.String(),
			Source:   a.file,
		})
	}
	return nil
}

// ---------------------------------------------------------------------
// Configuration reference from the annotated server.config.yaml

var (
	configKeyRegex = regexp.MustCompile(`^( *)(- )?([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$`)
)

type configItem struct {
	Path    string
	Depth   int
	Comment []string
	Value   []string
}

func (self *Site) generateConfigReference() error {
	data, err := os.ReadFile(filepath.Join(self.Opts.Root, "docs/references/server.config.yaml"))
	if err != nil {
		return err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	var items []*configItem
	var comment []string
	type frame struct {
		indent int
		name   string
	}
	var stack []frame
	var current *configItem
	headerDone := false
	var preamble []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			text := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			if !headerDone {
				preamble = append(preamble, text)
				continue
			}
			comment = append(comment, text)
			current = nil
			continue
		}
		if trimmed == "" {
			if !headerDone && len(preamble) > 0 {
				headerDone = true
			}
			if len(comment) > 0 {
				comment = append(comment, "")
			}
			continue
		}
		headerDone = true

		m := configKeyRegex.FindStringSubmatch(line)
		if m == nil {
			// A list item or continuation of a value.
			if current != nil {
				current.Value = append(current.Value, line)
			}
			continue
		}
		indent := len(m[1])
		if m[2] != "" {
			indent += 2
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		var parts []string
		for _, f := range stack {
			parts = append(parts, f.name)
		}
		parts = append(parts, m[3])
		item := &configItem{
			Path:    strings.Join(parts, "."),
			Depth:   len(parts),
			Comment: trimBlank(comment),
		}
		if v := strings.TrimSpace(m[4]); v != "" {
			item.Value = []string{v}
		}
		comment = nil
		stack = append(stack, frame{indent: indent, name: m[3]})

		// Skip duplicate paths (list items repeat keys).
		dup := false
		for _, existing := range items {
			if existing.Path == item.Path {
				dup = true
				if len(existing.Comment) == 0 {
					existing.Comment = item.Comment
				}
				break
			}
		}
		if !dup {
			items = append(items, item)
			current = item
		} else {
			current = nil
		}
	}

	md := &strings.Builder{}
	md.WriteString(`The server and clients read their settings from YAML configuration files
(` + "`server.config.yaml`" + ` and ` + "`client.config.yaml`" + `). This page lists every
setting, generated from the annotated sample configuration in this
repository. A value shown is the default used when the setting is
left out. For how to create and change the configuration, see
[Server configuration](/deployment/configuration/).

Top-level sections: `)
	var tops []string
	for _, it := range items {
		if it.Depth == 1 {
			tops = append(tops, fmt.Sprintf("[%s](#%s)", it.Path, strings.ToLower(it.Path)))
		}
	}
	md.WriteString(strings.Join(tops, " · ") + "\n\n")

	for _, it := range items {
		id := strings.ToLower(it.Path)
		if it.Depth == 1 {
			fmt.Fprintf(md, "## %s {#%s}\n\n", it.Path, id)
		} else {
			fmt.Fprintf(md, "### %s {#%s}\n\n", it.Path, id)
		}
		if len(it.Comment) > 0 {
			md.WriteString(commentToMarkdown(it.Comment) + "\n\n")
		}
		if len(it.Value) > 0 {
			val := strings.Join(it.Value, "\n")
			if len(it.Value) == 1 && !strings.Contains(val, "`") {
				fmt.Fprintf(md, "Default: `%s`\n\n", val)
			} else {
				fmt.Fprintf(md, "Default:\n\n```yaml\n%s\n```\n\n", dedent(it.Value))
			}
		}
	}

	self.addPage(&Page{
		Path:     "reference/config",
		Title:    "Configuration file reference",
		Section:  "Reference",
		Tag:      "Docs",
		Markdown: md.String(),
		Source:   "docs/references/server.config.yaml",
		NoTOC:    true,
	})
	return nil
}

func trimBlank(in []string) []string {
	for len(in) > 0 && in[len(in)-1] == "" {
		in = in[:len(in)-1]
	}
	for len(in) > 0 && in[0] == "" {
		in = in[1:]
	}
	return in
}

func dedent(lines []string) string {
	min := -1
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		n := len(l) - len(strings.TrimLeft(l, " "))
		if min < 0 || n < min {
			min = n
		}
	}
	var out []string
	for _, l := range lines {
		if len(l) >= min && min > 0 {
			l = l[min:]
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// commentToMarkdown keeps paragraphs and indented examples from the
// YAML comments.
func commentToMarkdown(lines []string) string {
	var out []string
	inCode := false
	for _, l := range lines {
		if strings.HasPrefix(l, "```") {
			inCode = !inCode
		}
		out = append(out, l)
	}
	if inCode {
		out = append(out, "```")
	}
	return strings.Join(out, "\n")
}

// ---------------------------------------------------------------------
// Command line reference, from the program's own help. The generator
// runs the binary given with -cli-binary: `help --help-long` for the
// command tree, then `help <command>` for each command.

func runHelp(binary string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, append([]string{"help"}, args...)...).CombinedOutput()
	return strings.ReplaceAll(string(out), "\r\n", "\n"), err
}

// helpSections splits kingpin help into its usage line, description
// and the Flags/Args blocks.
func helpSections(text string) (usage, desc string, blocks map[string][]string) {
	blocks = make(map[string][]string)
	current := ""
	var descLines []string
	for _, l := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(l, "usage: "):
			usage = strings.TrimPrefix(l, "usage: ")
			continue
		case l == "Flags:" || l == "Args:" || l == "Commands:":
			current = strings.TrimSuffix(l, ":")
			continue
		}
		if current == "" {
			descLines = append(descLines, l)
		} else {
			blocks[current] = append(blocks[current], l)
		}
	}
	return usage, strings.TrimSpace(strings.Join(descLines, "\n")), blocks
}

func (self *Site) generateCLIReference() error {
	md := &strings.Builder{}
	md.WriteString(`Atlantiraptor is a single program: the same binary runs the server, the
client and every command line tool. This page lists every command and
flag of this version, taken from the program's own help. For a guided
tour, see [The command line](/cli/).

Run ` + "`atlantiraptor help <command>`" + ` (` + "`Atlantiraptor.exe help <command>`" + ` on Windows) to see the
same information on your system. In the examples the program is called
` + "`atlantiraptor`" + `; use the name of your binary.

`)
	if self.Opts.CLIBinary == "" {
		md.WriteString("> **Note:** This copy of the documentation was built without the command line help. Run `atlantiraptor help --help-long` to see it.\n")
	} else {
		text, err := self.cliMarkdown()
		if err != nil {
			return err
		}
		md.WriteString(text)
	}

	self.addPage(&Page{
		Path:     "reference/cli",
		Title:    "Command line reference",
		Section:  "Reference",
		Tag:      "Docs",
		Markdown: md.String(),
		Source:   "generated:cli",
	})
	return nil
}

var cliTreeRegex = regexp.MustCompile(`^( +)([a-z][a-z0-9_-]*)`)

func (self *Site) cliMarkdown() (string, error) {
	top, err := runHelp(self.Opts.CLIBinary, "--help-long")
	if err != nil {
		return "", fmt.Errorf("%s help --help-long: %w: %s", self.Opts.CLIBinary, err, top)
	}
	_, _, topBlocks := helpSections(top)
	global := topBlocks["Flags"]
	for len(global) > 0 && strings.TrimSpace(global[len(global)-1]) == "" {
		global = global[:len(global)-1]
	}

	out := &strings.Builder{}
	out.WriteString("## Global flags {#global-flags}\n\nThese flags work with every command.\n\n```text\n" +
		dedent(global) + "\n```\n\n## Commands {#commands}\n\n")

	// Walk the command tree by indentation.
	var stack []string
	for _, l := range topBlocks["Commands"] {
		m := cliTreeRegex.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		depth := len(m[1])/2 - 1
		if depth < 0 {
			continue
		}
		if depth < len(stack) {
			stack = stack[:depth]
		}
		stack = append(stack, m[2])
		if m[2] == "help" && depth == 0 {
			continue
		}
		cmd := append([]string{}, stack...)

		text, err := runHelp(self.Opts.CLIBinary, cmd...)
		if err != nil {
			// Hidden internal commands do not have help.
			continue
		}
		usage, desc, blocks := helpSections(text)
		flags := blocks["Flags"]
		// Drop the global flags, which kingpin repeats first.
		if len(flags) >= len(global) {
			same := true
			for i := range global {
				if flags[i] != global[i] {
					same = false
					break
				}
			}
			if same {
				flags = flags[len(global):]
			}
		}

		name := strings.Join(cmd, " ")
		level := "###"
		if len(cmd) > 1 {
			level = "####"
		}
		fmt.Fprintf(out, "%s %s {#%s}\n\n", level, name, strings.Join(cmd, "-"))
		if desc != "" {
			out.WriteString(desc + "\n\n")
		}
		body := "usage: " + strings.Replace(usage, "velociraptor", "atlantiraptor", 1)
		if args := strings.TrimRight(dedent(blocks["Args"]), "\n "); args != "" {
			body += "\n\nArguments:\n" + args
		}
		if f := strings.TrimRight(dedent(flags), "\n "); strings.TrimSpace(f) != "" {
			body += "\n\nFlags:\n" + f
		}
		out.WriteString("```text\n" + body + "\n```\n\n")
	}
	return out.String(), nil
}

// ---------------------------------------------------------------------
// Integration REST API from the OpenAPI spec embedded in the server.

var openAPIRegex = regexp.MustCompile("(?s)const atlOpenAPISpec = `(.*?)`")

func (self *Site) generateRESTReference() error {
	data, err := os.ReadFile(filepath.Join(self.Opts.Root, "api/atlapi_openapi.go"))
	if err != nil {
		return err
	}
	m := openAPIRegex.FindSubmatch(data)
	if m == nil {
		return fmt.Errorf("api/atlapi_openapi.go: OpenAPI spec not found")
	}

	var spec struct {
		Info struct {
			Description string `yaml:"description"`
		} `yaml:"info"`
		Paths map[string]map[string]struct {
			Summary     string `yaml:"summary"`
			Description string `yaml:"description"`
			Parameters  []struct {
				Name        string `yaml:"name"`
				In          string `yaml:"in"`
				Required    bool   `yaml:"required"`
				Description string `yaml:"description"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(m[1], &spec); err != nil {
		return fmt.Errorf("OpenAPI spec: %w", err)
	}

	md := &strings.Builder{}
	md.WriteString(`The integration API lets a SIEM, SOAR or script read alerts and results
and start collections, hunts and response actions over HTTPS. It is
served by the console's web server under ` + "`/api/atl/v1/`" + `. How to create keys,
lock them to addresses and connect a SIEM is explained in
[API keys and SIEM integration](/server-automation/api-keys/).

The server publishes the machine-readable specification, without
authentication, at ` + "`https://<your server>/api/atl/v1/openapi.yaml`" + `. This page
is generated from the same specification.

## Overview

`)
	md.WriteString(strings.TrimSpace(spec.Info.Description) + "\n\n## Endpoints\n\n| Method | Path | Summary |\n|---|---|---|\n")

	paths := make([]string, 0, len(spec.Paths))
	for p := range spec.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	methodOrder := []string{"get", "post", "put", "patch", "delete"}
	for _, p := range paths {
		for _, method := range methodOrder {
			op, pres := spec.Paths[p][method]
			if !pres {
				continue
			}
			fmt.Fprintf(md, "| %s | `%s` | %s |\n", strings.ToUpper(method), p, mdEscapeCell(op.Summary))
		}
	}
	md.WriteString("\n## Details\n\n")
	for _, p := range paths {
		for _, method := range methodOrder {
			op, pres := spec.Paths[p][method]
			if !pres {
				continue
			}
			fmt.Fprintf(md, "### %s %s\n\n", strings.ToUpper(method), p)
			if op.Summary != "" {
				md.WriteString(op.Summary + "\n\n")
			}
			if d := strings.TrimSpace(op.Description); d != "" {
				md.WriteString(d + "\n\n")
			}
			if len(op.Parameters) > 0 {
				md.WriteString("| Parameter | In | Description |\n|---|---|---|\n")
				for _, prm := range op.Parameters {
					req := ""
					if prm.Required {
						req = " (required)"
					}
					fmt.Fprintf(md, "| `%s`%s | %s | %s |\n", prm.Name, req, prm.In, mdEscapeCell(prm.Description))
				}
				md.WriteString("\n")
			}
		}
	}

	self.addPage(&Page{
		Path:     "reference/api",
		Title:    "Integration REST API reference",
		Section:  "Reference",
		Tag:      "Docs",
		Markdown: md.String(),
		Source:   "api/atlapi_openapi.go",
	})
	return nil
}
