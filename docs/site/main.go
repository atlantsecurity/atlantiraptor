// Command site builds the Atlantiraptor documentation website.
//
// It turns the hand-written pages under docs/site/content (and a few
// Markdown files that live elsewhere in the repository, listed in
// nav.yaml) into a static HTML site, and generates the reference
// sections from the repository's own sources:
//
//   - VQL plugins and functions from docs/references/vql.yaml
//   - artifacts from artifacts/definitions
//   - server configuration from docs/references/server.config.yaml
//   - command line help by running an Atlantiraptor binary (-cli-binary)
//   - the integration REST API from the OpenAPI spec in api/atlapi_openapi.go
//
// It also writes a search index for the website and, optionally, the
// docs_index_v1.zip file that the console's "Search documentation"
// dialog downloads (see services/docs).
//
// Usage (from the repository root):
//
//	go run ./docs/site -out docs/site/public -cli-binary output/atlantiraptor
//
// See docs/site/README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	opts := Options{}
	flag.StringVar(&opts.Root, "root", ".", "Repository root")
	flag.StringVar(&opts.Out, "out", "docs/site/public", "Output directory")
	flag.StringVar(&opts.URL, "url", DefaultSiteURL, "Public URL of the site, ending with /")
	flag.StringVar(&opts.CLIBinary, "cli-binary", "", "An Atlantiraptor binary, to generate the command line reference (optional)")
	flag.StringVar(&opts.DocsIndex, "docs-index", "", "Also write the console search index zip to this file")
	flag.Parse()

	site, err := Build(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}

	if problems := site.CheckLinks(); len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, p)
		}
		fmt.Fprintf(os.Stderr, "%d broken links\n", len(problems))
		os.Exit(1)
	}

	if opts.DocsIndex != "" {
		err = site.WriteDocsIndex(opts.DocsIndex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "docs index: %v\n", err)
			os.Exit(1)
		}
	}

	abs, _ := filepath.Abs(opts.Out)
	fmt.Printf("Wrote %d pages to %s\n", len(site.Pages), abs)
}
