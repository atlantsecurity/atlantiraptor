# Documentation website

The Atlantiraptor documentation at
<https://atlantsecurity.github.io/atlantiraptor/> is built from this
folder by a small Go program (`go run ./docs/site`) and published by
`.github/workflows/docs.yml` on every merge to master.

## Layout

| Path | What it is |
|---|---|
| `content/<path>.md` | Hand-written pages, with `title` and `description` front matter |
| `nav.yaml` | The sidebar, in reading order. A page not listed here is not built |
| `templates/page.html` | The page template |
| `assets/` | CSS, JavaScript and icons |
| `*.go` | The generator |

The **Reference** section is generated from the repository itself:

- VQL plugins and functions from `docs/references/vql.yaml`,
- artifacts from `artifacts/definitions`,
- the configuration file from `docs/references/server.config.yaml`,
- the command line by running a built binary (`-cli-binary`),
- the integration REST API from `api/atlapi_openapi.go`.

So fixing a description in one of those files fixes the website too.

## Building locally

```bash
go run make.go -v BasicAssets
go build -tags "server_vql extras" -o output/atlantiraptor ./bin/
go run ./docs/site -out docs/site/public -cli-binary output/atlantiraptor
# The site lives under /atlantiraptor/, so serve it from a folder above:
mkdir -p /tmp/serve && ln -sfn "$PWD/docs/site/public" /tmp/serve/atlantiraptor
python3 -m http.server -d /tmp/serve 8000
# open http://localhost:8000/atlantiraptor/
```

The build fails on any broken internal link or `#anchor`, so a green
build means every link between pages works. `-docs-index file.zip` also
writes the search index the console's **Search documentation** dialog
downloads.

## Writing pages

- Markdown, with `{#custom-id}` after a heading to fix its anchor.
- Link to other pages by site path: `[Hunts](/hunts/#targeting)`.
- Callouts: a blockquote starting with `**Note**`, `**Tip**` or
  `**Warning**`.
- Describe Atlantiraptor as it is today, test VQL examples with
  `atlantiraptor query`, and use the console's own labels in **bold**.
