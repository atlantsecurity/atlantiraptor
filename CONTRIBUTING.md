# Contributing to Atlantiraptor

Thank you for your interest in improving Atlantiraptor. Bug reports,
fixes, artifacts and documentation improvements are all welcome.

## Reporting bugs

Open a [GitHub issue](https://github.com/atlantsecurity/atlantiraptor/issues)
with the version (`atlantiraptor version`), what you did, what you
expected and what happened. Collection logs (the **Log** tab) and a `-v`
log help a lot; remove host names, user names and secrets first.

Report security problems privately: see [security.md](security.md).

## Code

Atlantiraptor is written in Go, with a React console under
`gui/velociraptor`. Set up your environment as described in
[Building from source](README.md#building-from-source), then:

- keep changes focused and tested (`make test`, or `go test` on the
  packages you changed),
- follow standard Go conventions and the lint settings in
  [staticcheck.conf](staticcheck.conf),
- open a pull request against `master` describing what changed and how you
  tested it.

The VQL engine lives under `vql/`, server services under `services/`,
file system accessors under `accessors/` and built-in artifacts under
`artifacts/definitions/`.

Atlantiraptor is based on [Velociraptor](https://github.com/Velocidex/velociraptor)
and merges its changes regularly. A fix to code that Atlantiraptor shares
with Velociraptor helps both projects if it is also offered upstream.

## Artifacts

Built-in artifacts are YAML files under `artifacts/definitions/`. See
[Writing artifacts](https://atlantsecurity.github.io/atlantiraptor/artifacts/writing/).
Add a test case under `artifacts/testdata/` where you can.

## Documentation

The documentation website is built from [`docs/site`](docs/site/README.md).
Guides are Markdown files under `docs/site/content`. The reference sections
are generated from `docs/references/vql.yaml`, the artifact definitions,
`docs/references/server.config.yaml`, the command line and the REST API
specification, so improve a description at its source.

## Licence

Atlantiraptor is licensed under the
[GNU Affero General Public License v3.0](LICENSE). By contributing you
agree that your contributions are licensed under the AGPLv3.
