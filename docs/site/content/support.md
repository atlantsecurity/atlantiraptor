---
title: Getting help
description: Where to get help with Atlantiraptor - documentation, GitHub issues and Atlant Security's commercial support - and what to include in a request.
---

## Documentation

Start here: search this site with the box at the top (or press `/`), and
check [Troubleshooting](/troubleshooting/). The console's own search also
finds pages from this documentation.

## Questions and bug reports

Report bugs and ask for features in the
[GitHub issues](https://github.com/atlantsecurity/atlantiraptor/issues) of
the Atlantiraptor repository. Search existing issues first.

For security problems, don't open an issue: see
[Reporting a vulnerability](/security/#reporting-a-vulnerability).

## Commercial support and services

[Atlant Security](https://atlantsecurity.com) offers support
subscriptions, deployment help, premium [hunt feeds](/hunts/feeds/), and
incident response services with Atlantiraptor.

## What to include

A good report gets a good answer quickly. Include:

- the version (`atlantiraptor version`, or **Server updates** in the
  console) and the operating systems of the server and the affected
  clients,
- what you did, what you expected, and what happened instead,
- for a collection that failed: the collection's **Log** tab, and the
  artifact and parameters,
- for a server problem: the server log around the time of the problem
  (see [Logging](/deployment/logging/)),
- for a client problem: the client's log (see
  [Client problems](/troubleshooting/clients/)).

Remove hostnames, user names, IP addresses and anything else sensitive
before you share logs publicly.

## Upstream

Atlantiraptor is based on [Velociraptor](https://github.com/Velocidex/velociraptor).
Problems that also happen in Velociraptor are usually best reported there
too.
