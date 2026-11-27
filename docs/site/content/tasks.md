---
title: Everyday tasks
description: Step-by-step how-tos for the things people do most with Atlantiraptor - collect files, memory and browser history, quarantine computers, hunt across all of them.
---

Each page here is a short how-to for one job. They assume you have a
server with at least one connected computer (see
[Set up a test lab](/quickstart/)) and that you have run
[your first Rapid hunt](/first-hunt/).

## Looking

- [Look at one computer](/tasks/look-at-a-computer/): its programs,
  connections, users and what ran recently, in one click each.
- [See what's running and who it talks to](/tasks/processes/).
- [Search the Windows event logs](/tasks/event-logs/) for an event ID, a
  user name or an IP address.

## Collecting evidence

- [Collect a file](/tasks/collect-a-file/), from one computer or from all
  of them.
- [Get the browser history](/tasks/browser-history/) and download history.
- [Capture memory](/tasks/memory/): one program's memory, or the whole
  computer's.
- [Download and share what you collected](/tasks/download-results/).

## Across many computers

- [Ask every computer the same question](/tasks/every-computer/).
- [Check a cloud account for a breach](/tasks/cloud-tenant/): Microsoft
  365, Google Workspace, Okta and AWS.

## Responding

- [Quarantine a computer](/tasks/quarantine/): cut it off the network but
  keep investigating it.
- [Kill a process or delete a file](/tasks/stop-a-threat/), on one
  computer or everywhere.

## Setting up

- [Add more computers](/tasks/add-computers/) with the installer.

## A word on collections

Every time you collect something from a computer, Atlantiraptor runs a
ready-made **collection** with a name like `Windows.System.Pslist`
("Windows, system, process list"). The one-click buttons pick the right
one for you. When you start a collection yourself you search for it by
name or description, and each how-to tells you which one to choose.
Collections have settings with sensible defaults; you only change the
ones a how-to mentions.

If a computer is switched off, what you asked for waits on the server and
runs when it next connects.
