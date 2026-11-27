---
title: Cases
description: Track an investigation in Atlantiraptor from first alert to closure, with linked hosts, hunts, collections, alerts and indicators, and a timeline of notes.
---

A **case** keeps everything about one investigation in one place: what
happened, how bad it is, which hosts and indicators are involved, what was
collected, and what the team decided along the way.

## Creating a case

Open **Cases** and click **New case**, with a title, a severity and an
optional summary. Or create one on the fly from anywhere you see
**Add to case…**: an alert, a Rapid hunt match, a hunt, a collection, a
results row, or a value's pivot menu.

## What a case holds

- **Title, status and severity.** Status is *Open*, *In progress* or
  *Closed*; severity is *critical*, *high*, *medium* or *low*.
- **Summary**: what happened, the scope and the current assessment. Keep it
  up to date; it is what someone new to the case reads first.
- **Links**: hosts (clients), hunts, collections, alerts, indicators and
  individual result rows. Each link opens the item; the case records who
  added it and when.
- **Timeline**: notes and every change to the case (status, severity,
  links), newest first. Add notes for findings, decisions and next steps.

## Working a case

- Filter the case list by status, severity or text.
- Add notes as you go. Notes from [AI triage](/console/ai-triage/) can be
  saved into the case with **Save as case note**.
- From a linked host, start triage or a response action; then link the
  resulting collection back to the case.
- When the investigation ends, set the status to **Closed**.

## Reporting

**Export report** downloads a self-contained HTML report: the summary,
status and severity, every link with who added it, and the full timeline.
Attach it to your ticket or send it to the customer.

## How cases are stored

Each case is a notebook, visible to everyone in the organization who can
read notebooks. The case's own notebook (**Open notebook**) is the place for
deeper analysis with VQL cells next to the case. Because cases live in the
organization, every analyst sees the same case and timeline.

## From the API

`GET /api/atl/v1/cases` lists cases, for example to mirror them into a
ticketing system. See the [REST API reference](/reference/api/).
