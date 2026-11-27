---
title: Sigma
description: Match Sigma detection rules against Windows event logs and other sources with Atlantiraptor's sigma() plugin, as a hunt or continuously.
---

[Sigma](https://github.com/SigmaHQ/sigma) is an open format for detection
rules over log events. Atlantiraptor evaluates Sigma rules natively with
the `sigma()` plugin, on the endpoint, so only matches travel to the
server.

## Ready-made artifacts

| Artifact | Does |
|---|---|
| `Windows.Detection.SigmaMonitor` | A client event artifact: matches new events in the Security, System, PowerShell, Defender and Sysmon logs as they are written, and raises an [alert](/console/alerts/) for each match |
| `Windows.Sigma.EventLogs` | A collection: matches rules against the event logs already on disk (good for hunting back in time) |
| `Notebooks.Sigma.Studio` | A notebook for writing and testing rules against sample events |

`Windows.Detection.SigmaMonitor` comes with a small set of high-signal
rules (log cleared, new services, and others). Add your own to its
`SigmaRules` parameter, separated by lines of `---`. The larger community
rule sets can be imported with `Server.Import.Extras`.

## How sigma() works

A Sigma rule names a **log source** (such as `product: windows`,
`service: security`) and **detection** conditions on event fields. The
plugin needs to know:

1. where each log source's events come from: `sigma_log_sources()` maps
   log source names to VQL queries,
2. how rule field names map to event fields: `field_mapping`, a dict of
   field name to a lambda that reads it from the event.

```sql
LET LogSources <= sigma_log_sources(
  `*/windows/security`={
     SELECT * FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Security.evtx") },
  `*/windows/system`={
     SELECT * FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/System.evtx") })

LET FieldMapping <= dict(
  EventID="x=>x.System.EventID.Value",
  ServiceName="x=>x.EventData.ServiceName",
  ImagePath="x=>x.EventData.ImagePath")

SELECT _Rule.Title AS Rule, _Rule.Level AS Level,
       System.TimeCreated.SystemTime AS Time, EventData
FROM sigma(rules=split(string=Rules, sep_string="\n---\n"),
           log_sources=LogSources, field_mapping=FieldMapping)
```

Log source names are `category/product/service`, with `*` for any part.
Each match is the original event with a `_Rule` column describing the
rule that matched.

Using `watch_evtx()` instead of `parse_evtx()` in the log sources turns the
same rules into a monitor, which is what `Windows.Detection.SigmaMonitor`
does.

`Windows.Sigma.EventLogs` exports a standard field mapping
(`StandardSigmaFieldMapping`) covering common Windows and Sysmon fields.
Import that artifact into yours to reuse it.

## Extensions

Atlantiraptor's Sigma support adds a few fields to the rule format, all
VQL lambdas:

- `vql`: builds or enriches every event before matching,
- `enrichment`: adds context to a match after it is made,
- the `vql` modifier on a detection field (`Field|vql: x=>...`) for
  conditions the standard modifiers can't express.

## Writing and testing rules

1. Open a notebook from `Notebooks.Sigma.Studio`, pick the base type
   (Windows, Linux, or their event versions).
2. Paste rules and run them against sample events. With `Debug`, every
   rule is reported with what did or didn't match.
3. When a rule works, add it to the monitor's `SigmaRules`, or to your own
   artifact.
