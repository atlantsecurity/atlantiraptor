---
title: Server logging and audit
description: Atlantiraptor server log files, the audit log of user actions, and forwarding logs to syslog or a SIEM.
---

## Log files

The server writes its log to the directory in `Logging.output_directory`.
With `separate_logs_per_component: true` (the wizard's default) each
component gets its own files, which makes it easier to find things:

| Component | What it logs |
|---|---|
| Frontend | Agent connections, enrollment, communication errors |
| GUI | Web console and API: requests, sign in, errors |
| Tool | Tool downloads and the tool inventory |
| Audit | User actions (see below) |
| General | Everything else: startup, services, hunts, artifacts |

Each component has separate files per level (`debug`, `info`, `error`),
rotated every `rotation_time` seconds and deleted after `max_age` seconds
(one year by default). Disable a level you don't need with `disabled: true`
under it.

When you run the server in a terminal, add `-v` to print the log to the
screen as well. A Linux service writes to the journal too:
`journalctl -u velociraptor_server`.

## The audit log

Every significant action by a person or an API key is written to the audit
log, with who did it, when, from which address and with which parameters:

- signing in and out, failed sign ins, two-factor changes,
- starting, stopping and deleting collections and hunts,
- creating or editing artifacts, notebooks and cases,
- response actions and approvals,
- user and role changes, organization changes,
- server settings: updates, network access, API keys, integrations, the
  hunt feed licence,
- requests refused by network access lists.

Actions by API keys are recorded under the principal `api-<key id>`.

### Reading it in the console

The audit events also go to the `Server.Audit.Logs` server event artifact.
Open **Server events**, pick `Server.Audit.Logs` and a day to browse and
filter them, or query them in a notebook:

```sql
SELECT * FROM source(artifact="Server.Audit.Logs",
                     start_time=now() - 7 * 86400)
WHERE operation =~ "hunt"
```

**Response > Audit** shows the response actions of the last 30 days in a
friendlier form.

### Forwarding the audit log

To keep the audit log outside the server, where an administrator cannot
change it:

- **Syslog**: set `Logging.remote_syslog_server` (for example
  `siem.example.com:514`), `remote_syslog_protocol` (`udp` or `tcp`) and,
  optionally, `remote_syslog_components`. By default only audit events are
  forwarded.
- **SIEM integrations**: forward `Server.Audit.Logs` with a server event
  artifact (for example to Splunk or Elastic, see
  [Integrations](/server-automation/integrations/)).

## Collection logs

Each collection and hunt also has its own log: open a collection and choose
its **Log** tab. These show what the agent did while running the query:
which files it read, errors, how long it took. They are the first place to
look when a collection returns nothing; see
[Collection and hunt problems](/troubleshooting/server/#collections-that-return-nothing).

## Debugging

For very detailed logs, start the server with `--debug` and `-v`, or enable
the debug level in the configuration. The [debug server](/troubleshooting/debugging/)
shows the internal state of the server live.
