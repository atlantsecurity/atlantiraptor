---
title: Response actions
description: Contain and remediate from the Atlantiraptor console - quarantine, DNS sinkhole, kill, delete, remove persistence, disable accounts - with dry runs, approvals and an audit trail.
---

The **Response** page runs remediation actions on one host or many: cut a
compromised machine off the network, kill a process everywhere, delete a
dropped file, remove a malicious service. Every action is a hunt of a
response artifact, so it reaches machines that are offline when they come
back, and every action is recorded in the audit log.

## Actions

| Group | Action | Platforms | Does |
|---|---|---|---|
| Containment | **Network quarantine** | Windows, Linux, macOS | Cuts the host off the network except for the Atlantiraptor server, so you can keep investigating. Optionally shows a message to the user. |
| Containment | **Lift quarantine** | Windows, Linux, macOS | Removes the quarantine firewall policy. |
| Containment | **DNS sinkhole** | Windows | Points malicious domains at a sinkhole address through the hosts file (backed up first). |
| Containment | **Restore hosts file** | Windows | Undoes a sinkhole from the backup. |
| Process | **Kill process** | Windows, Linux, macOS | Terminates processes whose name or path (and optionally command line) matches a regex. The agent itself is never killed. |
| File | **Delete file** | Windows, Linux, macOS | Deletes files matching a glob, optionally only with a given SHA256. Hosts with more matches than a limit you set are skipped. |
| Persistence | **Remove scheduled tasks** | Windows | Deletes tasks whose command and arguments match regexes. |
| Persistence | **Remove service** | Windows | Stops and deletes services whose name or binary path matches a regex. |
| Accounts | **Disable local user** | Windows | Disables local accounts whose name matches a regex. Domain accounts are not affected. |
| Accounts | **Re-enable local user** | Windows | Re-enables accounts disabled this way. |
| Agent | **Uninstall agent** | Windows, Debian, RedHat | Removes the agent; the host stops reporting for good. |

The same quarantine is available from the [host page](/clients/host/) and
from [alerts](/console/alerts/).

## Running an action

1. Open **Response** and pick an action.
2. Choose the **targets**:
   - one client, or several clients you search and add,
   - all clients with some labels,
   - all clients of one operating system.
3. Fill in the parameters (for example the process regex).
4. Leave **Dry run** on first. In a dry run hosts only report what they
   would change; nothing is modified.
5. Enter a **reason** (for example the case number or alert). It is
   recorded in the audit log, and required for live actions.
6. Review the summary and confirm.

The result from each host appears under **Recent response actions**. Open
one to see per-client results. When the dry run looks right, run it again
with dry run off.

A live action changes every targeted host as soon as it checks in, and it
cannot be undone from the console except where an undo action exists (lift
quarantine, restore hosts file, re-enable user). Hosts that enroll while
the hunt runs, and match the target, are included too.

## Who can run them

Response actions need the `responder` role (or `administrator`): they use
artifacts that require `EXECVE`, `FILESYSTEM_WRITE` or `NETWORK`
permissions, which hunters and investigators do not have. The server
enforces this; the console only hides what you cannot do.

## Approvals (four-eyes)

Administrators can require a second person to approve live response
actions: on the **Approvals** tab, turn on **Require a second person to
approve live response actions**. Then:

- A live action starts **paused**, waiting for approval. Dry runs are not
  affected.
- Another user with the right role opens **Response > Approvals**, reviews
  the action, targets, parameters and the requester's reason, and chooses
  **Approve and run** or **Reject**. The requester can **Withdraw** their
  own request.
- Nobody can approve their own request, including requests made with an
  API key they created.
- The approver sees exactly what will run: the server checks that the
  request was not changed after it was made (for example that a label still
  targets the same hosts).

Approvals can also be handled from a SIEM or SOAR with
`GET /api/atl/v1/approvals` and `POST /api/atl/v1/approvals/{id}/approve`.

## The audit trail

The **Audit** tab lists live and dry-run response actions of the last 30
days from the server audit log: who, when, which action, which targets,
with which reason and result. Turn on **With hunt state changes** to also
see hunts being started and stopped. The user is recorded by the server,
not by the browser.

## From a SIEM or SOAR

`GET /api/atl/v1/actions` lists the actions with their parameters, and
`POST /api/atl/v1/actions/{id}/run` runs one on a host, labels, an OS or
all hosts. API runs are dry runs unless you ask otherwise, and follow the
same approval policy. See [API keys and SIEM integration](/server-automation/api-keys/).
