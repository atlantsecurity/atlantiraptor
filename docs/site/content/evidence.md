---
title: Exporting evidence
description: Export collections, hunts and notebooks from Atlantiraptor as zip archives, CSV or JSON, protect them with a password, and import collections from elsewhere.
---

Everything Atlantiraptor collects can be taken away: for a report, for
another tool (a SIEM, Timesketch, a spreadsheet), for legal hold, or for
another Atlantiraptor server.

## What you can export

| From | Export | Contains |
|---|---|---|
| A results table (anywhere) | **CSV** or **JSON** from the table's export menu | The rows of that table |
| A collection | **All files as zip** | Every result, the log and every uploaded file |
| A hunt | **Export hunt…**: **Full evidence** | Every client's collection with results, logs and files, plus combined results across clients |
| A hunt | **Export hunt…**: **Combined results only** | One table per artifact with rows from all clients; small and quick, without uploaded files |
| A notebook | **Export notebook** | An HTML report, or a zip with all the notebook's data |

For zips you choose the **Result formats** (JSON, CSV or both), and you can
**Password-protect the zip**.

Building a zip runs on the server; large ones take a while. You can keep
working, and the zip downloads when it is ready. Finished exports are
listed under the collection's, hunt's or notebook's **Exports** and kept
on the server until the collection, hunt or notebook is deleted.

## Password-protected zips

Antivirus on your workstation may delete malware samples inside an export,
or quarantine the whole zip. A password-protected zip stops that, because
the scanner cannot read inside it. The password is your
[downloads password](/console/preferences/#the-downloads-password), set in
your preferences (`infected` is the usual convention).

## The zip layout

A collection zip contains:

| Path | Contents |
|---|---|
| `results/<Artifact>.json` (or `.csv`) | One file per artifact source, one row per line |
| `uploads/<accessor>/<path>` | Files the collection uploaded, under their original path |
| `uploads.json` | The list of uploaded files with their original paths, sizes and hashes |
| `log.json` | The collection's log |
| `collection_context.json` | The request: artifacts, parameters, timestamps, who started it |
| `client_info.json` | The host the collection came from |

Hunt exports hold one such folder per client. This is the same format as
[offline collections](/offline/), so the same tools read both.

JSON results use one JSON object per line (JSONL), which most tools
(`jq`, Python, SIEM importers) read directly.

## Importing collections

A collection zip, from an offline collector or another Atlantiraptor or
Velociraptor server, can be imported so it shows up as a collection of a
client, with its results, files and notebook:

1. Copy the zip to the server (for example with `scp`).
2. Open **Server collections**, **Collect**, and pick
   `Server.Utils.ImportCollection`.
3. Set **Path** to the zip's path on the server. Leave **ClientId** as
   `auto` to create a new client, and set **Hostname** to the machine's
   name.

From VQL, the same is `import_collection(filename=..., hostname=...)`. See
[Importing offline collections](/offline/importing/).

## Sending results to other tools

- **Timesketch**: `Server.Utils.TimesketchUpload` sends timelines to a
  Timesketch server.
- **SIEMs and storage**: server event artifacts can forward results as they
  arrive (for example to Elastic, Splunk, a syslog server or S3). See
  [Integrations](/server-automation/integrations/).
- **Scripts**: the [REST API](/server-automation/api-keys/) returns results
  as JSON.

## Exporting with VQL

`create_flow_download()`, `create_hunt_download()` and
`create_notebook_download()` build the same zips from a notebook or server
artifact, which is handy for automation (for example: export every finished
collection of an artifact to a share). See the [VQL reference](/reference/vql/).
