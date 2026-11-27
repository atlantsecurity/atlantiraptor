---
title: Tips and how-tos
description: Short answers to common Atlantiraptor questions - finding a file across the fleet, searching event logs, converting timestamps, hashing files and more.
---

Short recipes for things people often ask. Each links to the page with the
details.

## Find which machines have a file

For a file name or hash, use [Rapid hunt](/console/rapid-hunt/). For a
path pattern, hunt with `Windows.Search.FileFinder` and set **Glob**, for
example `C:\Users\*\AppData\**\invoice*.exe`. Add a YARA rule to match by
content. See [Hunting](/hunts/).

## Search Windows event logs for an event ID or text

Collect or hunt `Windows.EventLogs.EvtxHunter`. Set **IdRegex** to the
event IDs (`^(4624|4625)$`), **ChannelRegex** to the log (`Security`) and
**IocRegex** to text to look for in the event, such as a user name or IP
address. **DateAfter** and **DateBefore** limit the time range.

## Collect from a laptop that is switched off

Start the collection anyway. It waits on the server and runs when the
laptop next connects. A hunt also reaches machines that come online while
it is running. See [Collecting from a client](/clients/collections/).

## Compare a host before and after a change

Open the first collection and click **Collect again**. Both collections
keep their results, so you can compare them side by side, or join them in a
notebook.

## Stop a collection that is taking too long

Open it and click **Cancel**. Results already sent are kept. Next time, set
a **Timeout** or **CPU limit** in the collection's resources.

## Download malware safely

Use **Password-protected zip** so antivirus doesn't delete the sample on
your machine. The password is your
[downloads password](/console/preferences/#the-downloads-password).

## Label machines automatically

Create a label rule so that new clients get labels by host name, operating
system or other fields, and target hunts and monitoring at those labels. See
[Automatic labels](/clients/#automatic-labels).

## Find machines that stopped checking in

**Fleet health** lists agents that have been quiet for 7 to 30 days and for
over 30 days. See [Fleet health](/console/fleet-health/).

## Hash a file in VQL

```sql
SELECT OSPath, hash(path=OSPath).SHA256 AS SHA256
FROM glob(globs="C:/Windows/Temp/*.exe")
```

`hash()` returns MD5, SHA1 and SHA256 together.

## Convert timestamps

`timestamp()` turns most formats into a time:

| Value | VQL |
|---|---|
| Unix seconds | `timestamp(epoch=1700000000)` |
| Windows FILETIME | `timestamp(winfiletime=133000000000000000)` |
| A string | `timestamp(string="2024-05-01 10:00:00")` |

`now()` is the current time in Unix seconds, so `now() - 86400` is one day
ago. See [VQL fundamentals](/vql/fundamentals/).

## Make sizes readable

`humanize(bytes=Size)` turns `123456789` into `123 MB`.

## Run a query once and use its result many times

`LET X <= SELECT ...` (with `<=`) runs the query once and keeps the rows.
`LET X = SELECT ...` reruns it each time `X` is used. See
[VQL fundamentals](/vql/fundamentals/).

## See why a collection returned nothing

Open the collection's **Log** tab: it shows each query and any error. Then
see [Collections that return nothing](/troubleshooting/server/#collections-that-return-nothing).

## Check which version you run

The **Server updates** page shows the server's version and whether a newer
release is available. `atlantiraptor version` prints it on the command
line. See [Updating](/deployment/updates/).
