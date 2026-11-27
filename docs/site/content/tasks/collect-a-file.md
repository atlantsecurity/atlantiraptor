---
title: Collect a file
description: Download a file from a computer, collect files that match a name or pattern, or collect them from every computer at once.
---

## A file you know the path of

1. Open the computer's [host page](/tasks/look-at-a-computer/) and click
   **Files**.
2. Open the drive (on Windows, `file` then `C:`; on Linux and macOS,
   `file` then `/`) and click through the folders. If a folder looks
   empty or old, click **List this folder from the client** to fetch it
   fresh.
3. Select the file and click **Collect from the client**.
4. When the download finishes, the file's details show its hashes and a
   link to download it to your own computer.

![Browsing files on a computer](/images/file-browser.webp "Browsing a computer's folders: each file with its size and timestamps.")

Files that Windows keeps locked, such as registry hives or an open
database, can still be collected: switch the view from `file` to `auto`
(or `ntfs`) and collect the file from there.

> **Malware?** Set a [downloads password](/console/preferences/#the-downloads-password)
> first. Zips you download are then password-protected, so your antivirus
> doesn't delete the sample on your computer. See
> [Download and share what you collected](/tasks/download-results/).

## Files that match a name or pattern

When you know the file's name but not its folder, or want all files of a
kind:

1. On the host page, click **Collect**.
2. Search for `FileFinder` and select `Windows.Search.FileFinder` (on
   Linux, `Linux.Search.FileFinder`; on macOS, `MacOS.Search.FileFinder`).
3. Click it to open its settings and set:
   - **Glob**: the pattern to look for. `*` matches any name inside one
     folder, `**` matches any number of folders. For example
     `C:\Users\*\Downloads\*.exe` (programs in anyone's Downloads), or
     `C:\Users\**\invoice*.pdf`.
   - **Upload_File**: turn it on to collect the files, not just list them.
   - **Calculate_Hash** (optional): turn it on to get each file's hashes.
4. Click **Collect now**.

The result lists every file found with its size and times, and the files
themselves are on the collection's **Files** tab.

## From every computer

Do the same as a hunt: open **Hunts**, click **New hunt**, select
`Windows.Search.FileFinder`, set **Glob** and **Upload_File**, and click
**Create and start hunt**. Every computer collects its matching files, and
the hunt keeps them all. Be careful with broad patterns: a hundred
computers times a thousand files adds up quickly.

To find out only *which* computers have a file, a
[Rapid hunt](/first-hunt/) for its name or hash is faster and collects
nothing.
