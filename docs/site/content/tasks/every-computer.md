---
title: Ask every computer the same question
description: Run a collection on all computers, or on a group of them, with a hunt, and read all the answers in one table.
---

A **hunt** runs the same collection on many computers and gathers all the
answers in one place. Computers that are switched off answer when they
come back, for as long as the hunt runs.

For one quick question (has anyone seen this website, file or program?)
use [Rapid hunt](/first-hunt/) instead. Use a hunt when you want the same
information from everyone: all running programs, all files in a folder,
all browser history.

## Start a hunt

1. Open **Hunts** in the sidebar and click **New hunt**.
2. On the left, search for what to collect and select it. For example
   `Windows.System.Pslist` for running programs. The how-tos in this
   section name the right one for each job.
3. Click it on the right to change its settings, if the how-to says so.
4. Choose the computers:
   - **All clients**,
   - **By label**: only computers with a label, such as `servers` or
     `finance` (see [Labels](/clients/#labels)),
   - only one operating system.
5. Check when the hunt ends: by default after one hour. Set a later end
   time if some computers are often switched off, so they still answer.
6. Click **Create and start hunt**.

![The New hunt dialog](/images/new-hunt.webp "Starting a hunt: pick what to collect on the left, then choose the computers.")

## Read the answers

Open the hunt from the **Hunts** list. Its page shows how many computers
have answered, and:

- **Results**: every answer in one table, with the computer's name on each
  row. Filter, sort, and click values to hunt for them.
- **Clients**: which computers have answered, and any errors.

![Hunt results](/images/hunt-results.webp "A hunt's results from all computers in one table.")

To download everything, see
[Download and share what you collected](/tasks/download-results/).

## Stop a hunt

Click **Stop** on the hunt's page. Answers already received are kept.

All the options, such as limits and scheduling, are in [Hunts](/hunts/).
