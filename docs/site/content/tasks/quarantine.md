---
title: Quarantine a computer
description: Cut a compromised computer off the network, except for Atlantiraptor, so you can keep investigating it, and lift the quarantine afterwards.
---

Quarantine stops a compromised computer from spreading the infection or
sending data out, while **keeping its connection to Atlantiraptor**, so you
can go on investigating it. It works on Windows, Linux and macOS.

You need the `responder` or `administrator` role.

## One computer

1. Open the computer's [host page](/tasks/look-at-a-computer/).
2. Open the **⋯** menu and choose **Quarantine host…**.
3. Optionally type a message to show to the user, such as "This computer
   has been isolated by the security team. Please call 555-0100."
4. Confirm.

Within seconds the computer can only talk to the Atlantiraptor server. The
host page shows it as quarantined, and it gets the `Quarantine` label, so
you can find all quarantined computers by that label.

If the computer is switched off, the quarantine happens as soon as it
connects.

## Lift the quarantine

On the host page, open the **⋯** menu and choose **Lift quarantine**. The
computer's network goes back to normal.

## Many computers at once

1. Open **Response** in the sidebar and choose **Network quarantine**.
2. Choose the computers: search and add them, or pick a label or an
   operating system.
3. Leave **Dry run** on the first time: the computers only report what
   they would do.
4. Type a **reason**, such as the case number. It is kept in the audit
   log.
5. Confirm. When the dry run looks right, run it again with **Dry run**
   off.

From a [Rapid hunt](/first-hunt/) result, **Respond to this machine** opens
this page with the matching computers already selected.

## Before you quarantine

If the attacker's program is still running, consider
[capturing its memory](/tasks/memory/) first, and note what it is
connected to (see [See what's running](/tasks/processes/)).

More in [Response actions](/console/response/).
