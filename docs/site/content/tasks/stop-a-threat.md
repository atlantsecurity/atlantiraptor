---
title: Kill a process or delete a file
description: Stop a malicious program, delete a dropped file, remove a malicious service or scheduled task, or disable an account, on one computer or many.
---

The **Response** page fixes things on one computer or many at once. Every
action is recorded with who did it, when and why.

You need the `responder` or `administrator` role.

## Kill a program

1. Open **Response** in the sidebar and choose **Kill process**.
2. Under **Process name or path**, type the program's name, for example
   `(?i)^evil\.exe$`. (`(?i)` ignores upper and lower case, `^` and `$`
   mean "exactly this name", and the dot needs a `\`.)
3. Choose the computers: search and add them, or pick a label, an
   operating system or all of them.
4. Leave **Dry run** on. Type a **reason**, such as the case number, and
   confirm.
5. Under **Recent response actions**, open the action to see which
   computers found the program. If that is what you expected, run it again
   with **Dry run** off.

The Atlantiraptor agent itself is never killed.

## Delete a file

Choose **Delete file** and set **File glob** to the file's path, for
example `C:\Users\*\AppData\Local\Temp\evil.exe` (`*` matches any user).
Add its **SHA256** to delete only that exact file, and keep the limit
that skips a computer with more matches than expected. Then dry run,
check, and run, as above.

Collect a copy of the file first if you might need it as evidence (see
[Collect a file](/tasks/collect-a-file/)).

## Other actions

| Action | Use it to |
|---|---|
| **Remove service** | Stop and delete a malicious Windows service |
| **Remove scheduled tasks** | Delete malicious Windows scheduled tasks |
| **Disable local user** | Lock a local Windows account an attacker created or stole |
| **DNS sinkhole** | Stop Windows computers from reaching malicious domains |
| **Network quarantine** | [Cut computers off the network](/tasks/quarantine/) |

Most of them have an undo action next to them. All of them, with
approvals by a second person, are described in
[Response actions](/console/response/).
