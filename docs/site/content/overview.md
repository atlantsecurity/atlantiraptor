---
title: What is Atlantiraptor?
description: What Atlantiraptor does, the server and the agents, and what you can do with them.
---

Atlantiraptor is a tool for investigating and responding to security
incidents on your computers and in your cloud accounts. It answers
questions such as:

- Which of our laptops visited this phishing website yesterday?
- Is this suspicious program running anywhere else?
- What is this server talking to, and which program opened the connection?
- Did anyone sign in to our Microsoft 365 tenant from two countries within
  an hour, or add a mail forwarding rule?
- Give me the browser history, event logs and this one file from these
  five machines, now.

And it lets you act on the answer: cut a computer off the network, kill a
program everywhere it runs, or delete a file.

![A host page in the Atlantiraptor console](/images/host-triage.webp "Investigating one computer: triage findings, one-click collections, and the computer's system and connection details.")

## Two parts: a server and agents

```text
   Your computers (Windows, Linux, macOS)            Atlantiraptor server
 ┌──────────────────────────────┐   encrypted     ┌───────────────────────────┐
 │ Agent ── sends answers ──────┼───────────────▶ │ Keeps every answer        │
 │       ◀─ receives tasks ─────┼─────────────────┤ and file it receives      │
 └──────────────────────────────┘                 │                           │
   You ── web browser ──────────────────────────▶ │ The console (web page)    │
                                                  └───────────────────────────┘
```

- **The server** is installed once. It holds everything collected, and it
  serves the **console**, the web page you work in.
- **The agent** (also called the *client*) is a small program installed as
  a service on each computer. It connects to the server and waits for
  tasks: collect this, check that, quarantine this machine. It sends the
  answers back.
- The agent always connects **to** the server, never the other way round,
  so your computers need no open ports. All traffic is encrypted.
- If a computer is switched off, its tasks wait on the server and run as
  soon as it connects again.

The server and the agent are the same program, `Atlantiraptor.exe`,
started in different ways. To try them, see [Set up a test lab](/quickstart/).

## What you can do with it

| You want to | Read |
|---|---|
| Find which computers have seen a website, IP address, file, program or user | [Your first Rapid hunt](/first-hunt/) |
| Look at one computer: programs, connections, users, what ran recently | [Look at one computer](/tasks/look-at-a-computer/) |
| Collect a file, the browser history or a memory dump | [Everyday tasks](/tasks/) |
| Ask all computers the same question at once | [Ask every computer](/tasks/every-computer/) |
| Cut an infected computer off the network | [Quarantine a computer](/tasks/quarantine/) |
| Kill a program or delete a file on many computers | [Kill a process or delete a file](/tasks/stop-a-threat/) |
| Check a Microsoft 365, Google Workspace, Okta or AWS account for a breach | [Cloud accounts](/tasks/cloud-tenant/) |
| Get alerts when something suspicious happens | [Alerts](/console/alerts/) |
| Collect from computers that can't reach the server | [Offline collections](/offline/) |

## Where Atlantiraptor comes from

Atlantiraptor is developed by [Atlant Security](https://atlantsecurity.com).
It is based on [Velociraptor](https://github.com/Velocidex/velociraptor),
the open source endpoint visibility tool created by Mike Cohen and
developed by Velocidex (now part of Rapid7), and is published under the
same licence, the GNU Affero General Public License v3. Its source code is
on [GitHub](https://github.com/atlantsecurity/atlantiraptor).

Atlant Security adds a redesigned console, guided investigation, cloud
breach hunting, premium hunt feeds and signed automatic updates (see
[What's new in Atlantiraptor](/whats-new/)). Some names still show the
origin: the program calls itself `velociraptor` in command line help, and
many built-in collections keep their original names, so that existing
configurations and scripts keep working. Atlantiraptor is not affiliated
with or endorsed by Velocidex or Rapid7.

## Next step

[Set up a test lab](/quickstart/): a server and an agent running in ten
minutes.
