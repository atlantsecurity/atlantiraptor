---
title: Offline collections
description: Collect evidence from machines without an Atlantiraptor agent using a self-contained offline collector.
---

Sometimes you can't install an agent: the machine is off the network, it
belongs to a third party, or you need evidence before any software is
deployed. An **offline collector** is a single program, built on your
server, that runs a fixed set of artifacts on the machine it is started on
and writes the results to a zip file (or uploads them to cloud storage).

It runs the same artifacts as the agent and produces the same zip format as
a collection export, so the results can be imported into the server and
analysed like any other collection.

## The workflow

1. **[Build](/offline/building/)** a collector on the server: pick the
   target OS, the artifacts and their parameters, how to protect the
   output, and where to send it.
2. **[Run](/offline/running/)** it on the machine, as an administrator: by
   hand, from a USB stick, by a remote admin tool, or by a colleague on site.
3. **[Import](/offline/importing/)** the results into the server and
   analyse them in a notebook.

## When to use it

| Situation | Use |
|---|---|
| Machines with an agent | A normal [collection](/clients/collections/) or [hunt](/hunts/) |
| A machine you can't install on, or an air-gapped network | An offline collector |
| Incident response for a customer that has no agent yet | An offline collector first, agents later |
| A disk image or a mounted disk | [Dead disk analysis](/forensics/deaddisk/) |

## Things to know

- The collector contains the artifacts as they were when you built it.
  Build a new one after changing artifacts.
- It needs administrator (root) rights for most forensic artifacts.
- Protect the output: evidence often contains passwords, hashes and
  personal data. Use encryption with your server's certificate (the
  default) so only your server can open it.
