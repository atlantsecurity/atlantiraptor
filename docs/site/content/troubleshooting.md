---
title: Troubleshooting
description: Find and fix common Atlantiraptor problems - agents not connecting, collections returning nothing, server performance, VQL errors.
---

Start with the symptom:

| Symptom | Look at |
|---|---|
| A host doesn't appear, or shows as offline | [Agent problems](/troubleshooting/clients/) |
| A collection or hunt returns nothing, or fails | [Collections that return nothing](/troubleshooting/server/#collections-that-return-nothing) |
| The console is slow, or the server uses too much CPU, memory or disk | [Server problems](/troubleshooting/server/) |
| A query gives an error, or not the rows you expected | [VQL problems](/troubleshooting/vql/) |
| An agent uses too much CPU or memory | [Agent problems](/troubleshooting/clients/#an-agent-uses-too-much-cpu-or-memory) |
| You need profiles and traces for a bug report | [Debugging](/troubleshooting/debugging/) |
| You can't sign in | [Authentication](/deployment/authentication/#every-administrator-lost-their-factor) and [Network access](/deployment/network-access/#if-you-lock-yourself-out) |

## The first things to check

1. **Logs.** A collection's **Log** tab, the server log (see
   [Logging](/deployment/logging/)), or the agent run in a terminal with
   `-v`. Almost every problem is explained there.
2. **Versions.** The server's version (**Server updates**) and the agent's
   (on the host page). Very old agents may not understand new artifacts.
3. **Time.** Certificates and collection timestamps depend on correct
   clocks on the server and the endpoints.
4. **Network.** Can the endpoint reach the server's frontend address and
   port (8000 by default)? Is a proxy or TLS inspection in the way?

If you are stuck, see [Getting help](/support/) for what to include in a
question.
