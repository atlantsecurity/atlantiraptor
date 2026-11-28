---
title: AI triage
description: Get a summary of an alert, collection or case from Claude, OpenAI or DeepSeek, using your own API key.
---

AI triage sends the data you are looking at to a large language model and
shows its summary: what the alert or collection suggests, what looks
suspicious, and what to check next. It is a second opinion, not a verdict:
the model can be wrong, so check its findings against the data.

## Where you find it

An **AI triage** button appears on:

- an [alert](/console/alerts/) ("Triage this security alert"),
- a [collection](/clients/collections/) ("Triage the results of this
  collection"),
- a host's **Full triage** panel, which sends the flagged rows, the
  indicators the console found and the process command lines rather than
  every raw row, and asks for a verdict and a list of indicators of
  compromise,
- a [case](/console/cases/) ("Summarise this investigation case").

Before anything is sent, the dialog shows **what** will be sent and **to
whom** (the provider and model). At most 60,000 characters leave the
server per request. The answer names the provider and model that produced
it. On a case, **Save as case note** adds the answer to the case timeline.

## Setting it up (administrators)

AI triage is off until an administrator configures it under **Server settings >
Integrations > AI triage**:

1. Pick the **provider** (Claude is the default; OpenAI and DeepSeek also
   work) and the **model** (`claude-opus-5-5` by default).
2. Paste the provider's **API key** and click **Save**.
3. Click **Test**: the server sends a short test request and shows the
   answer.

The key is stored encrypted as a server [secret](/secrets/) named
`atl-ai-<provider>` and is never shown again; paste a new one to replace
it. Every user who can run AI triage can use the key without seeing it.
Requests go from the server, not from analysts' browsers, so the server's
proxy settings apply.

If you set AI triage up earlier with an **HTTP Secrets** secret of your
own, it keeps working; paste the key on the card to switch to the managed
one.

## Data protection

The data sent includes host names, user names, file paths, command lines
and other details from your endpoints. Before enabling AI triage:

- check that your agreement with the provider allows this data (for
  example a zero-retention or enterprise agreement),
- consider which organizations it is used in; for customer data, get the
  customer's consent.

Only server administrators can change the settings.
