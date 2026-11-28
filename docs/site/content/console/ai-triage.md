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
- a [case](/console/cases/) ("Summarise this investigation case").

Before anything is sent, the dialog shows **what** will be sent and **to
whom** (the provider and model). The answer names the provider and model
that produced it. On a case, **Save as case note** adds the answer to the
case timeline.

## Setting it up (administrators)

AI triage is off until an administrator configures it under **Server settings >
Integrations > AI triage**:

1. Create an **HTTP Secrets** [secret](/secrets/) for the provider's API:
   the URL, method `POST`, and the API key in an extra header, for example
   `Authorization: Bearer <your key>` (OpenAI, DeepSeek) or the header the
   provider documents (Anthropic).
2. On the AI triage card, pick the **provider** (Anthropic Claude, OpenAI or
   DeepSeek), the **model**, and the **secret with the API key**.
3. Click **Test**: the server sends a short test request and shows the
   answer.
4. Save.

Requests go from the server, not from analysts' browsers, so the API key
never reaches them and the server's proxy settings apply.

## Data protection

The data sent includes host names, user names, file paths, command lines
and other details from your endpoints. Before enabling AI triage:

- check that your agreement with the provider allows this data (for
  example a zero-retention or enterprise agreement),
- consider which organizations it is used in; for customer data, get the
  customer's consent.

Only server administrators can change the settings.
