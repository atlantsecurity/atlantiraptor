---
title: Dashboard
description: The Atlantiraptor dashboard - clients, hunts, failures, server health, Rapid hunt and the alert queue.
---

The dashboard is the first page after sign in. It answers "is everything
working, and is anything happening?" at a glance.

![The dashboard](/images/dashboard.webp "The dashboard: Rapid hunt, open alerts, connected clients, running hunts and recently seen hosts.")

## What it shows

- **Connected clients**: agents seen in the last 15 minutes, out of all
  enrolled clients. Click to open the client list.
- **Running hunts**: hunts that are collecting right now.
- **Failed hunt collections**: clients that returned errors in hunts from
  the last 7 days. A sudden rise usually means an artifact problem or
  endpoints with too little disk or memory. Click to see which hunts.
- **Alerts**: the number of open critical and high alerts.
- **Rapid hunt**: a box to ask the whole fleet about one indicator. See
  [Rapid hunt](/console/rapid-hunt/).
- **Alerts panel**: the alert queue. See [Alerts](/console/alerts/).
- **Recently seen**: the clients that checked in most recently. Click one
  to open its [host page](/clients/host/).
- **Recent server collections**: the latest server artifacts run, such as
  cloud hunts and maintenance tasks.
- **Server health**: CPU, memory and connected clients over the last hours,
  sampled by the `Server.Monitor.Health` server event artifact. If the
  charts are empty, that artifact is not running; enable it under **Server
  events**.

The dashboard refreshes by itself. Everything on it links to the page with
details.

## A morning routine

1. Look at the open alerts: acknowledge what you will handle, close or mark
   false positives.
2. Check failed hunt collections and fleet health for agents that went
   quiet.
3. Paste any new indicators from threat intelligence into Rapid hunt or an
   IOC sweep.
