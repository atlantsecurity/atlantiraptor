---
title: Tour of the console
description: The Atlantiraptor web console - sidebar, top bar, command palette, pivots, themes, phones and the classic view.
---

The console is where analysts and administrators work. Open
`https://<your server>:8889/` (or the address your administrator gave you)
and sign in.

## Layout

**The sidebar** on the left groups pages by task. Collapse it with the
arrow at its bottom to get more room.

| Section | Pages |
|---|---|
| **Investigate** | [Dashboard](/console/dashboard/), [Hunts](/hunts/), [Response](/console/response/), [Cases](/console/cases/), [IOC sweep](/console/ioc-sweep/), [Hunt feeds](/hunts/feeds/), [Clients](/clients/), [Notebooks](/notebooks/) |
| **Client** (appears once you pick a client) | [Overview](/clients/host/), [Files](/clients/files/), [Collections](/clients/collections/), [Client events](/clients/monitoring/) |
| **Server** | [Fleet health](/console/fleet-health/), [Artifacts](/artifacts/managing/), Server collections, Server events |
| **Admin** (administrators) | [Users](/users/), [Groups](/users/#groups), [Security and 2FA](/deployment/authentication/#two-factor-sign-in), [Secrets](/secrets/), [Integrations](/server-automation/integrations/), [API keys](/server-automation/api-keys/), [Network access](/deployment/network-access/), [Server updates](/deployment/updates/) |
| **Links** | Extra links configured in `GUI.links`, such as this documentation |

What you see depends on your [roles](/users/): pages you cannot use are
hidden or read-only.

**The top bar** has:

- the **client search** box: type a host name, `label:`, `ip:` or a client
  ID (see [Finding clients](/clients/#searching-for-clients)),
- **notifications** of finished collections, exports and hunts,
- the **documentation search** (**?** icon), which searches these pages
  from inside the console,
- the **account menu**: switch organization, settings, password and
  two-factor sign in, light or dark theme, keyboard shortcuts and sign out.

## The command palette

Press <kbd>Ctrl</kbd>+<kbd>K</kbd> (<kbd>⌘</kbd>+<kbd>K</kbd> on a Mac)
anywhere. Type to jump to any page, client, hunt, case or notebook.

![Command palette with an indicator](/images/command-palette-indicator.webp "Pasting an indicator into the command palette offers a Rapid hunt or an IOC sweep for it.")

Paste an **IP address, domain, URL, hash or file path** and the palette
offers **Hunt for this indicator**, which starts a [Rapid hunt](/console/rapid-hunt/)
for it. Paste several indicators at once and it offers an
[IOC sweep](/console/ioc-sweep/).

## Pivoting from results

Every results table in the console works the same way:

- Click a column header to sort, and use the filter box to show only
  matching rows.
- Hover over a value and open its menu to **pivot**. Depending on what the
  value is (a user, process, IP address, domain, hash or path), the menu
  offers:
  - **Rapid hunt this**: which other machines have seen it,
  - **IOC sweep for it**,
  - **Filter rows to this value**,
  - **Find this client**,
  - **Add indicator to a case** or **Add this row to a case**,
  - **Look up on VirusTotal**,
  - **Copy**.

![Pivot menu on a result value](/images/pivot-menu.webp "Clicking a value in a results table offers filters, Rapid hunt, IOC sweep and adding it to a case.")

Large result sets load in pages; scroll to the end to load the rest, or use
the server-side search where a page offers it, so filters see every row.

## Light and dark

The console follows a light theme by default. Switch to dark in the account
menu. **Settings…** has more themes, the display time zone and language.
See [Preferences](/console/preferences/).

![Dashboard in the dark theme](/images/dashboard-dark.webp "The dashboard in the dark theme.")

## On a phone

The console works on phones and tablets: the sidebar becomes a menu, tables
scroll sideways, and the dashboard, alerts, Rapid hunt and host pages are
laid out for a narrow screen. This is handy for checking an alert or
quarantining a host when you are away from your desk.

![Dashboard on a phone](/images/phone-dashboard.webp "The dashboard on a phone.")

## The classic view

A few advanced screens from the original Velociraptor interface are still
available, under `/classic` and through **Open in classic view** links (for
example in notebooks and on event pages). They use the older style but work
with the same data.

## Links into the console

Console URLs are stable and include the organization, so you can paste them
into a ticket or chat:

| Page | URL |
|---|---|
| A host | `/app/index.html#/host/C.1a2b3c4d5e6f7a8b` |
| A collection | `/app/index.html#/collected/C.1a2b3c4d5e6f7a8b/F.CT2Q8M1J5G1OE` |
| A hunt | `/app/index.html#/hunts/H.CT2QA0L3P7JBE` |
| A notebook | `/app/index.html#/notebooks/N.CT2QB4F2B1LS8` |

Add `?org_id=<org>` before the `#` for organizations other than root.
