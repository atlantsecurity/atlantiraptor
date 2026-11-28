---
title: Security advisories
description: Vulnerabilities fixed in Atlantiraptor, their severity and the release that fixes them, with an RSS feed your server follows.
---

This page lists the security vulnerabilities fixed in Atlantiraptor. Most
of them were found in code that Atlantiraptor shares with the open source
Velociraptor project; Atlant Security merges those fixes and lists them
here once they are in an Atlantiraptor release.

## Am I affected? {#am-i-affected}

Check your version with `atlantiraptor version`, or on **Server settings > Server
updates**. If it is the same as or newer than **Fixed in**, the advisory
does not affect you. Every advisory below is fixed in Atlantiraptor 1.0.0
and later.

The fastest way to stay safe is to leave
[automatic server updates](/deployment/updates/) turned on. Agents are
upgraded from the server; see [Updating](/deployment/updates/).

## Notices in the console {#notices}

Your server checks this page's feed,
`https://atlantsecurity.github.io/atlantiraptor/security/advisories/index.xml`,
every 10 minutes (the `Server.Monitoring.RSSFeeds` server monitoring
artifact). When a new advisory is published, every console user gets one
notice with its title and a link here. Change the feed, the interval or
which users are notified in the artifact's parameters on **Server
events**.

To report a vulnerability, see
[Reporting a vulnerability](/security/#reporting-a-vulnerability).
