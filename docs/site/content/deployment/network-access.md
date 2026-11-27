---
title: Network access
description: Restrict which IP addresses can use the Atlantiraptor console and its integration API.
---

**Admin > Network access** limits which addresses may use the web console,
its sign-in pages and its API, and, separately, the
[integration REST API](/server-automation/api-keys/) that SIEMs and scripts
use. Agents connect to the frontend on a different port and are not
affected.

Each list is off until you turn it on. When on, only the listed addresses
and ranges get an answer; everyone else is refused before they reach the
sign-in page.

## Setting up a list

1. Open **Admin > Network access**.
2. Turn on the list for the **console**, the **integration API**, or both.
3. Enter one address or range per line, IPv4 or IPv6:

   ```text
   10.0.0.0/8
   192.0.2.15
   2001:db8::/32
   ```

4. Save.

The page shows the address you are connecting from and whether the list
allows it. If saving would lock you out, it warns you and asks you to
confirm.

An empty list that is turned on allows only the server itself.

Individual [API keys](/server-automation/api-keys/) can have their own
address restrictions on top of the API list, for example the address of
your SIEM.

## Rules that always apply

- Requests from the server machine itself (loopback) are always allowed.
- The configuration setting `GUI.allowed_cidr` is applied first: if it is
  set, an address must be in it **and** in the list.
- Refused attempts are written to the [audit log](/deployment/logging/#the-audit-log),
  at most once a minute per address.

## Behind a reverse proxy

When the console is behind a proxy or load balancer, every request seems to
come from the proxy. Set `GUI.forwarded_proxy_header` (for example
`X-Forwarded-For`) in the server configuration so the server sees the real
client address; the page warns you when it detects this situation. Only do
this when the proxy is the only way to reach the console, since clients can
otherwise send the header themselves.

## If you lock yourself out

Either sign in from the server machine itself (for example with a browser
on the server, or an SSH tunnel to `127.0.0.1:8889`), or restart the server
with the environment variable `ATLANTIRAPTOR_DISABLE_ALLOWLIST=1`, which
turns every list off until it is removed.

## Other ways to limit exposure

Network access lists are one layer. Also consider:

- binding the console to an internal interface or localhost
  (`GUI.bind_address`) and reaching it over VPN or a reverse proxy,
- cloud firewall rules (security groups) for the console port,
- [single sign-on](/deployment/authentication/#single-sign-on) with your
  identity provider's conditional access policies.
