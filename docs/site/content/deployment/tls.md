---
title: TLS certificates
description: Self-signed, Let's Encrypt and custom certificates for the Atlantiraptor frontend and console, reverse proxies and certificate renewal.
---

Agents and browsers talk to the server over TLS. There are two layers:

- **TLS on the connection**, which every HTTPS client sees. Its
  certificate can be self-signed (by the server's own CA), issued by Let's
  Encrypt, or provided by you.
- **Message encryption inside the connection**, between each agent and
  the server, using the server key and each agent's own key. This is
  always present and does not depend on the TLS certificate. Even if the
  TLS layer were intercepted (for example by a corporate proxy), the
  agent's messages stay encrypted and authenticated.

## Self-signed certificates (default)

The wizard's default. The server's internal CA signs a certificate for the
frontend and the console, and agents accept only that CA
(`Client.use_self_signed_ssl: true`). Advantages: no external dependency,
works with an IP address or an internal name, and agents cannot be pointed
at an impostor by someone with a valid public certificate.

The only drawback is the browser warning on the console. Either accept it
once per browser, or install the CA certificate (`Client.ca_certificate`
in the configuration) in your browsers' trusted roots, or use a separate
certificate for the console behind a [reverse proxy](#behind-a-reverse-proxy-or-load-balancer).

## Let's Encrypt

Choose *Automatically provision certificates with Let's Encrypt* in the
wizard. The server then obtains a certificate for `Frontend.hostname` and
renews it by itself. Requirements:

- a public DNS name pointing to the server,
- port **80** reachable from the internet (for the HTTP challenge),
- the frontend and the console on port **443** (they share the port).

Certificates are cached in the directory set by `autocert_cert_cache`.
Agents then verify the server with the public certificate chain
(`use_self_signed_ssl: false`).

## Your own certificate

To use a certificate from your company CA or a commercial CA:

1. Put the certificate (with its chain) and key in files on the server.
2. Set in the server configuration:

   ```yaml
   Frontend:
     tls_certificate_filename: /etc/atlantiraptor/cert.pem
     tls_private_key_filename: /etc/atlantiraptor/cert.key
   Client:
     use_self_signed_ssl: false
   ```

3. If the issuing CA is not publicly trusted, add its certificate to
   `Client.Crypto.root_certs` so agents accept it.
4. Regenerate the client configuration (`config client`) and redeploy
   agents, since `use_self_signed_ssl` changed.

The certificate's name must match the host name in `Client.server_urls`.

## Behind a reverse proxy or load balancer

A reverse proxy (nginx, IIS, a cloud load balancer, Cloudflare) can sit in
front of the console to add single sign-on, a WAF, or a certificate your
browsers trust. Recommended setup:

- Bind the console to localhost (`GUI.bind_address: 127.0.0.1`) and let
  the proxy forward to it. Set `GUI.public_url` to the address users type.
- If the console is served under a path (for example
  `https://tools.example.com/atlantiraptor/`), set `GUI.base_path` to that
  path and `GUI.public_url` to the full URL ending in `/app/index.html`.
- Tell the server which header carries the real client address, so audit
  logs and [network access lists](/deployment/network-access/) see users'
  addresses instead of the proxy's: `GUI.forwarded_proxy_header`, for
  example `X-Forwarded-For`.
- Allow WebSockets and long-lived connections.

For the **frontend** (agents), prefer a TCP (layer 4) pass-through so the
agents' TLS reaches the server unchanged. If the proxy must terminate TLS,
set `Frontend.use_plain_http: true` so the server listens without TLS
behind it, use a public certificate on the proxy, and set
`use_self_signed_ssl: false` in the client configuration. The message
encryption between agent and server stays in place.

### Cloudflare Tunnel

A Cloudflare Tunnel publishes the server without opening inbound ports.
Run `cloudflared` on the server with an ingress rule to
`https://localhost:8000` (with `noTLSVerify: true` for the self-signed
certificate) for the frontend, and protect the console hostname with
Cloudflare Access. Agents then connect to the tunnel's hostname, which you
put in `Client.server_urls`, with `use_self_signed_ssl: false`.

## Renewing the internal certificates

The certificates issued by the internal CA (frontend and console, when
self-signed) are valid for one year. The server logs a warning as they near
expiry. Renew them with:

```sh
atlantiraptor --config server.config.yaml config reissue_certs > server.new.yaml
```

Replace the configuration with the new file and restart the server. Agents
keep connecting because they trust the CA, which does not change. The CA
itself is valid for ten years.

If the certificate already expired, agents cannot connect until you renew
it. Nothing is lost: they reconnect and deliver queued data afterwards.

## Checking a certificate

From an endpoint, check what the frontend presents:

```sh
curl -v https://atlantiraptor.example.com:8000/server.pem
```

With self-signed certificates add `-k` (or `--cacert ca.pem`). The command
prints the certificate's subject, issuer and validity, and the server's
public certificate as the response body.
