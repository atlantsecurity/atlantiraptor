---
title: Running the server in Docker
description: Build and run an Atlantiraptor server container with Docker Compose.
---

The `Docker/` folder of the repository contains everything needed to run
the server in a Linux container: a small Alpine image, an entry point that
creates a configuration on first start, and a Compose file. Atlant Security
does not publish a container image, so you build it from a Linux binary.

## Build the image

1. [Build a Linux binary](/deployment/server/#building-from-source) of the
   release you want and copy it to `Docker/bin/velociraptor`.
2. Build the image:

   ```sh
   cd Docker
   docker build -t atlantiraptor-server .
   ```

3. In `compose.yaml`, set `image:` to `atlantiraptor-server` (the file in
   the repository still names the upstream image).

## Configure and start

Compose reads its settings from a `.env` file next to `compose.yaml`:

```ini
VELOCIRAPTOR_HOSTNAME=atlantiraptor.example.com
VELOCIRAPTOR_FRONTEND_PORT=8000
VELOCIRAPTOR_GUI_PORT=8889
VELOCIRAPTOR_DATASTORE_PATH=/datastore
VELOCIRAPTOR_CONFIG_PATH=/etc/velociraptor
VELOCIRAPTOR_INITIAL_ADMIN_PASSWORD=change-me-now
```

Then start it:

```sh
docker compose up -d
docker compose logs -f
```

On the first start, the entry point:

- generates a server configuration with self-signed certificates for
  `VELOCIRAPTOR_HOSTNAME` and stores it in `./etc/` (mounted at
  `/etc/velociraptor/`),
- keeps all data in `./datastore/` (mounted at `/datastore/`), so it
  survives container restarts and upgrades,
- creates an `admin` user with the initial password from `.env`,
- builds agent packages (MSI, Debian and RPM) with this server's
  configuration, which you can then download from the server.

Sign in at `https://<host>:8889/`, change the password at once and set up
[two-factor sign in](/deployment/authentication/#two-factor-sign-in).

## Use an existing configuration

To run an existing deployment in a container, put its
`server.config.yaml` into `./etc/` before the first start and match the
ports in `.env` to the configuration. The entry point uses the file as is.

## Upgrade

Build a new image from the new binary, then:

```sh
docker compose down
docker compose up -d
```

The configuration and data stay in the mounted folders.

## Things to keep in mind

- **Back up `./etc/`.** It holds the CA and server keys. Agents can only
  talk to a server with the same keys.
- The container's port mapping and `Frontend.hostname` must match what
  agents use: if you publish the frontend on port 443, regenerate or edit
  the configuration so the agents' `server_urls` use 443 too.
- Automatic [server updates](/deployment/updates/) only install on Windows.
  Containers are upgraded by rebuilding the image.
- For certificates other than self-signed, see [TLS certificates](/deployment/tls/).
