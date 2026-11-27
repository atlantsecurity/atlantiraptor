---
title: Scaling out
description: Serve very large fleets with several Atlantiraptor frontends sharing one datastore.
---

A single Atlantiraptor server comfortably handles thousands of endpoints.
Scale up first: more CPU cores, more memory and faster disks go a long way,
and one server is simpler to run, back up and update. When one machine is
not enough (typically beyond 15,000 to 20,000 connected agents, or when
agents need to connect to servers in several regions), run several
frontends.

## How it works

In a multi-frontend deployment:

- One **master** frontend runs the console, the APIs, hunts, notebooks
  and all server artifacts, and also serves agents.
- One or more **minion** frontends only serve agents: they receive their
  results and write them to the shared storage.
- All of them share the **same filestore**, for example an NFS export or
  Amazon EFS, and the same configuration (same CA, same keys).
- Agents are spread over the frontends: either `Client.server_urls` lists
  every frontend (agents pick one and fail over), or a load balancer puts
  them behind one name.

The master uses an in-memory cache in front of the shared files
(`Datastore.master_implementation: MemcacheFileDataStore`) and the minions
send their datastore operations to the master
(`minion_implementation: RemoteFileDataStore`). Minions talk to the master
over its gRPC API port.

## Setting it up

1. Put the datastore on shared storage that every frontend mounts at the
   same path, with low latency between them.
2. Start from a working single-server configuration. Make sure the API
   port (`API.bind_address`, default `127.0.0.1:8001`) is reachable from the
   minions: bind it to the internal interface.
3. Copy the same configuration to each frontend machine. Change
   `Client.server_urls` to include every frontend's URL (or the load
   balancer's), and regenerate the client configuration.
4. Start the master normally: `atlantiraptor --config server.config.yaml frontend`.
5. Start each minion with `--minion`:

   ```sh
   atlantiraptor --config server.config.yaml frontend --minion
   ```

The Linux packages accept `--minion`-style variants too (`debian server`
names them *master* and *minion*).

## Load balancers

Agents keep long-lived connections. If you put a load balancer in front of
the frontends:

- use TCP (layer 4) pass-through, not TLS termination, unless you follow
  the steps in [TLS certificates](/deployment/tls/#behind-a-reverse-proxy-or-load-balancer),
- keep idle timeouts long (several minutes),
- do not use session stickiness by cookie; agents reconnect and that is
  fine.

## Things to know

- Server artifacts, the console and notebooks always run on the master.
  Size it larger than the minions.
- All frontends must run the same version. Upgrade them together.
- [Automatic updates](/deployment/updates/) are meant for single servers;
  upgrade multi-frontend deployments by hand.
- Monitor every frontend (see [Performance and sizing](/deployment/performance/#monitoring-the-server)).
