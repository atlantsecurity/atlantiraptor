---
title: The gRPC API
description: Full programmatic access to Atlantiraptor with VQL over the gRPC API, using certificate-authenticated API client configurations.
---

The **gRPC API** gives programs the same power as the console: they send
VQL queries to the server and stream back the results. Anything a server
artifact or notebook can do, an API client can do. It is meant for
automation you build and trust, such as a SOAR integration that needs
more than the [REST API](/server-automation/api-keys/) offers, or a
pipeline that pulls monitoring data continuously.

## How it works

- The API listens on its own port, **8001** by default
  (`API.bind_address` and `API.bind_port`). It binds to `127.0.0.1` by
  default, so only programs on the server can reach it; set
  `bind_address: 0.0.0.0` (and firewall it) to allow others.
- Clients authenticate with a **certificate** issued by the server's CA.
  There are no passwords or API keys.
- Each API client is a user with roles, like a console user. The `api`
  role lets it connect; add roles for what it may do.

## Creating an API client

On the server:

```bash
atlantiraptor --config server.config.yaml config api_client \
    --name siem-automation --role reader,api api.config.yaml
```

`api.config.yaml` holds the client's certificate, private key, the CA
certificate and the API address (`API.hostname`). Keep it as secret as a
password: whoever has it can use the API with those roles.

To change its roles later:

```bash
atlantiraptor --config server.config.yaml acl grant siem-automation \
    '{"roles": ["reader", "investigator", "api"]}'
```

Revoke access by removing all its roles, on **Users** or with `acl grant`.
API client certificates expire after `security.certificate_validity_days`
(a year by default).

## Querying from the command line

Any Atlantiraptor binary can use an API client configuration:

```bash
atlantiraptor --api_config api.config.yaml query \
    "SELECT client_id, os_info.hostname AS Host FROM clients() LIMIT 5"
```

The query runs **on the server**, with the API client's permissions.

## Querying from Python

The API is defined by protocol buffers in `api/proto/api.proto` in the
[repository](https://github.com/atlantsecurity/atlantiraptor). The
`Query` call takes VQL and streams back responses; generate a client for
your language with the gRPC tools, or use an existing Velociraptor
Python client library, which is compatible.

```python
import grpc, json, yaml
import api_pb2, api_pb2_grpc   # generated from api/proto/api.proto

config = yaml.safe_load(open("api.config.yaml"))
creds = grpc.ssl_channel_credentials(
    root_certificates=config["ca_certificate"].encode(),
    private_key=config["client_private_key"].encode(),
    certificate_chain=config["client_cert"].encode())
options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)

with grpc.secure_channel(config["api_connection_string"], creds, options) as channel:
    stub = api_pb2_grpc.APIStub(channel)
    request = api_pb2.VQLCollectorArgs(Query=[api_pb2.VQLRequest(
        VQL="SELECT * FROM info()")])
    for response in stub.Query(request):
        if response.Response:
            for row in json.loads(response.Response):
                print(row)
```

## Following events

A query that uses `watch_monitoring()` never ends: the API streams each
new row as it arrives. That is the simplest way to feed Atlantiraptor's
alerts or monitoring data into another system in real time:

```bash
atlantiraptor --api_config api.config.yaml query \
    "SELECT * FROM watch_monitoring(artifact='Server.Internal.Alerts')"
```

## Security

- Prefer the REST API with a narrowly scoped key for integrations; use the
  gRPC API when you need VQL.
- Give each API client its own name and only the roles it needs.
- All API queries are logged, and changes are in the
  [audit log](/deployment/logging/#the-audit-log).
