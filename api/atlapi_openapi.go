package api

// OpenAPI description of /api/atl/v1, served without authentication at
// /api/atl/v1/openapi.yaml so SIEM/SOAR tools can import it.

const atlOpenAPISpec = `openapi: 3.0.3
info:
  title: Atlantiraptor integration API
  version: "1.0"
  description: |
    REST API for SIEM and SOAR integration. Authenticate with an API key
    created under Admin > API keys:  Authorization: Bearer atl_...
    Each key holds roles (reader, analyst, investigator, hunter,
    responder, api) and is checked exactly like a console user with those
    roles. Requests are rate limited per key (HTTP 429 with Retry-After).
    Every write is recorded in the audit log under the principal api-<key id>.
servers:
  - url: /api/atl/v1
security:
  - bearer: []
components:
  securitySchemes:
    bearer:
      type: http
      scheme: bearer
  schemas:
    Error:
      type: object
      properties:
        error: {type: string}
    Target:
      type: object
      description: Exactly one of client_id, client_ids (up to 100), labels, os or all.
      properties:
        client_id: {type: string, example: C.f614264ea30165fa}
        client_ids: {type: array, maxItems: 100, items: {type: string}}
        labels: {type: array, items: {type: string}}
        exclude_labels: {type: array, items: {type: string}}
        os: {type: string, enum: [WINDOWS, LINUX, OSX]}
        all: {type: boolean}
    Action:
      type: object
      properties:
        id: {type: string, example: kill}
        kind: {type: string, enum: [response, triage]}
        group: {type: string}
        title: {type: string}
        description: {type: string}
        platforms: {type: string}
        artifacts: {type: array, items: {type: string}}
        fixed_parameters: {type: object, additionalProperties: {type: string}}
        parameters:
          type: array
          items:
            type: object
            properties:
              key: {type: string}
              label: {type: string}
              required: {type: boolean}
              default: {type: string}
        dry_run_parameter: {type: string, description: Present when the action supports a dry run.}
        changes_endpoints: {type: boolean}
    Started:
      type: object
      properties:
        data:
          type: object
          properties:
            client_id: {type: string}
            flow_id: {type: string}
            hunt_id: {type: string}
            state: {type: string, enum: [running, waiting_for_approval]}
            dry_run: {type: boolean}
            status_url: {type: string}
paths:
  /whoami:
    get:
      summary: The calling key, its roles and principal
      responses: {"200": {description: OK}, "401": {description: Bad key}}
  /actions:
    get:
      summary: Catalogue of response actions and quick-triage collections
      responses:
        "200":
          description: OK
          content:
            application/json:
              schema:
                type: object
                properties:
                  data: {type: array, items: {$ref: "#/components/schemas/Action"}}
  /actions/{id}:
    get:
      summary: One action
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}, "404": {description: Unknown action}}
  /actions/{id}/run:
    post:
      summary: Run an action against one host, labels, an OS or all hosts
      description: |
        Actions that support it run as a dry run unless dry_run is false.
        Live response actions need a reason. When the console requires
        two-person approval for response actions, live actions are created
        as paused hunts tagged approval:pending and wait for an approver in
        the console (state waiting_for_approval). The key needs the
        responder role (or the permissions the artifact requires).
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [target]
              properties:
                target: {$ref: "#/components/schemas/Target"}
                parameters: {type: object, additionalProperties: {type: string}}
                dry_run: {type: boolean, default: true}
                reason: {type: string}
      responses:
        "201": {description: Started, content: {application/json: {schema: {$ref: "#/components/schemas/Started"}}}}
        "400": {description: Invalid request}
        "403": {description: The key lacks permission}
  /alerts:
    get:
      summary: Detection alerts after a cursor
      description: |
        Poll with since set to the previous response's next_since. Rows are
        never split across a second, so a cursor never skips alerts.
      parameters:
        - {name: since, in: query, schema: {type: integer, description: Unix seconds; default 24 hours ago}}
        - {name: limit, in: query, schema: {type: integer, default: 500, maximum: 5000}}
      responses:
        "200":
          description: OK
          content:
            application/json:
              schema:
                type: object
                properties:
                  data: {type: array, items: {type: object}}
                  next_since: {type: integer}
                  count: {type: integer}
  /clients:
    get:
      summary: Endpoints (search syntax as in the console, e.g. host:web*, label:prod)
      parameters:
        - {name: q, in: query, schema: {type: string, default: all}}
        - {name: limit, in: query, schema: {type: integer}}
      responses: {"200": {description: OK}}
  /clients/{client_id}/flows:
    get:
      summary: Collections on one endpoint
      parameters: [{name: client_id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}}
  /clients/{client_id}/flows/{flow_id}:
    get:
      summary: Collection status
      parameters:
        - {name: client_id, in: path, required: true, schema: {type: string}}
        - {name: flow_id, in: path, required: true, schema: {type: string}}
      responses: {"200": {description: OK}, "404": {description: Not found}}
  /clients/{client_id}/flows/{flow_id}/results:
    get:
      summary: Rows a collection returned for one artifact (or artifact/source)
      parameters:
        - {name: client_id, in: path, required: true, schema: {type: string}}
        - {name: flow_id, in: path, required: true, schema: {type: string}}
        - {name: artifact, in: query, required: true, schema: {type: string}}
        - {name: limit, in: query, schema: {type: integer}}
      responses: {"200": {description: OK}}
  /collections:
    post:
      summary: Collect artifacts from one endpoint
      description: Artifacts that change endpoints (response artifacts, or ones needing EXECVE, FILESYSTEM_WRITE, NETWORK or MACHINE_STATE) are refused here with 403; run them through /actions/{id}/run.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [client_id, artifacts]
              properties:
                client_id: {type: string}
                artifacts: {type: array, items: {type: string}}
                parameters:
                  type: object
                  description: Per artifact, a map of parameter name to value.
                  additionalProperties: {type: object, additionalProperties: {type: string}}
      responses: {"201": {description: Started}}
  /hunts:
    get:
      summary: Hunts
      responses: {"200": {description: OK}}
    post:
      summary: Start a hunt across endpoints
      description: Artifacts that change endpoints are refused here with 403; run them through /actions/{id}/run.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [artifacts, target]
              properties:
                description: {type: string}
                artifacts: {type: array, items: {type: string}}
                parameters: {type: object}
                target: {$ref: "#/components/schemas/Target"}
                paused: {type: boolean}
      responses: {"201": {description: Started}}
  /hunts/{hunt_id}:
    get:
      summary: Hunt status
      parameters: [{name: hunt_id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}}
  /hunts/{hunt_id}/results:
    get:
      summary: Hunt results for one artifact
      parameters:
        - {name: hunt_id, in: path, required: true, schema: {type: string}}
        - {name: artifact, in: query, required: true, schema: {type: string}}
        - {name: limit, in: query, schema: {type: integer}}
      responses: {"200": {description: OK}}
  /ioc-sweeps:
    post:
      summary: Sweep endpoints for indicators (hashes, IPs, domains, paths, file names)
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [indicators, target]
              properties:
                indicators:
                  type: array
                  items:
                    type: object
                    properties:
                      type: {type: string, enum: [sha256, sha1, md5, ip, domain, path, filename]}
                      value: {type: string}
                      note: {type: string}
                target: {$ref: "#/components/schemas/Target"}
                hash_glob: {type: string}
                raise_alerts: {type: boolean, default: true}
      responses: {"201": {description: Started}}
  /artifacts:
    get:
      summary: Artifact definitions
      parameters:
        - {name: type, in: query, schema: {type: string, enum: [CLIENT, SERVER, CLIENT_EVENT, SERVER_EVENT]}}
        - {name: name, in: query, schema: {type: string}}
      responses: {"200": {description: OK}}
  /cases:
    get:
      summary: Investigation cases
      responses: {"200": {description: OK}}
  /cases/{case_id}:
    get:
      summary: One case
      parameters: [{name: case_id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: OK}}
`
