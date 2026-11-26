// Integration examples shown on the API keys page. {BASE} is replaced
// with this server's API URL.

export interface Example { id: string; title: string; blurb: string; lang: string; code: string }

export const EXAMPLES: Example[] = [
  {
    id: 'curl', title: 'curl', lang: 'bash',
    blurb: 'Check the key, list response actions, then run one as a dry run.',
    code: `export ATL=atl_xxxxxxxx   # your key
curl -s -H "Authorization: Bearer $ATL" {BASE}/whoami
curl -s -H "Authorization: Bearer $ATL" {BASE}/actions

# Kill a process on one host. Dry run unless "dry_run": false.
curl -s -X POST -H "Authorization: Bearer $ATL" -H "Content-Type: application/json" \\
  {BASE}/actions/kill/run -d '{
    "target": {"client_id": "C.f614264ea30165fa"},
    "parameters": {"ProcessRegex": "evil\\\\.exe"},
    "dry_run": false,
    "reason": "INC-1234 malware beacon"
  }'`,
  },
  {
    id: 'splunk', title: 'Splunk', lang: 'python',
    blurb: 'Pull alerts into Splunk with a scripted or modular input (HEC push is also available under Integrations).',
    code: `# Splunk scripted input: prints one JSON event per alert.
import json, os, requests
BASE = "{BASE}"
KEY = os.environ["ATL_API_KEY"]
STATE = os.path.join(os.path.dirname(__file__), "atl_since")
since = int(open(STATE).read()) if os.path.exists(STATE) else 0
r = requests.get(f"{BASE}/alerts", params={"since": since, "limit": 1000},
                 headers={"Authorization": f"Bearer {KEY}"}, timeout=30)
r.raise_for_status()
body = r.json()
for alert in body["data"]:
    print(json.dumps(alert))
open(STATE, "w").write(str(body["next_since"]))

# props.conf: [atlantiraptor:alert]  KV_MODE = json
# Alert action: call {BASE}/actions/quarantine/run with the client_id field.`,
  },
  {
    id: 'elastic', title: 'Elastic', lang: 'yaml',
    blurb: 'Filebeat httpjson input polls alerts with a cursor.',
    code: `filebeat.inputs:
  - type: httpjson
    interval: 1m
    request.url: {BASE}/alerts
    request.transforms:
      - set:
          target: header.Authorization
          value: "Bearer \${ATL_API_KEY}"
      - set:
          target: url.params.since
          value: "[[.cursor.since]]"
          default: "0"
    response.split:
      target: body.data
    cursor:
      since:
        value: "[[.last_response.body.next_since]]"
    processors:
      - decode_json_fields: {fields: [message], target: atl}`,
  },
  {
    id: 'sentinel', title: 'Microsoft Sentinel', lang: 'json',
    blurb: 'Codeless connector (RestApiPoller) for alerts; a Logic App HTTP action runs response actions.',
    code: `{
  "kind": "RestApiPoller",
  "properties": {
    "dataType": "Atlantiraptor_Alerts_CL",
    "auth": { "type": "APIKey", "ApiKeyName": "Authorization", "ApiKeyIdentifier": "Bearer" },
    "request": {
      "apiEndpoint": "{BASE}/alerts",
      "httpMethod": "GET",
      "queryWindowInMin": 5,
      "queryTimeFormat": "UnixTimestamp",
      "startTimeAttributeName": "since"
    },
    "response": { "eventsJsonPaths": ["$.data"] }
  }
}

// Logic App action (playbook) to isolate the host from an incident entity:
// HTTP POST {BASE}/actions/quarantine/run
// Headers: Authorization: Bearer @{parameters('AtlKey')}
// Body: {"target":{"client_id":"@{triggerBody()?['client_id']}"},"reason":"Sentinel incident @{triggerBody()?['IncidentNumber']}"}`,
  },
  {
    id: 'soar', title: 'SOAR playbook', lang: 'python',
    blurb: 'Generic SOAR step (XSOAR, Tines, Shuffle, Swimlane): triage, then isolate if the analyst approves.',
    code: `import os, time, requests
BASE, KEY = "{BASE}", os.environ["ATL_API_KEY"]
H = {"Authorization": f"Bearer {KEY}"}

def run(action, target, **kw):
    r = requests.post(f"{BASE}/actions/{action}/run", headers=H, timeout=30,
                      json={"target": target, **kw})
    r.raise_for_status()
    return r.json()["data"]

def wait_flow(client_id, flow_id, timeout=600):
    end = time.time() + timeout
    while time.time() < end:
        f = requests.get(f"{BASE}/clients/{client_id}/flows/{flow_id}", headers=H, timeout=30).json()["data"]
        if f["state"] in ("FINISHED", "ERROR"):
            return f
        time.sleep(10)

host = {"client_id": incident["client_id"]}
triage = run("triage-processes", host)
wait_flow(host["client_id"], triage["flow_id"])
procs = requests.get(f"{BASE}/clients/{host['client_id']}/flows/{triage['flow_id']}/results",
                     params={"artifact": "Windows.System.Pslist"}, headers=H).json()["data"]

if analyst_approves(procs):
    res = run("quarantine", host, reason=f"SOAR case {incident['id']}")
    # res["state"] == "waiting_for_approval" when two-person approval is on.`,
  },
  {
    id: 'rapid', title: 'Rapid hunt', lang: 'python',
    blurb: 'Ask the fleet who visited a domain, URL or IP, then act on every machine that did.',
    code: `import os, time, requests
BASE, H = "{BASE}", {"Authorization": f"Bearer {os.environ['ATL_API_KEY']}"}

hunt = requests.post(f"{BASE}/rapid-hunts", headers=H, timeout=30,
                     json={"indicator": "evil.example", "days_back": 30}).json()["data"]

# Results arrive as machines answer; poll until enough have reported.
for _ in range(30):
    r = requests.get(f"{BASE}/rapid-hunts/{hunt['hunt_id']}", headers=H, timeout=30).json()["data"]
    p = r["progress"]
    if p["scheduled"] and p["with_results"] + p["with_errors"] >= p["scheduled"]:
        break
    time.sleep(10)

for m in r["machines"]:
    print(m["hostname"], m["client_id"], m["sources"], m["users"], m["hit_count"])

# Quarantine all of them at once (held for approval if your policy requires it).
ids = [m["client_id"] for m in r["machines"]]
if ids:
    requests.post(f"{BASE}/actions/quarantine/run", headers=H, timeout=30,
                  json={"target": {"client_ids": ids}, "reason": "Visited evil.example"})`,
  },
  {
    id: 'approve', title: 'Approvals', lang: 'bash',
    blurb: 'Show pending live actions in the SIEM and approve them there. The requester can never approve their own.',
    code: `curl -s -H "Authorization: Bearer $ATL" {BASE}/approvals
curl -s -X POST -H "Authorization: Bearer $ATL" "{BASE}/approvals/H.XXXXXXXX/approve?reason=Checked+by+SOC+lead"
curl -s -X POST -H "Authorization: Bearer $ATL" {BASE}/approvals/H.XXXXXXXX/reject`,
  },
  {
    id: 'ioc', title: 'IOC sweep', lang: 'bash',
    blurb: 'Push threat intel indicators to every Windows host; matches raise alerts you can poll.',
    code: `curl -s -X POST -H "Authorization: Bearer $ATL" -H "Content-Type: application/json" \\
  {BASE}/ioc-sweeps -d '{
    "target": {"os": "WINDOWS"},
    "indicators": [
      {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "note": "TI feed"},
      {"type": "domain", "value": "evil.example"},
      {"type": "ip", "value": "203.0.113.7"}
    ]
  }'`,
  },
];
