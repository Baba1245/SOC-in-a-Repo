# Lab infrastructure

Infrastructure-as-code for a single-node Wazuh + Sysmon detection lab. This is
the environment where the compiled detections are *deployed and validated* — the
Python pipeline (compile / simulate-validate / coverage / triage / evaluate)
runs with no infrastructure at all, but the real detections run here.

## Topology

```
 Windows endpoint                      Docker host (laptop-sized)
┌───────────────────┐                ┌──────────────────────────────┐
│ Sysmon (EID 1)    │                │ wazuh.indexer  (:9200)        │
│  → Wazuh agent    │── 1514/tcp ───▶│ wazuh.manager  (:1514/:55000) │
│                   │                │ wazuh.dashboard(:5601)        │
└───────────────────┘                └──────────────────────────────┘
```

## Bring it up

```bash
cd infra
cp .env.example .env          # then change every password
docker compose up -d
docker compose ps             # wait for wazuh.indexer -> healthy
# Dashboard: https://localhost:5601  (admin / $INDEXER_PASSWORD)
```

Requirements: Docker + Compose v2, ~4 GB RAM free, and on Linux
`sysctl -w vm.max_map_count=262144` for the indexer.

## Deploy the detections

`socrepo compile` writes `config/wazuh/local_rules.xml`. The manager service
bind-mounts that file to `/var/ossec/etc/rules/local_rules.xml`, so the deploy
loop is:

```bash
socrepo compile                       # regenerate from detections/sigma/*.yml
docker compose restart wazuh.manager  # manager reloads the ruleset
```

Also merge `config/wazuh/ossec.conf.snippet.xml` into the manager's
`ossec.conf` (once), and on the endpoint add
`config/wazuh/agent.ossec.conf.snippet.xml` so the Sysmon channel is forwarded.

## Endpoint setup (Windows)

```powershell
# 1. Install Sysmon with the lab config
sysmon64.exe -accepteula -i config\sysmon\sysmonconfig.xml

# 2. Install the Wazuh agent, point it at the manager, enrol, start
#    (see Wazuh docs for the agent MSI + agent-auth enrollment)

# 3. Forward the Sysmon channel (agent.ossec.conf.snippet.xml)
```

## Validate against Atomic Red Team

On the endpoint, run atomics for the techniques in
`data/mappings/attack_scope.yaml` (GUIDs are pinned there for reproducibility),
confirm the corresponding `100200`–`100207` rules fire in the dashboard, then
record results. The offline pipeline models this same match with
`socrepo validate` so CI can prove the loop without a live endpoint.

> **Safety.** Live atomic execution in `socrepo` is double-gated (`--live` flag
> **and** `SOCREPO_ALLOW_LIVE_ATOMICS=1`) and only runs on Windows. Never point
> this lab at anything but a disposable VM you own.
