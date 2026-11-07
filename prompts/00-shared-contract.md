# VortexAI — Shared Contract (paste this with EVERY module prompt)

VortexAI is a HackRPI 2026 ("In The Clouds") project: an AI cloud-security system with three
independent agents running on top of a shared environment platform. The agents never call each other
directly. They only share the data shapes and interfaces below.

| Module | Role | Origin it covers | Owner |
|---|---|---|---|
| **Searcher** | Scans randomized cloud configuration files and flags security risks | Internal (mistakes by people with access) | Vaibhav |
| **Attacker** | Simulates attacks on a clone of the simulated cloud at varying security levels | External (outsiders forcing their way in) | Vaibhav |
| **Builder** | Reads both modules' findings, diagnoses weak points, recommends countermeasures to the admin | Both | Vaibhav |
| **Environment platform** | Generates the simulated cloud and its clones, stores all data, hosts the API app and the dashboard shell with the 3D traffic overview | — | Alex |

Everything is **simulated**. There is no real cloud account, no real network traffic, and no real exploit code.

---

## 1. Threat taxonomy (from the team's research doc — use these IDs everywhere)

| `category` | Name | Origin | `technique` IDs |
|---|---|---|---|
| 1 | Identity & Credential Abuse | E | `leaked_key_abuse`, `password_spray`, `oidc_trust_abuse` |
| 2 | Infrastructure Misconfigurations | I | `public_bucket`, `overpermissive_iam`, `open_port` |
| 3 | Supply Chain & Third-Party | E | `vulnerable_integration`, `poisoned_image` |
| 4 | Cloud-Native Architecture | I | `container_escape`, `serverless_abuse` |
| 5 | Control Plane & API Hijacking | E | `living_off_the_cloud`, `cryptojacking` |

The Searcher finds the *preconditions* (an internal mistake). The Attacker *exploits* them.
Example: Searcher flags `overpermissive_iam` on `role-ci`. Attacker escalates through `role-ci`.
Builder links the two by `resource_id`.

---

## 2. Simulated environment (`Environment`)

Produced by `vortex/shared/generator.py::generate_environment(seed: int, level: str) -> Environment`.
`level` is one of `"hardened" | "default" | "sloppy"`. The same `seed` with a different `level` must
produce the **same resources** (same IDs and names) with **different security settings**. That is what
"a clone at varying degrees of security" means.

```jsonc
{
  "env_id": "env-42-sloppy",
  "seed": 42,
  "security_level": "sloppy",
  "identities": {
    "users": [{ "id": "user-ana", "mfa": false, "password_strength": "weak", "reused_password": true,
                "access_keys": [{ "id": "key-01", "age_days": 400, "exposed_publicly": true }],
                "role_ids": ["role-dev"] }],
    "service_accounts": [{ "id": "sa-ci", "role_ids": ["role-ci"] }]
  },
  "roles": [{ "id": "role-ci",
              "policies": [{ "actions": ["*"], "resources": ["*"] }],
              "trust": { "type": "oidc", "subject": "repo:acme/*" } }],
  "storage_buckets": [{ "id": "bkt-customers", "public_read": true, "public_write": false,
                        "encrypted": false, "data_class": "pii" }],
  "network": { "security_groups": [{ "id": "sg-db",
                "rules": [{ "port": 5432, "protocol": "tcp", "source_cidr": "0.0.0.0/0" }] }] },
  "compute": {
    "instances":  [{ "id": "vm-api", "sg_ids": ["sg-db"], "role_id": "role-dev", "public_ip": true }],
    "containers": [{ "id": "ctr-web", "image": "webapp", "tag": "latest", "registry": "dockerhub-unverified",
                     "signed": false, "privileged": true, "host_mounts": ["/var/run/docker.sock"], "role_id": "role-dev" }],
    "functions":  [{ "id": "fn-resize", "role_id": "role-ci", "max_concurrency": null, "public_trigger": true }]
  },
  "integrations": [{ "id": "int-crm", "vendor": "AcmeCRM", "scopes": ["*"], "version_outdated": true }],
  "controls": { "logging": true, "alerting": false, "rate_limiting": false, "budget_alerts": false,
                "egress_filtering": false, "image_signing_required": false },
  "_ground_truth": [{ "technique": "public_bucket", "resource_id": "bkt-customers" }]
}
```

Rules:
- `_ground_truth` lists every weakness the generator injected. Only the scoring code may read it
  (to measure Searcher precision/recall). **Searcher and Attacker detection logic must never read it.**
- Approximate weakness odds per resource: hardened about 5%, default about 30%, sloppy about 70%.
- Deterministic: all randomness comes from `random.Random(seed)`.
- About 15–30 resources per environment, which is readable in a demo.

---

## 3. Finding (the only thing Builder consumes)

```jsonc
{
  "id": "f-3c9a",                 // unique
  "source": "searcher",           // "searcher" | "attacker"
  "origin": "internal",           // "internal" | "external"
  "category": 2,                  // 1–5 from the taxonomy
  "technique": "overpermissive_iam",
  "resource_id": "role-ci",       // MUST match an ID in the Environment
  "env_id": "env-42-sloppy",
  "severity": "critical",         // "critical" | "high" | "medium" | "low"
  "title": "CI role grants *:* on all resources",
  "evidence": { "path": "roles[3].policies[0]", "value": { "actions": ["*"], "resources": ["*"] } },
  "exploited": null,              // Attacker sets true/false; Searcher leaves null
  "detected": null,               // Attacker: was the step caught by logging/alerting? Searcher: null
  "attack_run_id": null           // Attacker: which run produced this
}
```

---

## 4. Repo layout and API

```
vortex/
  shared/   schema.py, generator.py, store.py      # Alex: environment platform
  llm.py    one OpenAI wrapper used by every agent  # Vaibhav
  searcher/ rules.py, scan.py, router.py, __main__.py              # Vaibhav
  attacker/ techniques.py, engine.py, planner.py, router.py, __main__.py   # Vaibhav
  builder/  correlate.py, playbook.py, advisor.py, router.py       # Vaibhav
  api/      main.py: FastAPI app, environment and findings routes, mounts each agent's router  # Alex
web/
  src/App.tsx, layout, 3D traffic overview          # Alex
  src/panels/SearcherPanel.tsx, AttackerPanel.tsx, BuilderPanel.tsx   # Vaibhav
data/       JSON output (environments/, findings/, runs/, diagnoses/), no database
tests/fixtures/env-42-{hardened,default,sloppy}.json   # hand-written, so agents can start before the platform lands
```

**Platform interface** (Alex implements it in `vortex/shared/`; the agents import only these):
```python
generate_environment(seed: int, level: str) -> Environment
get_environment(env_id: str) -> Environment
save_environment(env: Environment) -> None            # used by Builder for patched clones
save_findings(env_id: str, source: str, findings: list[Finding]) -> None
list_findings(env_id: str) -> list[Finding]
save_attack_run(run: AttackRun) -> None
list_attack_runs(env_id: str) -> list[AttackRun]
```
`AttackRun` steps carry `target` resource IDs and a step index, so the platform's 3D view can replay an
attack as traffic between resources.

| Method | Route | Owner | Returns |
|---|---|---|---|
| POST | `/api/environments` `{seed, level}` | Platform | `Environment` |
| GET | `/api/environments/{env_id}` | Platform | `Environment` |
| POST | `/api/searcher/scan` `{env_id}` | Searcher | `{findings: Finding[], score: {precision, recall}}` |
| POST | `/api/attacker/campaign` `{seed, levels[], runs_per_level}` **or** `{env_ids[], runs_per_level}` | Attacker | `{runs: AttackRun[], findings: Finding[], summary}` |
| GET | `/api/findings?env_id=` | Platform | `Finding[]` (all sources) |
| POST | `/api/builder/diagnose` `{env_id}` | Builder | `Diagnosis` |
| POST | `/api/builder/apply` `{env_id, fix_ids[]}` | Builder | `ApplyResult` (before/after) |

**Stack:** Python 3.12+, FastAPI, Pydantic v2, pytest. Frontend: React 18 + Vite + TypeScript + TailwindCSS.
**AI:** OpenAI API through the official `openai` Python SDK (team's OpenAI plan). Read the key from
`OPENAI_API_KEY` and the model ID from `OPENAI_MODEL`; never hard-code either. All modules call the model
through one wrapper, `vortex/llm.py`. Every AI call needs a deterministic fallback so the demo works
with no API key and survives a refusal or timeout.
