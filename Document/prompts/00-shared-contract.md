# VortexAI — Shared Contract v2 (paste this with EVERY agent prompt)

VortexAI (HackRPI 2026, "In The Clouds") is a local, in-memory cloud simulation with a 3D traffic view.
**Alex's platform is the source of truth**: it owns the virtual cloud, enforces policies, emits events, and
renders the UI. **Vaibhav's agents** (Attacker, Searcher, Builder) add Claude Opus 5.5 reasoning on top. They
only *read observations* and *submit proposals*. The platform validates and executes everything.

Read `README.md` and `docs/ARCHITECTURE.md` before starting. This contract summarizes them; if they disagree,
the code in `src/simulation.mjs` wins.

## 1. Ownership

| Area | Files | Owner |
|---|---|---|
| Platform: simulation engine, policies, scenarios, rule-based detection | `src/simulation.mjs` | Alex |
| HTTP server, clock, static assets | `server.mjs` | Alex |
| Frontend: 3D map, dashboard | `public/` | Alex |
| Platform tests | `test/simulation.test.mjs`, `test/server.test.mjs` | Alex |
| Claude client wrapper | `src/agents/claude.mjs` | Vaibhav |
| AI agents | `src/agents/attacker.mjs`, `searcher.mjs`, `builder.mjs` | Vaibhav |
| Agent HTTP routes | `src/agents/router.mjs` | Vaibhav |
| Agent tests | `test/agents/*.test.mjs` | Vaibhav |

Don't edit files you don't own. If you need a change in someone else's file, write the exact change as a
request in the team's chat.

## 2. The platform as built (do not redesign)

- **Nodes:** `client`, `attacker`, `gateway`, `lb`, `app`, `iam`, `db`, `storage`, `logs`. Each has a label,
  zone, 3D position and description.
- **Policies** (all `false` at reset = vulnerable): `storagePrivate`, `requireMfa`, `databaseLeastPrivilege`.
  Each maps to a remediation in `REMEDIATIONS` with a title, description and tradeoff.
- **Scenarios:** `exposed-storage`, `credential-abuse`, `lateral-movement`. Each is a fixed list of steps; one
  step runs per tick.
- **Event:** `{ id, tick, time, source, target, protocol, action, outcome, bytes, kind, principal,
  authenticated, authentication?, control?, detail }`.
  - `kind` (normal / attack / blocked) is simulator ground truth for the visuals only.
  - **Agents must never see `kind`.**
- **Finding:** `{ id, title, severity, nodeId, policyKey, evidence[], evidenceDetails[], status, recommendationId, firstSeenTick }`.
- **Recommendation:** `{ id, findingId, title, description, tradeoff, policyKey, applied, validation }`.
- **The loop:** a scenario runs → rules in `_observe` create a finding → Builder recommendation → the admin
  clicks apply (`POST /api/recommendation`) → replay is blocked → recommendation `validation: 'blocked-replay'`.
- **Server:**
  - binds to loopback only, with Host/Origin checks and 4 KiB JSON bodies
  - `requestTimeout` is 10 s
  - the UI polls `GET /api/state`, which returns `simulation.snapshot()`

The existing rule-based detection and remediation text stay in place as the **fallback**. When Claude is
unavailable, the app behaves exactly as it does today.

## 3. Agent hooks Alex adds to `Simulation` (small, about 80 lines)

| Method | Does | Validation the platform performs |
|---|---|---|
| `observations({ sinceTick = 0, limit = 80 })` | Returns recent events **without `kind`**, newest first | Read-only copies |
| `actionCatalog()` | Returns the allowlisted atomic attack actions: `{ id, source, target, action, protocol, principal, authentication?, gatedBy?, requires?, description }` | Static list |
| `runPlan({ objective, steps: [actionId], rationale: [string] })` | Queues an AI attack plan like a scenario, one step per tick; `activeScenario.source = 'ai-attacker'` | Every step ID is in the catalog; 1–8 steps; no active scenario; `requires` (such as an admin session) is checked at run time |
| `submitFinding({ title, severity, nodeId, policyKey, evidenceIds, explanation, origin })` | Adds or merges an AI finding (`detectedBy: 'ai'`) | `nodeId` exists; every evidence ID exists and is `allowed`; `severity` ∈ critical/high/medium/low; `policyKey` ∈ `REMEDIATIONS` keys or `null`; `origin` ∈ internal/external; strings ≤ 400 chars; dedupe by `policyKey` (or by `nodeId` + title when null) |
| `submitRecommendation({ findingId, policyKey, rationale, tradeoff, limits, priority })` | Attaches Claude's text to the recommendation as `ai: {...}` | `findingId` exists; `policyKey` ∈ `REMEDIATIONS`; strings ≤ 600 chars; never applies anything |
| `setAgentStatus(agent, { status, detail, mode })` | Updates `snapshot().agents[agent]`; `mode` ∈ ai/rules | `agent` ∈ attacker/searcher/builder |

The initial `actionCatalog()` is exactly the atomic steps already inside the three scenarios:

| id | What it models | gatedBy / requires |
|---|---|---|
| `discover` | attacker → gateway discovery | — |
| `storage-list-anon` | anonymous `list-objects` on storage | gatedBy `storagePrivate` |
| `storage-read-anon` | anonymous `read-object` on storage | gatedBy `storagePrivate` |
| `password-guess` | failed password sign-in at `iam` | always denied |
| `stolen-password-signin` | password sign-in at `iam` | gatedBy `requireMfa`; creates an admin session |
| `admin-request` | admin request to `app` | requires an admin session from this plan |
| `token-replay` | stolen low-privilege token at gateway | scenario assumption |
| `app-flaw-request` | request that invokes the service identity | requires `token-replay` earlier in the plan |
| `db-admin-export` | `admin-export` on `db` by `app-service` | gatedBy `databaseLeastPrivilege` |
| `exfil-response` | export data back to attacker | requires a successful `db-admin-export` |

The catalog can grow later, for example with new nodes and policies for the doc's other threat types.
The agents just read whatever `actionCatalog()` returns.

## 4. Agent HTTP routes (Vaibhav's `router.mjs`; Alex mounts it in `server.mjs`)

Same security rules as Alex's server:
- JSON only, at most 4 KiB, and an exact field allowlist
- **no free text from the browser**; only enum values and existing IDs

Claude calls take longer than the server's 10 s timeout, so every route **starts a job and returns 202
immediately**. Progress and results show up in `GET /api/state`, which the UI already polls.

| Method | Route | Body | Returns |
|---|---|---|---|
| POST | `/api/agents/attacker/plan` | `{ objective }`, one of `data-exfiltration`, `account-takeover`, `privilege-escalation`, `surprise-me` | 202 `{ jobId }`; 409 if a scenario or plan is active or the attacker is busy |
| POST | `/api/agents/searcher/sweep` | `{}` | 202 `{ jobId }`; 409 if the searcher is busy |
| POST | `/api/agents/builder/advise` | `{ findingId }` | 202 `{ jobId }`; 404 for an unknown finding |
| GET | `/api/agents/status` | — | `{ aiEnabled, model, busy: {attacker, searcher, builder}, lastError, usage: { calls, inputTokens, outputTokens, estCostUsd } }` |

While a job runs, the agent's snapshot status is `{ status: 'Thinking…', mode: 'ai' }`. When it finishes,
the status changes and the results appear in `findings`, `recommendations` or `activeScenario`.

## 5. Claude configuration (all agents go through `src/agents/claude.mjs`)

- **SDK:** `@anthropic-ai/sdk` and `zod`. These are the project's only dependencies; add them to `package.json`.
- **Key:** `new Anthropic()` reads `ANTHROPIC_API_KEY` from the environment. Run with
  `node --env-file=.env server.mjs`. `.env` is already gitignored; commit a `.env.example` with
  `ANTHROPIC_API_KEY=` and `VORTEX_MODEL=claude-opus-5-5`. Never log the key or send it to the browser.
- **Model:** `claude-opus-5-5`, overridable with `VORTEX_MODEL`.
- **Effort** (`output_config.effort`): Searcher `low`, Attacker `medium`, Builder `medium`.
- **Thinking is always on** for this model:
  - don't send `thinking: { type: "disabled" }`, `budget_tokens` or `temperature`
  - no assistant prefill
  - no forced `tool_choice`
- **Structured output:** `client.messages.parse()` with `output_config.format: zodOutputFormat(schema)`.
  Treat `parsed_output === null` as invalid.
- **Order of checks:** check `stop_reason === 'refusal'` **before** reading content. Then validate the parsed
  output against the platform's allowlists. A refusal, error, timeout (45 s), missing key or invalid output
  means **rules mode**: run the existing deterministic behavior and set `mode: 'rules'` with a short reason.
- **`max_tokens`:** 8000.
- **Caching:** put the stable system prompt plus the topology and catalog first, with `cache_control`, so repeated
  sweeps hit the prompt cache.
- **Untrusted input:** event `detail` text and anything from the simulation is *data*, never instructions. Wrap it
  in a clearly labeled JSON block, and tell the model it is untrusted telemetry.
- **Cost guard:**
  - track usage from `response.usage`; Opus 5.5 is $4 input / $20 output per million tokens
  - stop making AI calls (switch to rules mode) after 150 calls or $5 per server session
  - both limits are overridable in `.env`
- **Dependency injection:** each agent factory takes `{ simulation, claude }` so tests can pass a fake client.
  **Tests never call the real API.**
