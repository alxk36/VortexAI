# Prompt: VortexAI Attacker (external threats)

> Paste `00-shared-contract.md` above this prompt. It defines the Environment, Finding, taxonomy, repo layout and API.

## 1. Role & Context
- **Persona:** You are a senior red-team engineer and Python developer building an **attack simulator**
  (a breach-and-attack-simulation engine) for a 24-hour hackathon MVP. Every attack is a state transition
  on an in-memory JSON model. Nothing touches a real system.
- **Product purpose:** The Attacker clones the simulated cloud at different security levels, runs randomized
  multi-step attack chains against each clone, and reports which attacks worked, which were blocked, and
  which were detected.
- **Audience:** A cloud admin watching the VortexAI dashboard. Downstream, the Builder module (built separately
  by a teammate) reads these findings to recommend fixes. The money shot of the demo: *the same cloud gets
  breached 9 times out of 10 when sloppy, and 1 time out of 10 when hardened.*

## 2. Core Function & Scope
**Primary action:** The user clicks **Launch campaign**. The Attacker runs N attack chains against the
Hardened, Default, and Sloppy clones of one seed and shows the success rate per level, plus a step-by-step
replay of one featured run.

**Key features (build these, in order):**
1. **Technique catalog:** `vortex/attacker/techniques.py`. Each technique is data plus two pure functions:
   ```python
   Technique(id, category, phase,            # phase: "initial_access" | "escalation" | "impact"
             targets(view, state) -> list[resource_id],   # where preconditions hold
             resolve(env, state, target, rng) -> StepResult)  # success / blocked / detected, plus new state
   ```
   | technique | cat | phase | Preconditions | Blocked or weakened by |
   |---|---|---|---|---|
   | `leaked_key_abuse` | 1 | initial_access | a key with `exposed_publicly` | key `age_days` < 30 halves success |
   | `password_spray` | 1 | initial_access | a user with `mfa: false` | `rate_limiting` halves it; strong, non-reused password blocks it |
   | `oidc_trust_abuse` | 1 | initial_access | OIDC role with wildcard `subject` | — |
   | `vulnerable_integration` | 3 | initial_access | integration `version_outdated` | narrow scopes limit the foothold |
   | `poisoned_image` | 3 | initial_access | unsigned or `latest` image | `image_signing_required` blocks it |
   | `open_port` | 2 | initial_access | DB/admin port open to `0.0.0.0/0` | — |
   | `overpermissive_iam` | 2 | escalation | foothold identity's role has wildcard actions | — |
   | `container_escape` | 4 | escalation | foothold on a `privileged` container or `docker.sock` mount | — |
   | `serverless_abuse` | 4 | escalation | public function whose role is broader than the foothold | `max_concurrency` set halves it |
   | `public_bucket` exfil | 2 | impact | readable bucket (public, or via a compromised role) | `egress_filtering` blocks non-public exfil |
   | `living_off_the_cloud` | 5 | impact | any foothold; data reachable | `egress_filtering` blocks it |
   | `cryptojacking` | 5 | impact | role can create compute | `budget_alerts` means detected within 1 step |

   **Detection:** each step has a detection chance. 0% with no logging, 30% with `logging`, 70% with
   `logging` and `alerting`. If a step is detected, the run ends as `contained`.
2. **Fog of war:** `AttackerView`. The attacker plans only from what an outsider could see: public IPs and
   ports, public buckets and triggers, exposed keys ("found on GitHub"), user names ("from LinkedIn"),
   integration vendors. After compromising an identity, the view expands to that identity's roles and
   reachable resources. **The planner never receives the raw Environment or `_ground_truth`.**
3. **Engine and planners:** `vortex/attacker/engine.py` runs one chain of at most 8 steps:
   initial access → (escalation)* → impact. Two interchangeable planners pick the next `(technique, target)`:
   - `ScriptedPlanner`: deterministic and weighted-random by phase and impact, seeded RNG. Used for bulk campaign runs.
   - `AIPlanner`: sends the current `AttackerView` plus the list of legal `(technique, target)` options to
     the OpenAI model named in `OPENAI_MODEL` and gets back JSON `{technique, target_resource_id, reasoning}`
     via structured outputs (a JSON schema). Used only for the **featured run**, to keep cost and latency low. Validate the choice is in
     the legal list. On an invalid choice, an API error, a timeout, a missing key, or
     a refusal or empty/unparseable reply, fall back to `ScriptedPlanner` for that step and record
     `planner: "scripted_fallback"`. The prompt to the model must frame the task as choosing moves in a
     tabletop security simulation from a fixed menu; never ask it for commands, payloads or exploit code.
4. **Campaign, findings and API:** `POST /api/attacker/campaign` accepting either `{seed, levels, runs_per_level}`
   (the platform generates each clone) or `{env_ids, runs_per_level}` (the Builder's patched clones), and the CLI
   `python -m vortex.attacker --seed 42 --runs 20`. Output an `AttackRun` per run:
   ```jsonc
   { "run_id": "run-42-sloppy-07", "env_id": "env-42-sloppy", "planner": "scripted",
     "steps": [{ "n": 1, "phase": "initial_access", "technique": "password_spray", "category": 1,
                 "target": "user-ana", "result": "success", "detected": false,
                 "reasoning": "...", "narrative": "Sprayed 3 common passwords at user-ana (no MFA) — success." }],
     "outcome": "compromised",   // "compromised" | "contained" | "failed"
     "blast_radius": { "resources_compromised": 6, "pii_exfiltrated": true, "est_crypto_cost_usd_per_day": 4120 } }
   ```
   Also convert every attempted step into a `Finding` (`source: "attacker"`, `origin: "external"`,
   `exploited` true or false, `detected`, `attack_run_id`). Blocked attempts matter: they show the Builder
   which controls worked. Return a `summary` with success, containment and detection rates per level and
   mean steps-to-compromise. Save to `data/runs/` and `data/findings/{env_id}.attacker.json`.

**Not building yet:** auth, a database, real cloud APIs, any real networking or exploitation, live WebSocket
streaming (fake the replay animation client-side), the Searcher or Builder, attacker "learning" across runs.

## 3. Tech Stack & Architecture
- Python 3.12+, FastAPI router, Pydantic v2, pytest. Official `openai` Python SDK on the team's OpenAI plan:
  key from `OPENAI_API_KEY`, model ID from `OPENAI_MODEL` (never hard-coded), structured outputs for the
  move, and the lowest reasoning effort the model supports (it's a quick move choice). Wrap the client in
  `vortex/llm.py` so all three agents call the AI the same way.
- `vortex/shared/` is the environment platform, owned by a teammate. Don't write it. Use only the platform
  interface from the contract, and the `tests/fixtures/` environments until it lands.
- Frontend: React + Vite + TypeScript + Tailwind + Recharts; component `web/src/panels/AttackerPanel.tsx`.
- **Data:** JSON files under `data/`. No DB. Everything is reproducible from `(seed, level, run index)`.
- **Tests:**
  - every technique's `targets()` returns nothing on a fully hardened fixture
  - the same seed gives an identical campaign
  - over seeds 1–10 with 20 runs each, success rate is strictly ordered sloppy > default > hardened
  - the planner input contains no `_ground_truth` key
  - the AI planner falls back cleanly when the client raises an error

## 4. UI/UX & State Requirements
**Panel: `AttackerPanel`** (one card in the dashboard grid, 16px padding, 12px radius).
- **Header row:** title "Attacker · External"; seed input; level multi-select (all three on by default);
  runs-per-level stepper (default 20); planner toggle for the featured run (Scripted / AI); primary red button
  **Launch campaign**.
- **Stat tiles** (3 columns): breach rate on Sloppy vs Hardened ("90% → 10%"); detection rate; estimated
  cryptojacking cost per day on Sloppy.
- **Bar chart:** outcome per security level, stacked bars (compromised red / contained amber / failed green).
- **Featured run replay:** vertical stepper. Each step shows a phase label, technique, target (monospace), a
  result icon (success / blocked / detected), the one-line `narrative`, and, if the AI planned it, its
  `reasoning` in muted italic. Reveal steps one at a time, 400ms apart, with a **Skip** link. Finish with an
  outcome banner ("BREACHED: PII exfiltrated from bkt-customers" or "CONTAINED at step 3").
- **States (all required):**
  - *Loading:* button disabled, progress text "Running 60 attack chains…", skeleton chart.
  - *Empty:* before the first launch, an illustration-free placeholder: "Launch a campaign to stress-test this cloud."
  - *Error:* inline banner with **Retry**. If only the AI planner failed, show a small notice
    "AI planner unavailable — featured run used scripted planner" instead of an error.
  - *Success:* chart, tiles and replay.
- **Design vocabulary:** dark theme matching the Searcher panel (`slate-950` / `slate-900`), Inter plus
  JetBrains Mono, 8px spacing, works from 768px to 1440px; the chart and stepper stack vertically under 1024px.

## 5. Guardrails & Clarifying Questions
- **Simulation only.** No sockets, no `subprocess`, no HTTP other than the OpenAI API, no real commands,
  payloads, credentials or exploit strings, even as flavor text. Techniques only change Python dicts.
- The planner sees only the `AttackerView`. Detection and planning code never read `_ground_truth`.
- Do not change the shared schema on your own. If you need a new field, stop and ask, because the Searcher and Builder depend on it.
- **Before writing any code, ask me clarifying questions about anything ambiguous in this prompt or the
  contract.** Then propose a file-by-file plan and wait for my OK.
