# Prompt: VortexAI Attacker (Claude Opus 5.5)

> Paste `00-shared-contract.md` above this prompt. Read `README.md`, `docs/ARCHITECTURE.md` and
> `src/simulation.mjs` before planning.

## 1. Role & Context
- **Persona:** You are a senior red-team engineer and Node.js developer adding an **AI attack planner** to an
  existing breach-and-attack *simulation* for a 24-hour hackathon MVP. Every action is an allowlisted
  state transition inside an in-memory model; nothing touches a real system.
- **Product purpose:** Given an objective, the Attacker uses Claude Opus 5.5 to compose a multi-step attack
  plan from the platform's action catalog, adapting to what worked or got blocked in earlier attempts. The
  platform executes the plan tick by tick, so the 3D map shows it live.
- **Audience:** A cloud admin and hackathon judges. The demo moment: the admin fixes one weakness, the AI
  attacker *adapts* and finds another path, and the admin fixes that too.

## 2. Core Function & Scope
**Primary action:** The admin picks an objective and clicks **Launch AI attack**. A few seconds later, a
named plan with per-step reasoning starts animating on the map.

**Key features (build these, in order):**
1. **Planner job:** `src/agents/attacker.mjs` exports `createAttacker({ simulation, claude })`. It returns
   `{ plan(objective), busy, history }`. A plan:
   1. Builds an **outsider view**: only internet-facing nodes (`gateway`, `iam`, `storage`), the catalog
      entries, and the attacker's own previous plans with each step's outcome (allowed or denied, plus the
      `control` that blocked it). The planner never sees policy values directly. It learns them from outcomes.
   2. Calls Claude, effort `medium`, framed as *choosing moves in a tabletop security simulation from a fixed
      menu*. Never ask the model for commands, payloads, exploit code or real-world targets.
   3. Expects structured output:
      `{ name, objective, steps: [{ actionId, reasoning }], expectedWeakness, ifBlocked }`.
   4. Validates the output: every `actionId` is in `simulation.actionCatalog()`; 1–8 steps; ordering respects
      `requires`. If it's invalid once, make one retry that includes the validation error. If it's invalid
      again, use the fallback.
   5. Calls `simulation.runPlan(...)`.
2. **Adaptation:** keep a session `history` of `{ plan, perStepOutcome, blockedBy[] }`, read from
   `observations()` after the plan finishes. The next plan must avoid controls that are known to block.
   - **Objective `surprise-me`:** pick the objective most likely to succeed given the history.
   - **Nothing left:** if every known path is blocked, return a plan anyway and report
     `status: 'All known paths blocked'`. This is a good demo ending.
3. **Fallback (rules mode):** a missing key, a refusal (`stop_reason === 'refusal'`; Opus 5.5 can decline
   anything that looks like offensive security), an error, a timeout or a second invalid plan → run the
   built-in scenario for the objective:
   - `data-exfiltration` → `exposed-storage`
   - `account-takeover` → `credential-abuse`
   - `privilege-escalation` → `lateral-movement`
   - `surprise-me` → the first scenario not yet blocked

   Record `mode: 'rules'` and the reason.

**Stretch (only after 1–3 work): breach-rate campaign.** Ask Alex for `simulation.fork({ policies })`, a
headless clone. Run the same plan against three policy presets (all off / one on / all on), ticking each
fork to completion. Return a success rate per preset for a "90% → 0%" chart.

**Not building yet:** new nodes or policies (ask Alex), real networking of any kind, multi-agent
self-play, attacker memory across server restarts, any UI code.

## 3. Tech Stack & Architecture
- Node.js 22+, ES modules, no build step. Dependencies: `@anthropic-ai/sdk` and `zod`.
- Claude through `src/agents/claude.mjs` (contract §5): `claude-opus-5-5`, effort `medium`, `messages.parse`
  + `zodOutputFormat`, refusal check first, 45 s timeout.
- Route: `POST /api/agents/attacker/plan { objective }` → 202 `{ jobId }`; 409 if a scenario or plan is
  active or the attacker is busy.
- **Tests** (`test/agents/attacker.test.mjs`, with a fake `claude`):
  - an unknown `actionId` or a `requires` violation is rejected, retried once, then falls back
  - a refusal falls back to the mapped scenario
  - the outsider view contains no policy values, no `kind`, and no internal-only nodes
  - after `storagePrivate` blocks a plan, the next request's history includes `blockedBy: ['storagePrivate']`
  - plans are capped at 8 steps

## 4. UI/UX & State Requirements (data you expose; Alex renders it)
- `snapshot().activeScenario` for AI plans includes `source: 'ai-attacker'`, `name`, and the per-step
  `reasoning`. Alex shows the current step's reasoning as a caption on the 3D map.
- `snapshot().agents.attacker` = `{ status, detail, mode }`. Statuses: `Ready`, `Planning…`, `Attacking`,
  `Blocked`, `Completed`, `All known paths blocked`, `Rules mode`.
- **History panel:** each past plan with a ✓ (step allowed) / ⛔ (denied, plus the control) per step.
- **States:**
  - *Loading:* `Planning…` with the launch button disabled.
  - *Empty:* "Launch an AI attack to test this cloud."
  - *Error / fallback:* "AI planner unavailable — running built-in scenario."
  - *Success:* the plan animates on the map.

## 5. Guardrails & Clarifying Questions
- **Simulation only.** No sockets, `fetch` (except the Anthropic SDK), `child_process` or filesystem writes
  in agent code. No real commands, payloads, hostnames or exploit strings, even in prompts or flavor text.
- The model chooses only catalog IDs. The platform decides every outcome. Never call private `_` methods
  on `Simulation`.
- Don't edit `src/simulation.mjs`, `server.mjs` or `public/`. Write hook requests for Alex instead.
- **Before writing any code, ask me clarifying questions about anything ambiguous.** Then propose a
  file-by-file plan and wait for my OK.
