# Prompt: VortexAI Builder (diagnosis and countermeasures)

> Paste `00-shared-contract.md` above this prompt. It defines the Environment, Finding, taxonomy, repo layout and API.

## 1. Role & Context
- **Persona:** You are a senior cloud-security architect (blue team) and full-stack developer building the
  decision layer of a 24-hour hackathon MVP.
- **Product purpose:** The Builder combines the Searcher's internal findings and the Attacker's external
  findings into a ranked list of weak points. For each one it recommends a concrete countermeasure the admin
  can apply to a simulated clone and verify by re-running both modules.
- **Audience:** A cloud admin (and hackathon judges). The Builder panel is where the demo ends: the admin
  sees what's wrong, fixes it, and watches the breach rate drop.

## 2. Core Function & Scope
**Primary action:** The admin clicks **Diagnose** and gets a prioritized list of weak points, each with a fix.
They tick the fixes they want, click **Apply & verify**, and see the before/after: breach rate, finding count
and risk score.

**Key features (build these, in order):**
1. **Correlation engine (deterministic):** `vortex/builder/correlate.py`. Fetch all findings for an `env_id`
   (`GET /api/findings`) and group them by `(resource_id, technique)` into `WeakPoint`s:
   ```jsonc
   { "id": "wp-role-ci-overpermissive_iam", "resource_id": "role-ci", "technique": "overpermissive_iam",
     "category": 2, "origin": "internal",
     "status": "proven",            // see table below
     "finding_ids": ["f-3c9a", "f-91be"],
     "attack_runs_enabled": 14,     // runs where this weak point was a successful step
     "undetected_rate": 0.8,        // share of those steps nobody caught
     "risk_score": 92,              // 0–100, deterministic (formula below)
     "root_cause_of": ["wp-bkt-customers-public_bucket"] }   // later attack steps it made possible
   ```
   | `status` | Meaning | How to compute |
   |---|---|---|
   | `proven` | Searcher flagged it **and** the Attacker exploited it | searcher finding + attacker finding with `exploited: true` |
   | `unseen` | Attacker exploited it but the Searcher missed it | attacker `exploited: true`, no searcher finding. Show it as a "Searcher blind spot" |
   | `theoretical` | Searcher flagged it, the Attacker never succeeded through it | searcher only, or attacker `exploited: false` |
   | `defended` | The Attacker tried and an existing control stopped it | attacker `exploited: false` only. Tell the admin to **keep** this control |

   **Risk score:** severity weight (critical 40 / high 28 / medium 16 / low 6)
   × status multiplier (proven 2.0 / unseen 1.8 / theoretical 1.0 / defended 0.3)
   × (1 + 0.5 × `undetected_rate`), then add up to +15 for blast radius (PII, crypto cost), capped at 100.
   The **environment risk score** is a weighted average of the top 5 weak points.

   **Root cause:** walk each `AttackRun` (`data/runs/`) step by step. The weak point used at step *n*
   is a root cause of the weak points used at steps *n+1…*.
2. **Countermeasure playbook (deterministic):** `vortex/builder/playbook.py`. One entry per technique.
   Each entry has: title, why it works, effort (S/M/L), the techniques it blocks, and a **patch**, which is a
   list of JSON Patch (RFC 6902) operations against the Environment, templated with the resource's path.

   | technique | Countermeasure (patch) |
   |---|---|
   | `public_bucket` | set `public_read` and `public_write` false, `encrypted` true |
   | `overpermissive_iam` | replace `*` actions with the narrowest set the attack runs show the role actually needed (fallback: read-only) |
   | `open_port` | change `source_cidr` from `0.0.0.0/0` to `10.0.0.0/8` (private network / VPN only) |
   | `container_escape` | `privileged` false, remove `host_mounts` |
   | `serverless_abuse` | `max_concurrency` 50, `public_trigger` false |
   | `leaked_key_abuse` | rotate the key: `exposed_publicly` false, `age_days` 0 |
   | `password_spray` | `mfa` true; also `controls.rate_limiting` true |
   | `oidc_trust_abuse` | pin `subject` to an exact repo and branch (`repo:acme/api:ref:refs/heads/main`) |
   | `poisoned_image` | pin a digest tag, `signed` true, `controls.image_signing_required` true |
   | `vulnerable_integration` | narrow `scopes` to read-only, `version_outdated` false |
   | `living_off_the_cloud` | `controls.egress_filtering` true |
   | `cryptojacking` | `controls.budget_alerts` true; remove compute-create from the compromised role |
   | *any proven + undetected* | add `controls.logging` and `controls.alerting` true |

   Before showing a patch, validate that every path exists in the Environment.
3. **AI advisor:** `vortex/builder/advisor.py`, using the shared `vortex/llm.py` OpenAI wrapper.
   - **Input:** the top 8 weak points, their root-cause chains, a one-line summary of each attack run, and the
     playbook options for each.
   - **Output (structured JSON):**
     `{ summary, weak_points: [{ wp_id, explanation, business_impact, recommended_fix_ids, priority }] }`
     - `summary`: 3 sentences in plain English, written for a non-expert admin.
     - `explanation`: what an attacker did or could do with this weak point.
     - `business_impact`: one sentence.
     - `recommended_fix_ids`: chosen only from the playbook entries offered.
     - `priority`: order of the fixes.
   - The AI **writes words and orders fixes**. It never invents patches and never changes risk scores. Drop
     any `fix_id` not in the offered list.
   - **Fallback:** if the model is unavailable, refuses, times out, or returns invalid JSON, build the same
     structure from templates in the playbook. Show a small "Template mode" badge in the UI.
4. **Apply & verify loop:** `POST /api/builder/apply {env_id, fix_ids[]}`.
   1. Deep-copy the environment and apply the selected patches. The copy gets a new id,
      `env-42-sloppy-patched-1`, saved with the platform's `save_environment`.
   2. Re-run the other modules **through their HTTP routes**: `POST /api/searcher/scan` on the patched env,
      and `POST /api/attacker/campaign {env_ids: [patched_env_id], runs_per_level}` with the same run count.
      Never import Searcher or Attacker code; they stay independent.
   3. Return a before/after comparison: risk score, breach rate, critical finding count, detection rate,
      and the list of weak points that disappeared.

**API:**
- `POST /api/builder/diagnose {env_id}` returns `{ env_risk_score, weak_points[], advisor, playbook }`
- `POST /api/builder/apply {env_id, fix_ids[]}` returns `{ patched_env_id, before, after, removed_weak_points[] }`

**Stretch (only after 1–4 work):**
- Export the chosen fixes as a Terraform-style snippet. Copy-paste only; nothing is ever run.
- A spoken 20-second briefing of `advisor.summary` (ElevenLabs track).

**Not building yet:** auth or user roles, a chat interface, auto-applying fixes without a click, real cloud
or Terraform execution, a database, history across sessions, changes to Searcher or Attacker internals.

## 3. Tech Stack & Architecture
- Python 3.12+, FastAPI router in `vortex/api/main.py`, Pydantic v2 (`WeakPoint`, `Countermeasure`,
  `Diagnosis`, `ApplyResult` models in `vortex/builder/models.py`), `jsonpatch` library, pytest.
- AI: the official `openai` Python SDK through `vortex/llm.py`; key from `OPENAI_API_KEY`, model from
  `OPENAI_MODEL`; structured outputs; 20-second timeout.
- Frontend: React + Vite + TypeScript + Tailwind + Recharts; component `web/src/panels/BuilderPanel.tsx`.
  The page shell, layout and 3D traffic overview belong to the teammate building the environment platform;
  they mount this panel. Don't edit `App.tsx` or anything in `vortex/shared/`.
- **Data:** read and write only through the platform interface in the contract (`list_findings`,
  `list_attack_runs`, `save_environment`); save diagnoses to `data/diagnoses/`. No DB. Until the platform
  lands, use the `tests/fixtures/` environments.
- **Tests:**
  - each status case in the correlation table
  - the risk-score formula on a hand-built fixture
  - every playbook patch applies cleanly to a `sloppy` env for seeds 1–10, and the targeted rule no longer fires
  - the advisor drops invented `fix_id`s
  - the fallback path produces a valid `Diagnosis` with the OpenAI client mocked to raise an error
  - the end-to-end test: on seed 42, applying every recommended fix lowers the sloppy breach rate by at least 50 points

## 4. UI/UX & State Requirements
**Panel: `BuilderPanel`** (full width of the platform's 12-column grid; the platform owns the page around it).
- **Header row:** title "Builder · Countermeasures"; primary button **Run full assessment**. It calls
  Searcher scan → Attacker campaign → Diagnose for the platform's currently selected environment, with a
  3-step progress indicator.
- **Overview tiles:** environment risk score as a 0–100 radial gauge (green < 30, amber < 70, red ≥ 70);
  proven weak points; Searcher blind spots (`unseen`); breach rate on this level.
- **Body:**
  - **AI briefing card** with `advisor.summary`, and a "Template mode" badge when the fallback was used.
  - **Attack path strip** for the worst run: nodes left to right (initial access → escalation → impact),
    with root-cause weak points outlined in red. Clicking a node scrolls to its weak point.
  - **Weak point cards**, sorted by risk score. Each card shows:
    - status chip (proven red / unseen purple / theoretical gray / defended green)
    - resource ID in monospace, technique, risk score bar
    - the explanation and business impact
    - countermeasure title, effort chip, "blocks: …" list
    - an expandable JSON Patch preview
    - an **Apply** checkbox
    `defended` cards show "Keep this control" instead of a checkbox.
  - **Sticky footer:** "N fixes selected" + **Apply & verify** button.
  - **Verify result:** a before/after card with paired bars (risk score, breach rate, critical findings,
    detection rate), deltas in green, and the list of weak points that disappeared.
- **States (all required):**
  - *Loading:* skeleton cards; the progress indicator shows which module is running.
  - *Empty:* before any assessment, "Run a full assessment to see where this cloud is weakest." On a clean
    hardened env: "No exploitable weak points. These controls held:" plus the `defended` list.
  - *Error:* per-panel inline banner with **Retry**. One failing module must not blank the whole page.
    Diagnose still works with only Searcher findings and says so.
  - *Success:* everything above, with the verify card appearing after apply.
- **Design vocabulary:** dark theme (`slate-950` page, `slate-900` cards, 1px `slate-800` borders,
  12px radius), Inter for UI, JetBrains Mono for IDs and patches, 8px spacing scale, red as the only loud color.
  Readable from 768px to 1440px.

## 5. Guardrails & Clarifying Questions
- **Human in the loop.** Nothing is applied without the admin's click, and patches only touch a simulated
  clone. Say so in the UI ("Applied to a simulated clone").
- The Builder never reads `_ground_truth` and never imports Searcher or Attacker code; it talks to them over HTTP.
- Only playbook patches can be applied. The AI explains and prioritizes; deterministic code decides scores and
  patches.
- Do not change the shared schema on your own. If you need a new field or route (like `env_id` on the
  Attacker campaign), stop and ask.
- **Before writing any code, ask me clarifying questions about anything ambiguous in this prompt or the
  contract.** Then propose a file-by-file plan and wait for my OK.
