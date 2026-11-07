# Prompt: VortexAI Searcher (internal threats)

> Paste `00-shared-contract.md` above this prompt. It defines the Environment, Finding, taxonomy, repo layout and API.

## 1. Role & Context
- **Persona:** You are a senior cloud-security engineer and Python backend developer building a
  cloud security posture scanner for a 24-hour hackathon MVP.
- **Product purpose:** The Searcher scans a randomized cloud configuration and flags every internal
  security risk (mistakes made by people with access) as a structured `Finding`.
- **Audience:** A cloud admin watching the VortexAI dashboard. Downstream, the Builder module
  (built separately by a teammate) reads these findings to recommend fixes.

## 2. Core Function & Scope
**Primary action:** The user picks a seed and security level, clicks **Scan**, and gets a ranked list of
risks, each pointing at an exact resource and config path.

**Key features (build these, in order):**
1. **Platform hookup:** `vortex/shared/` (environment generator and store) belongs to the teammate building
   the environment platform. **Don't write it.** Use only the platform interface from the contract. Until it
   lands, load the hand-written fixtures in `tests/fixtures/env-42-{level}.json`, which follow the contract
   exactly. Create them if they don't exist, with every injected weakness listed in `_ground_truth`.
2. **Rule engine:** `vortex/searcher/rules.py`. Each rule is a pure function
   `(env) -> list[Finding]`, registered in a list. Write one rule per check:

   | technique | category | Flag when | Default severity |
   |---|---|---|---|
   | `public_bucket` | 2 | `public_read` or `public_write` is true | critical if `data_class == "pii"`, else high |
   | `overpermissive_iam` | 2 | a policy has `"*"` in actions **and** resources, or `<service>:*` on `"*"` | critical |
   | `open_port` | 2 | an SG rule on 22/3389/3306/5432/6379/27017 has source `0.0.0.0/0` | high (critical for DB ports) |
   | `container_escape` | 4 | container is `privileged` or mounts `docker.sock` or `/` | critical |
   | `serverless_abuse` | 4 | function has `public_trigger` **and** (`max_concurrency` is null or its role is over-permissive) | high |
   | `leaked_key_abuse` *(precondition)* | 1 | access key `exposed_publicly` or `age_days > 90` | critical if exposed, else medium |
   | `password_spray` *(precondition)* | 1 | user has `mfa: false` and weak or reused password | high |
   | `oidc_trust_abuse` *(precondition)* | 1 | role trust is `oidc` with a wildcard in `subject` | high |
   | `poisoned_image` *(precondition)* | 3 | tag is `latest` or unsigned image from an unverified registry, and `image_signing_required` is false | medium |
   | `vulnerable_integration` *(precondition)* | 3 | integration has `"*"` scope or `version_outdated` | medium |

   Every Searcher finding has `source: "searcher"`, `origin: "internal"`, `exploited: null`, and `evidence`
   holding the JSON path and offending value. Category 1/3/5 rows are internal mistakes that *enable*
   external attacks, so they are still `origin: "internal"`.
3. **Toxic-combination escalation:** after the base rules run, raise severity one level when one
   resource has several findings that chain together. Example: a public-IP instance whose role is
   over-permissive. Record the reason in `evidence.escalated_because`.
4. **Scoring and API:** compare findings to `_ground_truth` on `(technique, resource_id)` to compute
   precision and recall. This is the only code allowed to read `_ground_truth`. Expose
   `POST /api/searcher/scan` and a CLI: `python -m vortex.searcher --seed 42 --level sloppy`, which prints
   a severity-sorted table and the score. Save findings to `data/findings/{env_id}.searcher.json`.

**Stretch (only after 1–4 work):** *Sweep mode.* Every N seconds, apply a random "config drift" (a
teammate makes a bucket public, opens a port), re-scan, and mark findings that are new since the last sweep.
This is the "bot hovering over the system" from the team doc.

**Not building yet:** auth, real cloud APIs (AWS/GCP/Azure SDKs), a database, Terraform/YAML parsing (input
is the contract JSON only), auto-remediation, anything in Attacker or Builder, LLM calls in the detection path.

## 3. Tech Stack & Architecture
- Python 3.12+, FastAPI router in `vortex/api/main.py`, Pydantic v2, pytest.
- Frontend: React + Vite + TypeScript + Tailwind; component `web/src/panels/SearcherPanel.tsx`.
- **Data:** environments and findings are JSON files under `data/`, with an in-memory cache. No DB.
- **Tests:** for each rule, one positive and one negative fixture. A property test checks that the
  `hardened` level yields at most 20% of the findings `sloppy` yields for seeds 1–20. Recall on `sloppy`
  must be 1.0, because every injected weakness has a rule.

## 4. UI/UX & State Requirements
**Panel: `SearcherPanel`** (one card in the dashboard grid, 16px padding, 12px radius).
- **Header row:** title "Searcher · Internal"; seed number input; level segmented control
  (Hardened / Default / Sloppy); primary button **Scan**.
- **Stat tiles row** (3 equal columns): total findings; critical count; precision/recall as "P 1.00 · R 0.95".
- **Findings table:** severity chip (critical red / high orange / medium yellow / low gray), category
  number and name, technique, `resource_id` in monospace, title. Click a row to expand it and show
  `evidence` as pretty-printed JSON in a monospace block. Sorted by severity, then category.
- **States (all required):**
  - *Loading:* button disabled with a spinner; 5 skeleton rows.
  - *Empty:* centered message "No internal risks found. This environment is clean." (common on Hardened).
  - *Error:* inline red banner with the message and a **Retry** button; keep the last good results visible underneath.
  - *Success:* the table, plus a subtle "Scanned 24 resources in 38 ms" footer.
- **Design vocabulary:** dark theme (`slate-950` page, `slate-900` cards), Inter for UI, JetBrains Mono for
  IDs and evidence, 8px spacing scale, readable from 768px wide up to 1440px; the table scrolls
  horizontally on narrow screens instead of wrapping.

## 5. Guardrails & Clarifying Questions
- Detection logic must never read `_ground_truth`. Add a test that deletes it and confirms the findings are unchanged.
- No network calls, shelling out, or real scanning of anything. Input is the in-memory Environment only.
- Do not change the shared schema on your own. If you need a new field, stop and ask, because the Attacker and Builder depend on it.
- **Before writing any code, ask me clarifying questions about anything ambiguous in this prompt or the
  contract.** Then propose a file-by-file plan and wait for my OK.
