# VortexAI — cloud security lab

A provider-neutral learning platform with a 3D traffic map, bounded attack scenarios, evidence-based findings, and administrator-approved fixes. Choose an **in-memory simulation** or an **isolated Docker service lab**. Separate Attacker, Searcher, and Builder workers connect to **Claude Opus 5.5** through a restricted broker, with explicit fallback when the model is unavailable.

## Quick start: simulation

From this project folder, using Node.js 24:

```sh
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). No cloud account, package installation, or API key is required for the simulation. Keep the terminal running; Ctrl+C stops it. If PowerShell blocks `npm.ps1`, use `npm.cmd start` or `node server.mjs`.

## Real services and Claude Opus 5.5

Requires Docker Desktop using Linux containers/WSL 2 on Windows, Docker Engine 28+, and Compose. Stop any standalone simulation server on port 4173 first.

```sh
npm run lab:setup
```

Open the generated `.env` locally and put your Anthropic key after `ANTHROPIC_API_KEY=`. Keep `ANTHROPIC_MODEL=claude-opus-5-5`. An empty key enables visible fallback mode; it does not produce a live AI result. The key belongs only in `.env`, never in chat or the dashboard.

```sh
npm run lab:up
```

This builds and starts 12 containers, then runs containment checks. Open the dashboard and choose **Isolated service lab** only after the checks pass. Six target services handle real HTTP requests, with SQLite-backed demo database/storage. They have no published ports or external network attachment. The model broker alone holds the Anthropic key and calls the provider. The trusted dashboard also has an external route through its frontend bridge; targets, executor, and agents stay on internal isolated networks.

```sh
npm run lab:status
npm run lab:verify
npm run lab:down
```

Read [the full service-lab guide](docs/REAL-LAB.md) for setup, the network diagram, trust boundaries, verification gates, and limitations. Live Docker containment and provider access require verification on the machine where you run the lab; unit tests and fallback results do not certify either.

## Try the feedback loop

1. Watch normal traffic and inspect a resource.
2. Run **Exposed storage**, **Credential abuse**, or **Lateral movement**. These are the only executable attack scenarios.
3. Review Searcher's recorded evidence and Builder's proposed policy change and tradeoff.
4. After the scenario finishes, select **Approve & apply in lab**.
5. Replay the same scenario and look for a blocked result while normal application access continues.
6. Use the three agent buttons for model-assisted planning, assessment, and advice. Each result identifies **MODEL** or **FALLBACK**. Builder never applies a fix itself.

In simulation mode, events are synthetic. In service mode, events describe actual requests and authorization outcomes inside the teaching lab. The 3D animation is an explanation of event records, not packet capture. Data is fabricated, state is transient, and all browser tabs share the selected server environment.

## Mouse controls

| Gesture | Action |
| --- | --- |
| Left/middle drag | Orbit a full 360° horizontally and vertically; vertical drag direction is reversed |
| Shift + drag | Pan |
| Wheel | Zoom |
| Ctrl + click | Select/toggle nodes |
| Ctrl + left drag | Move a node, or the entire group when dragging a selected node |
| Alt + left drag | Draw a box to select multiple nodes |
| Right click a selected node | Information and shared status/action options for the selection |
| Ctrl + right drag | Also move selected nodes on their horizontal plane |
| Escape during a drag | Cancel the move or box selection |

Use **Inspect resource → Edit selected** for keyboard access. Positions persist in this browser and do not alter service connectivity. **Reset view** restores the camera; **Reset layout** restores positions. In service mode, status/action editing applies to the six actual services: pause/quarantine denies ordinary requests, and Observe annotates telemetry. Health/control routes stay available; containers and network isolation are unchanged. Conceptual user/attacker/telemetry nodes have layout controls only. Security-policy changes still use reviewed recommendations.

## Scope and validation

```sh
npm test
```

Tests cover simulations, service handlers, observed findings and fixed replays, AI output validation/fallback, HTTP limits, containment-inspection rules, and grid movement math. They do not issue paid model requests or prove real Docker isolation.

This is a purpose-built teaching lab, not an actual cloud provider or arbitrary exploit runner. The full 12-technique, seeded-clone campaign platform in `prompts/` is still a roadmap; this stage adapts its agent boundaries and approval pattern to the existing Node code. For arbitrary untrusted exploit execution later, use a separate disposable VM with independent containment controls.

## Project map

| Location | Purpose |
| --- | --- |
| `src/simulation.mjs` | In-memory cloud, policies, scenarios, evidence and recommendations |
| `src/runtime.mjs` | Environment switching and independent-agent orchestration |
| `src/findings.mjs` | Canonical `GET /api/findings` adapter for the shared finding fields |
| `lab/` | Bounded executor, actual HTTP teaching services, namespace probes |
| `ai/` | Three worker roles, context filtering, response validation, Anthropic broker |
| `compose.yaml`, `Dockerfile` | Container topology and restricted runtime settings |
| `scripts/` | Local token setup, Docker lifecycle and live containment verifier |
| `public/` | Dashboard, perspective rendering, grid controls |
| `test/` | Node built-in test runner suite |
| `docs/REAL-LAB.md` | Current real-service/AI setup and limitations |
| `docs/ARCHITECTURE.md` | Earlier in-memory baseline architecture; see the real-lab guide for this stage |
| `prompts/` | Team design reference and deferred broader contract |

The dashboard reads `GET /api/state` and uses named commands for scenarios, recommendations, mode switching, node controls, and agent runs. It never supplies arbitrary target URLs, shell commands, or model-generated executable code.
