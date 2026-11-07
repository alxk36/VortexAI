# VortexAI — local cloud security lab

A provider-neutral, in-memory cloud simulation with a rotatable 3D traffic map and three explainable agents: **Attacker**, **Searcher**, and **Builder**. No cloud account, API key, downloads, or package installation required.

## Run

Requires Node.js 22 or newer. From this project folder:

```sh
npm start
```

Open **http://127.0.0.1:4173** in your browser. Keep the terminal running; press Ctrl+C to stop. If PowerShell blocks `npm.ps1`, use `npm.cmd start` or `node server.mjs` instead. The server binds only to loopback. `PORT` can override the port.

## Try the complete feedback loop

1. Watch normal requests travel through the gateway, load balancer, application, and data services. Drag the map to orbit; scroll over it to zoom. Use **Inspect resource** for node details.
2. Run **Exposed storage**. Within three simulation ticks, Searcher records successful anonymous access and Builder proposes private storage access.
3. Expand the evidence and tradeoff. After the scenario finishes, select **Approve & apply in lab**.
4. Run **Exposed storage** again. Anonymous access is denied and the recommendation reports a verified blocked replay. Authorized application reads continue.
5. Repeat with **Credential abuse** (MFA requirement) and **Lateral movement** (remove administrative export privileges).
6. Use **Pause simulation** to inspect the event stream and **Reset lab** to restore the vulnerable starting state.

All browser tabs share one server session. State and evidence are held in memory and cleared on reset or server restart. The event feed retains the latest 160 records; each finding preserves up to eight evidence records. Metrics are cumulative for the session. Attack events count allowed attack-labeled actions; blocked events include rejected credential guesses and blocked replays.

## What is implemented

- Nine virtual resources with explicit topology and 3D coordinates.
- Normal request/response traffic and three deterministic attack scenarios.
- Attacker: generates only predefined synthetic actions, not real network requests.
- Searcher: inspects observed action, identity, outcome, and recent failures, without using scenario labels to decide findings.
- Builder: proposes a specific policy change with a tradeoff; admin approval is required and replay verifies the modeled mitigation.
- Responsive dashboard, traffic filter, resource inspection, pause/reset, and reduced-motion support.
- Loopback-only HTTP interface, strict command validation, bounded request bodies, and browser-origin protections.

This is a runnable prototype, not an actual cloud, VM, packet capture, or trained AI system. It deliberately models only three paths. No exploit payloads or outbound network capabilities exist in the simulation engine. It does not rely on a reward penalty to enforce containment. A future real-service lab needs separate infrastructure-level isolation.

## Validate

```sh
npm test
```

Tests cover baseline traffic, all three finding/remediation/replay loops, legitimate traffic after fixes, pause/reset, evidence retention, invalid commands, and HTTP boundary checks. No external services are used by the tests.

## Project map

| File | Purpose |
| --- | --- |
| `src/simulation.mjs` | Virtual resources, policy model, scenarios, detection, recommendations |
| `server.mjs` | Local HTTP API, static assets, simulation clock |
| `public/app.mjs` | 3D projection, traffic animation, dashboard interactions |
| `public/index.html`, `public/styles.css` | Accessible interface and responsive layout |
| `test/` | Simulation and HTTP tests using Node's built-in test runner |
| `docs/ARCHITECTURE.md` | Cloud traffic diagram, agent contracts, and optional container/AI roadmap |

The UI polls `GET /api/state`. Named local actions use `POST /api/scenario`, `/api/recommendation`, `/api/running`, and `/api/reset`. The API accepts predefined IDs, never hostnames, arbitrary code, or shell commands.
