# Planning prompts (historical)

These four files are the prompts written at the start of HackRPI 2026 to plan the
Attacker, Searcher and Builder agents. They are **not** a description of what was
built. Alex built the platform first; the agents were then added to it, and the
design changed along the way. For the system as it is, read
[`source/docs/AI.md`](../../source/docs/AI.md) and
[`source/docs/ARCHITECTURE.md`](../../source/docs/ARCHITECTURE.md).

## How the build differs from these prompts

| Planned here | Built |
|---|---|
| Agents call `submitFinding` / `submitRecommendation` / `runPlan` hooks on `Simulation` | Agents run as separate containers behind a model broker (the only holder of the API key) and return one validated decision: `summary`, `scenarioId`, `evidenceIds`, `recommendationIds`, `labels` |
| Attacker composes multi-step plans from an action catalog | Attacker picks one of three scripted scenarios, using its own attack history (succeeded / blocked) to move to untried paths after a fix |
| Claude Opus 5.5 for every agent | Opus 5.5 for every agent; Attacker requests opt into Anthropic's server-side fallback, because Opus 5.5's cyber safeguard declines them. Cyber declines are answered by Opus 4.8, and the dashboard says so |
| Searcher reads the newest events | Searcher reads the whole retained feed, with repeated routine traffic collapsed into counted entries, so attack evidence stays visible |
| Findings tagged internal / external in the agent prompts | `labels` in every decision: the Searcher labels evidence and the Builder labels fixes as **internal** (a mistake by people with access) or **external** (outsiders forcing their way in), shown on finding cards |
| Agents can create findings | Findings still come only from the platform's rules; AI output is advice, evidence citations and labels. Only the Attacker's scenario choice executes, and only the admin applies fixes |

Every AI call has a labeled deterministic fallback, so the demo works without a key.
