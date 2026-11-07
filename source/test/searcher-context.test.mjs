import test from 'node:test';
import assert from 'node:assert/strict';
import { Simulation } from '../src/simulation.mjs';
import { prepareContext, validateDecision, runAgent } from '../ai/agents.mjs';

const SCENARIOS = ['exposed-storage', 'credential-abuse', 'lateral-movement'];

/** Run a scenario to completion, then let normal traffic keep flowing. */
function afterScenario(id, extraTicks) {
  const sim = new Simulation();
  sim.runScenario(id);
  while (sim.snapshot().activeScenario) sim.tick();
  for (let i = 0; i < extraTicks; i++) sim.tick();
  return sim.snapshot();
}

// Ground truth (`kind`) is used only by the test to know which events the
// Searcher must still be able to see; the context itself never carries it.
const attackIds = snap => snap.events.filter(e => e.kind !== 'normal').map(e => e.id);
const citable = context => new Set(context.events.flatMap(e => [e.id, ...(e.ids ?? [])]));

test('attack evidence stays visible to the Searcher after normal traffic resumes', () => {
  for (const id of SCENARIOS) {
    for (const extra of [0, 5, 12]) {
      const snap = afterScenario(id, extra);
      const visible = citable(prepareContext('searcher', snap));
      const missing = attackIds(snap).filter(e => !visible.has(e));
      assert.deepEqual(missing, [], `${id}, ${extra} ticks later: attack events dropped from the Searcher view`);
    }
  }
});

test('evidence the rules already flagged survives after the live feed rolls over', () => {
  const snap = afterScenario('exposed-storage', 40); // ~360 normal events: far past the 160-event feed
  assert.equal(attackIds(snap).length, 0, 'precondition: the live feed no longer holds the attack');
  const visible = citable(prepareContext('searcher', snap));
  for (const evidenceId of snap.findings[0].evidence) assert.ok(visible.has(evidenceId), `${evidenceId} lost`);
});

test('repeated normal traffic is collapsed into counted entries, not dropped', () => {
  const sim = new Simulation();
  for (let i = 0; i < 20; i++) sim.tick();
  const context = prepareContext('searcher', sim.snapshot());
  assert.ok(context.events.length <= 16, `expected a compact view, got ${context.events.length} entries`);
  assert.ok(context.events.every(e => e.count >= 4 && e.ids.length <= 8 && e.ids[0] === e.id));
  const total = context.events.reduce((sum, e) => sum + e.count, 0);
  assert.equal(total, sim.snapshot().events.length, 'every retained event is accounted for in a count');
});

test('the compressed view stays bounded, idempotent, label-free and small enough for the agent services', () => {
  for (const id of SCENARIOS) {
    const snap = afterScenario(id, 12);
    const context = prepareContext('searcher', snap);
    assert.ok(context.events.length <= 48);
    assert.deepEqual(prepareContext('searcher', context), context, 'each trust boundary must reproduce the same view');
    const json = JSON.stringify(context);
    assert.ok(!json.includes('"kind"') && !json.includes('"detail"'));
    assert.ok(json.length < 16_000, `context is ${json.length} bytes; agent services accept 32 KiB`);
  }
});

test('the Searcher may cite any collapsed member id, never an unknown one', async () => {
  const sim = new Simulation();
  for (let i = 0; i < 20; i++) sim.tick();
  const context = prepareContext('searcher', sim.snapshot());
  const member = context.events[0].ids.at(-1);
  const decision = { summary: 'Routine reads only.', scenarioId: null, evidenceIds: [member], recommendationIds: [] };
  assert.deepEqual(validateDecision('searcher', decision, context), decision);
  assert.throws(() => validateDecision('searcher', { ...decision, evidenceIds: ['event-999999'] }, context));
  const result = await runAgent('searcher', sim.snapshot(), { infer: async () => decision });
  assert.equal(result.mode, 'model');
});

test('the rule fallback still finds the allowed attack operations after traffic resumes', async () => {
  const snap = afterScenario('credential-abuse', 12);
  const fallback = await runAgent('searcher', snap);
  assert.equal(fallback.mode, 'fallback');
  assert.ok(fallback.evidenceIds.length >= 1, 'fallback cites the stolen-password sign-in');
});
