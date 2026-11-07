import test from 'node:test';
import assert from 'node:assert/strict';
import { Simulation } from '../src/simulation.mjs';
import { Runtime } from '../src/runtime.mjs';
import { prepareContext, validateDecision, runAgent, DECISION_SCHEMA } from '../ai/agents.mjs';
import { inferClaude } from '../ai/anthropic.mjs';
import { callBroker } from '../ai/agent-service.mjs';

// internal = a weakness created by people with access (misconfiguration, excess permissions)
// external = outsiders forcing their way in (credential guessing and abuse, identity abuse)
function afterScenario(id) {
  const sim = new Simulation();
  sim.runScenario(id);
  while (sim.snapshot().activeScenario) sim.tick();
  return sim.snapshot();
}
const base = { summary: 'ok', scenarioId: null, evidenceIds: [], recommendationIds: [], labels: [], suspects: [] };

test('the decision schema requires labels with an internal/external origin', () => {
  assert.ok(DECISION_SCHEMA.required.includes('labels'));
  const item = DECISION_SCHEMA.properties.labels.items;
  assert.deepEqual(item.properties.origin.enum, ['internal', 'external']);
  assert.equal(item.additionalProperties, false);
  assert.deepEqual(item.required, ['id', 'origin']);
});

test('labels may only name what the role cited, with a valid origin, once', () => {
  const snap = afterScenario('exposed-storage');
  const search = prepareContext('searcher', snap);
  const cited = snap.findings[0].evidence[0];
  const ok = { ...base, evidenceIds: [cited], labels: [{ id: cited, origin: 'internal' }] };
  assert.deepEqual(validateDecision('searcher', ok, search), ok);
  assert.throws(() => validateDecision('searcher', { ...ok, labels: [{ id: 'event-1', origin: 'internal' }] }, search), /label/i);
  assert.throws(() => validateDecision('searcher', { ...ok, labels: [{ id: cited, origin: 'insider' }] }, search), /label/i);
  assert.throws(() => validateDecision('searcher', { ...ok, labels: [{ id: cited, origin: 'internal' }, { id: cited, origin: 'external' }] }, search), /label/i);
  assert.throws(() => validateDecision('searcher', { ...ok, labels: [{ id: cited, origin: 'internal', note: 'x' }] }, search), /label/i);
  assert.throws(() => validateDecision('searcher', { summary: 'ok', scenarioId: null, evidenceIds: [], recommendationIds: [] }, search), /schema/i);

  const builder = prepareContext('builder', snap);
  const rec = builder.recommendations[0].id;
  const advice = { ...base, recommendationIds: [rec], labels: [{ id: rec, origin: 'internal' }] };
  assert.deepEqual(validateDecision('builder', advice, builder), advice);
  assert.throws(() => validateDecision('builder', { ...advice, labels: [{ id: 'recommendation-other', origin: 'internal' }] }, builder), /label/i);

  const attacker = prepareContext('attacker', snap);
  assert.throws(() => validateDecision('attacker', { ...base, scenarioId: 'credential-abuse', labels: [{ id: 'x', origin: 'external' }] }, attacker));
});

test('the rule fallback labels misconfigurations internal and credential attacks external', async () => {
  const expected = { 'exposed-storage': 'internal', 'lateral-movement': 'internal', 'credential-abuse': 'external' };
  for (const [scenario, origin] of Object.entries(expected)) {
    const snap = afterScenario(scenario);
    const searcher = await runAgent('searcher', snap);
    assert.ok(searcher.labels.length > 0, `${scenario}: searcher labels`);
    assert.ok(searcher.labels.every(l => l.origin === origin && searcher.evidenceIds.includes(l.id)), `${scenario}: searcher says ${JSON.stringify(searcher.labels)}`);
    const builder = await runAgent('builder', snap);
    assert.deepEqual(builder.labels, builder.recommendationIds.map(id => ({ id, origin })), `${scenario}: builder`);
  }
  const attacker = await runAgent('attacker', afterScenario('exposed-storage'));
  assert.deepEqual(attacker.labels, []);
});

test('labels reach the model as part of the strict output schema', async () => {
  let schema;
  const snap = afterScenario('credential-abuse');
  const cited = snap.findings[0].evidence.at(-1);
  await inferClaude('searcher', snap, { apiKey: 'test-only', fetchImpl: async (_url, options) => {
    schema = JSON.parse(options.body).output_config.format.schema;
    return Response.json({ stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify({ ...base, evidenceIds: [cited], labels: [{ id: cited, origin: 'external' }] }) }] });
  } });
  assert.ok(schema.required.includes('labels'));
});

test('labels survive the agent service and the dashboard runtime', async () => {
  const snap = afterScenario('exposed-storage');
  const rec = snap.recommendations[0].id;
  const reply = { agent: 'builder', mode: 'model', provider: 'anthropic', model: 'claude-opus-5-5', ...base, recommendationIds: [rec], labels: [{ id: rec, origin: 'internal' }] };
  const viaService = await callBroker('builder', snap, { token: 'a'.repeat(32), fetchImpl: async () => Response.json(reply) });
  assert.deepEqual(viaService.labels, [{ id: rec, origin: 'internal' }]);

  const runtime = new Runtime({ container: true, agentToken: 'c'.repeat(32), fetchImpl: async () => Response.json(reply) });
  runtime.simulation.runScenario('exposed-storage');
  while (runtime.simulation.snapshot().activeScenario) runtime.simulation.tick();
  await runtime.runAI('builder');
  assert.deepEqual(runtime.snapshot().ai.runs[0].labels, [{ id: rec, origin: 'internal' }]);
});
