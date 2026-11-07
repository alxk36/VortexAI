import test from 'node:test';
import assert from 'node:assert/strict';
import { Runtime } from '../src/runtime.mjs';
import { prepareContext, runAgent } from '../ai/agents.mjs';
import { inferClaude } from '../ai/anthropic.mjs';

// Simulator mode only: no Docker, no agent containers, no model calls.
const lab = () => new Runtime({ container: false });

async function finish(runtime) {
  for (let i = 0; i < 20 && runtime.snapshot().activeScenario; i++) await runtime.tick();
  assert.equal(runtime.snapshot().activeScenario, null, 'scenario should finish');
}
async function attack(runtime, id) { await runtime.runScenario(id); await finish(runtime); }
async function fix(runtime, policyKey) {
  const rec = runtime.snapshot().recommendations.find(r => r.policyKey === policyKey);
  await runtime.applyRecommendation(rec.id);
}

test('each finished attack is recorded as succeeded or blocked, newest first', async () => {
  const runtime = lab();
  await attack(runtime, 'exposed-storage');
  assert.deepEqual(runtime.snapshot().attackHistory.map(h => [h.scenarioId, h.result]), [['exposed-storage', 'succeeded']]);
  await fix(runtime, 'storagePrivate');
  await attack(runtime, 'exposed-storage');
  const [latest] = runtime.snapshot().attackHistory;
  assert.equal(latest.result, 'blocked');
  assert.deepEqual(latest.blockedBy, ['storagePrivate']);
  assert.equal(runtime.snapshot().attackHistory.length, 2);
});

test('failed password guesses alone do not count as a blocked attack', async () => {
  const runtime = lab();
  await attack(runtime, 'credential-abuse');
  assert.equal(runtime.snapshot().attackHistory[0].result, 'succeeded');
  await fix(runtime, 'requireMfa');
  await attack(runtime, 'credential-abuse');
  assert.equal(runtime.snapshot().attackHistory[0].result, 'blocked');
});

test('the Attacker sees its own outcomes, but not control names or policies', async () => {
  const runtime = lab();
  await attack(runtime, 'exposed-storage');
  await fix(runtime, 'storagePrivate');
  await attack(runtime, 'exposed-storage');
  const context = prepareContext('attacker', runtime.snapshot());
  assert.deepEqual(context.history, [
    { scenarioId: 'exposed-storage', result: 'blocked' },
    { scenarioId: 'exposed-storage', result: 'succeeded' },
  ]);
  const json = JSON.stringify(context);
  for (const hidden of ['storagePrivate', 'blockedBy', 'policies', 'requireMfa']) assert.ok(!json.includes(hidden), `${hidden} leaked`);
  assert.deepEqual(prepareContext('attacker', context), context, 'idempotent across trust boundaries');
});

test('the fallback Attacker moves to an untried path after a fix, then stops when all are blocked', async () => {
  const runtime = lab();
  await attack(runtime, 'exposed-storage');
  await fix(runtime, 'storagePrivate');
  await attack(runtime, 'exposed-storage');

  await runtime.runAI('attacker');
  assert.equal(runtime.snapshot().ai.runs[0].scenarioId, 'credential-abuse', 'skips the blocked storage path');
  assert.equal(runtime.snapshot().activeScenario?.id, 'credential-abuse');
  await finish(runtime);
  assert.deepEqual(runtime.snapshot().attackHistory[0], { ...runtime.snapshot().attackHistory[0], scenarioId: 'credential-abuse', result: 'succeeded', source: 'ai' });

  await fix(runtime, 'requireMfa');
  await runtime.runAI('attacker');
  assert.equal(runtime.snapshot().ai.runs[0].scenarioId, 'lateral-movement');
  await finish(runtime);
  await fix(runtime, 'databaseLeastPrivilege');
  // Replay the two newer fixes so every path's latest attempt is blocked.
  await attack(runtime, 'credential-abuse');
  await attack(runtime, 'lateral-movement');

  await runtime.runAI('attacker');
  const last = runtime.snapshot().ai.runs[0];
  assert.equal(last.scenarioId, null);
  assert.match(last.summary, /blocked/i);
  assert.equal(runtime.snapshot().activeScenario, null, 'nothing runs when every known path is blocked');
});

test('a path whose last attempt succeeded is retried before giving up', async () => {
  const result = await runAgent('attacker', {
    scenarios: [{ id: 'exposed-storage', name: 'Exposed storage' }, { id: 'credential-abuse', name: 'Credential abuse' }],
    attackHistory: [{ scenarioId: 'exposed-storage', result: 'blocked' }, { scenarioId: 'credential-abuse', result: 'succeeded' }],
  });
  assert.equal(result.scenarioId, 'credential-abuse');
});

test('history reaches the model request, and reset clears it', async () => {
  const runtime = lab();
  await attack(runtime, 'exposed-storage');
  let sent;
  await inferClaude('attacker', runtime.snapshot(), { apiKey: 'test-only', fetchImpl: async (_url, options) => {
    sent = JSON.parse(JSON.parse(options.body).messages[0].content);
    return Response.json({ stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify({ summary: 'Try credentials next.', scenarioId: 'credential-abuse', evidenceIds: [], recommendationIds: [] }) }] });
  } });
  assert.deepEqual(sent.history, [{ scenarioId: 'exposed-storage', result: 'succeeded' }]);
  await runtime.reset();
  assert.deepEqual(runtime.snapshot().attackHistory, []);
});
