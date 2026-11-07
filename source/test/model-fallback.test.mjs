import test from 'node:test';
import assert from 'node:assert/strict';
import { inferClaude } from '../ai/anthropic.mjs';
import { createBroker } from '../ai/broker.mjs';
import { callBroker } from '../ai/agent-service.mjs';
import { runAgent } from '../ai/agents.mjs';
import { Runtime } from '../src/runtime.mjs';

const context = {
  scenarios: [{ id: 'exposed-storage', name: 'Exposed storage' }, { id: 'credential-abuse', name: 'Credential abuse' }],
  attackHistory: [{ scenarioId: 'exposed-storage', result: 'blocked' }],
  events: [], findings: [], recommendations: [],
};
const choice = { summary: 'Storage was fixed; try credentials.', scenarioId: 'credential-abuse', evidenceIds: [], recommendationIds: [], labels: [] };
const text = value => ({ type: 'text', text: JSON.stringify(value) });
const switched = { type: 'fallback', from: { model: 'claude-opus-5-5' }, to: { model: 'claude-opus-4-8' } };
const fallbackReply = (content = [switched, text(choice)]) => Response.json({
  model: 'claude-opus-4-8', stop_reason: 'end_turn', content,
  usage: { iterations: [{ type: 'message', model: 'claude-opus-5-5' }, { type: 'fallback_message', model: 'claude-opus-4-8' }] },
});

test('only the Attacker opts into Anthropic server-side fallback', async () => {
  const seen = {};
  for (const agent of ['attacker', 'searcher', 'builder']) {
    const reply = agent === 'attacker' ? choice : { ...choice, scenarioId: null };
    await inferClaude(agent, context, { apiKey: 'test-only', fetchImpl: async (_url, options) => {
      seen[agent] = { beta: options.headers['anthropic-beta'], fallbacks: JSON.parse(options.body).fallbacks, model: JSON.parse(options.body).model };
      return Response.json({ model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [text(reply)] });
    } }).catch(() => {});
  }
  assert.deepEqual(seen.attacker, { beta: 'server-side-fallback-2026-07-01', fallbacks: 'default', model: 'claude-opus-5-5' });
  for (const agent of ['searcher', 'builder']) assert.deepEqual(seen[agent], { beta: undefined, fallbacks: undefined, model: 'claude-opus-5-5' });
});

test('a fallback answer is accepted and reports the model that served it', async () => {
  let servedBy;
  const decision = await inferClaude('attacker', context, { apiKey: 'test-only', onModel: m => { servedBy = m; }, fetchImpl: async () => fallbackReply() });
  assert.deepEqual(decision, choice);
  assert.equal(servedBy, 'claude-opus-4-8');
});

test('text written before the switch point is ignored', async () => {
  const partial = { type: 'text', text: '{"summary":"Exposed sto' };
  const decision = await inferClaude('attacker', context, { apiKey: 'test-only', fetchImpl: async () => fallbackReply([partial, switched, text(choice)]) });
  assert.deepEqual(decision, choice);
});

test('a refusal by the whole chain, or an unexpected serving model, still fails closed', async () => {
  const refused = async () => Response.json({ model: 'claude-opus-4-8', stop_reason: 'refusal', content: [switched], stop_details: { type: 'refusal', category: 'cyber' } });
  await assert.rejects(() => inferClaude('attacker', context, { apiKey: 'test-only', fetchImpl: refused }));
  const odd = async () => Response.json({ model: 'some-other-model', stop_reason: 'end_turn', content: [text(choice)] });
  await assert.rejects(() => inferClaude('attacker', context, { apiKey: 'test-only', fetchImpl: odd }), /model/i);
  const result = await runAgent('attacker', context, { infer: (agent, ctx) => inferClaude(agent, ctx, { apiKey: 'test-only', fetchImpl: refused }) });
  assert.equal(result.mode, 'fallback');
});

test('the broker and agent service carry servedBy through, and drop unknown values', async () => {
  const token = 'b'.repeat(32);
  const broker = createBroker({ token, apiKey: 'test-only', infer: async (_agent, _ctx, { onModel }) => { onModel('claude-opus-4-8'); return choice; } });
  await new Promise(resolve => broker.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${broker.address().port}/infer`;
    const viaBroker = async (input, options) => fetch(url, options);
    const result = await callBroker('attacker', context, { token, fetchImpl: viaBroker });
    assert.equal(result.mode, 'model');
    assert.equal(result.model, 'claude-opus-5-5', 'model stays the requested model');
    assert.equal(result.servedBy, 'claude-opus-4-8');
  } finally { broker.close(); }
  const forged = await callBroker('attacker', context, { token, fetchImpl: async () => Response.json({
    agent: 'attacker', mode: 'model', provider: 'anthropic', model: 'claude-opus-5-5', servedBy: 'evil-model', ...choice }) });
  assert.equal(forged.servedBy, undefined);
});

test('the dashboard run says which model answered when the fallback served it', async () => {
  const runtime = new Runtime({ container: true, agentToken: 'c'.repeat(32), fetchImpl: async () => Response.json({
    agent: 'attacker', mode: 'model', provider: 'anthropic', model: 'claude-opus-5-5', servedBy: 'claude-opus-4-8', ...choice }) });
  await runtime.runAI('attacker');
  const [run] = runtime.snapshot().ai.runs;
  assert.equal(run.mode, 'model');
  assert.equal(run.servedBy, 'claude-opus-4-8');
  assert.match(runtime.snapshot().ai.detail, /claude-opus-4-8/);
  assert.match(runtime.snapshot().ai.detail, /fallback/i);
  assert.equal(runtime.snapshot().activeScenario?.id, 'credential-abuse');
});
