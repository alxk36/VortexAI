import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Simulation } from '../src/simulation.mjs';
import { Runtime } from '../src/runtime.mjs';
import { prepareContext, validateDecision, runAgent, DECISION_SCHEMA } from '../ai/agents.mjs';

const seeded = seed => () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const golden = JSON.parse(readFileSync(new URL('./fixtures/scenario-golden.json', import.meta.url), 'utf8'));
const POLICY = { 'exposed-storage': 'storagePrivate', 'credential-abuse': 'requireMfa', 'lateral-movement': 'databaseLeastPrivilege' };
const finish = sim => { while (sim.snapshot().activeScenario) sim.tick(); return sim.snapshot(); };
const attackEvents = snap => snap.events.filter(e => !e.clientId && e.kind !== 'normal');
const base = { summary: 'New chain.', scenarioId: null, evidenceIds: [], recommendationIds: [], labels: [], suspects: [] };

test('the three scripted scenarios produce exactly the same events as before the refactor', () => {
  for (const id of Object.keys(POLICY)) for (const fixed of [false, true]) {
    const sim = new Simulation({ random: seeded(42) });
    if (fixed) sim._policies[POLICY[id]] = true;
    sim.runScenario(id);
    const s = finish(sim);
    const want = golden[`${id}:${fixed ? 'fixed' : 'vulnerable'}`];
    assert.deepEqual([...s.events].reverse(), want.events, `${id} ${fixed ? 'fixed' : 'vulnerable'}`);
    assert.deepEqual(s.findings.map(f => f.id), want.findings);
    assert.deepEqual(s.agents.attacker, want.attacker);
  }
});

test('the action catalog is public, names no controls, and lists what each step requires', () => {
  const { attackActions } = new Simulation().snapshot();
  assert.ok(attackActions.length >= 10);
  const json = JSON.stringify(attackActions);
  for (const hidden of ['storagePrivate', 'requireMfa', 'databaseLeastPrivilege', 'gatedBy']) assert.ok(!json.includes(hidden), `${hidden} leaked`);
  const byId = Object.fromEntries(attackActions.map(a => [a.id, a]));
  assert.deepEqual(byId['admin-request'].requires, ['stolen-password-signin']);
  assert.deepEqual(byId['exfiltrate'].requires, ['db-admin-export']);
});

test('a composed chain is validated before anything runs', () => {
  const sim = new Simulation();
  for (const actions of [[], ['discover', 'not-an-action'], Array(9).fill('discover'), ['admin-request'], ['exfiltrate', 'db-admin-export']]) {
    assert.throws(() => sim.runPlan({ actions }), /plan|action|requires|steps/i, JSON.stringify(actions));
  }
  assert.equal(sim.snapshot().activeScenario, null);
  sim.runScenario('exposed-storage');
  assert.throws(() => sim.runPlan({ actions: ['discover'] }), /already running/);
});

test('a composed chain mixing scenarios runs step by step and obeys the controls', () => {
  const chain = ['discover', 'storage-read', 'token-replay', 'app-flaw-request', 'db-admin-export', 'exfiltrate'];
  const open = new Simulation();
  open.runPlan({ actions: chain, name: 'Storage then database' });
  assert.equal(open.snapshot().activeScenario.total, chain.length);
  const done = finish(open);
  assert.deepEqual(attackEvents(done).reverse().map(e => [e.action, e.outcome]), [
    ['discover', 'allowed'], ['read-object', 'allowed'], ['token-replay', 'allowed'], ['application-request', 'allowed'], ['admin-export', 'allowed'], ['export-response', 'allowed']]);
  assert.equal(done.findings.length, 2, 'rules catch both weaknesses from a mixed chain');

  const hardened = new Simulation();
  hardened._policies.databaseLeastPrivilege = true;
  hardened.runPlan({ actions: chain });
  const blocked = finish(hardened);
  assert.deepEqual(attackEvents(blocked).slice(0, 2).map(e => [e.action, e.outcome]), [['export-denied-audit', 'denied'], ['admin-export', 'denied']]);
  assert.equal(blocked.agents.attacker.status, 'Blocked');
});

test('the Attacker may answer with its own chain, but only from the catalog and in a valid order', () => {
  assert.ok(DECISION_SCHEMA.required.includes('plan'));
  const context = prepareContext('attacker', new Simulation().snapshot());
  assert.ok(context.actions.length >= 10 && !JSON.stringify(context.actions).includes('storagePrivate'));
  const ok = { ...base, plan: ['stolen-password-signin', 'admin-request'] };
  assert.deepEqual(validateDecision('attacker', ok, context).plan, ok.plan);
  assert.throws(() => validateDecision('attacker', { ...ok, plan: ['admin-request'] }, context), /plan/i);
  assert.throws(() => validateDecision('attacker', { ...ok, plan: ['make-coffee'] }, context), /plan/i);
  assert.throws(() => validateDecision('attacker', { ...ok, scenarioId: 'exposed-storage' }, context), /plan/i, 'not both');
  assert.throws(() => validateDecision('searcher', { ...base, plan: ['discover'] }, prepareContext('searcher', {})), /plan/i);
  assert.deepEqual(prepareContext('attacker', context), context, 'idempotent');
});

test('an AI chain launches, is recorded in attack history, and is shown to the Attacker next time', async () => {
  const plan = ['discover', 'storage-list', 'storage-read'];
  const reply = { agent: 'attacker', mode: 'model', provider: 'anthropic', model: 'claude-opus-5-5', ...base, summary: 'Probe storage directly.', plan };
  const runtime = new Runtime({ container: true, agentToken: 'c'.repeat(32), fetchImpl: async () => Response.json(reply) });
  await runtime.runAI('attacker');
  assert.deepEqual(runtime.snapshot().activeScenario.plan, plan);
  for (let i = 0; i < 10 && runtime.snapshot().activeScenario; i++) await runtime.tick();
  const [entry] = runtime.snapshot().attackHistory;
  assert.deepEqual([entry.scenarioId, entry.result, entry.source, entry.plan], ['custom', 'succeeded', 'ai', plan]);
  assert.match(entry.name, /discover → storage-list → storage-read/);
  assert.deepEqual(runtime.snapshot().ai.runs[0].plan, plan);
  const context = prepareContext('attacker', runtime.snapshot());
  assert.deepEqual(context.history[0], { scenarioId: 'custom', plan, result: 'succeeded' });
});

test('real-service mode keeps the scripted scenarios only', async () => {
  const runtime = new Runtime({ container: false });
  runtime.mode = 'lab';
  runtime.realState = { activeScenario: null, events: [], metrics: {}, nodeSettings: {} };
  assert.equal(runtime.snapshot().attackActions, undefined);
  assert.deepEqual(prepareContext('attacker', runtime.snapshot()).actions, []);
  await assert.rejects(() => runtime.launchPlan(['discover'], 'ai'), /simulator/);
});

test('the rule fallback still picks scripted scenarios and never invents a chain', async () => {
  const result = await runAgent('attacker', new Simulation().snapshot());
  assert.deepEqual(result.plan, []);
  assert.equal(result.scenarioId, 'exposed-storage');
});
