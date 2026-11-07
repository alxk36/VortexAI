import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { Simulation } from '../src/simulation.mjs';
import { prepareContext, validateDecision, runAgent } from '../ai/agents.mjs';

const seeded = seed => () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const ticks = (sim, n) => { for (let i = 0; i < n; i++) sim.tick(); return sim.snapshot(); };
const base = { summary: 'ok', scenarioId: null, evidenceIds: [], recommendationIds: [], labels: [], suspects: [], plan: [] };

test('a client blocked again and again is one tripwire entry with a count', () => {
  const sim = new Simulation({ random: seeded(9) });
  sim.setTraffic({ users: 20, bots: true });
  const [flooder] = sim._traffic.userIds.slice(-1);
  sim._traffic.userIds = sim._traffic.userIds.slice(0, -1);
  sim._traffic.bots = [{ clientId: flooder, behavior: 'request-flood', startTick: 2, nextFlood: 0 }];
  const snap = ticks(sim, 80); // long enough for several 20-tick blocks to expire and re-trip
  const entries = snap.traffic.autoBlocks.filter(b => b.clientId === flooder);
  assert.equal(entries.length, 1);
  assert.ok(entries[0].count >= 2, `blocked ${entries[0].count} times`);
});

test('the tripwire log shows how many times a client was blocked', () => {
  const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
  const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));
  const source = app.slice(app.indexOf('// Live traffic:'), app.indexOf('// End live traffic.'));
  const ctx = { traffic: { blocked: [], autoBlocks: [{ clientId: '198.51.100.114', reason: '8 requests in one tick (limit 8)', count: 4 }, { clientId: '203.0.113.15', reason: '9 requests in one tick (limit 8)', count: 1 }] } };
  vm.runInNewContext(`${escapeLine}\n${source}\nresult = autoBlocksMarkup(traffic);`, ctx);
  assert.match(ctx.result, /198\.51\.100\.114.*blocked 4 times/);
  assert.ok(!/203\.0\.113\.15[^<]*blocked \d+ times/.test(ctx.result), 'no count for a single block');
});

/** Exposed storage found, its fix applied and verified by a blocked replay. */
function fixedStorage() {
  const sim = new Simulation();
  const run = id => { sim.runScenario(id); while (sim.snapshot().activeScenario) sim.tick(); };
  run('exposed-storage');
  sim.applyRecommendation('recommendation-storagePrivate');
  run('exposed-storage');
  run('credential-abuse'); // a second finding whose fix is still open
  return sim.snapshot();
}

test('the Builder sees fixes that are already applied, with their verification', () => {
  const context = prepareContext('builder', fixedStorage());
  const applied = context.recommendations.find(r => r.id === 'recommendation-storagePrivate');
  assert.deepEqual([applied.applied, applied.validation], [true, 'blocked-replay']);
  const open = context.recommendations.find(r => r.id === 'recommendation-requireMfa');
  assert.deepEqual([open.applied, open.validation], [false, 'pending']);
  assert.deepEqual(prepareContext('builder', context), context, 'idempotent');
});

test('the Builder may only rank fixes that are not applied yet', () => {
  const context = prepareContext('builder', fixedStorage());
  const ok = { ...base, recommendationIds: ['recommendation-requireMfa'] };
  assert.deepEqual(validateDecision('builder', ok, context).recommendationIds, ['recommendation-requireMfa']);
  assert.throws(() => validateDecision('builder', { ...base, recommendationIds: ['recommendation-storagePrivate'] }, context), /remediation|applied/i);
});

test('the Builder fallback says which fixes are already in place', async () => {
  const sim = new Simulation();
  sim.runScenario('exposed-storage'); while (sim.snapshot().activeScenario) sim.tick();
  sim.applyRecommendation('recommendation-storagePrivate');
  sim.runScenario('exposed-storage'); while (sim.snapshot().activeScenario) sim.tick();
  const result = await runAgent('builder', sim.snapshot());
  assert.deepEqual(result.recommendationIds, []);
  assert.match(result.summary, /already applied/i);
  assert.match(result.summary, /verified/i);
  const mixed = await runAgent('builder', fixedStorage());
  assert.deepEqual(mixed.recommendationIds, ['recommendation-requireMfa']);
  assert.match(mixed.summary, /already applied/i);
});
