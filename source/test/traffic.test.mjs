import test from 'node:test';
import assert from 'node:assert/strict';
import { Simulation } from '../src/simulation.mjs';
import { Runtime } from '../src/runtime.mjs';
import { prepareContext, validateDecision, runAgent, DECISION_SCHEMA } from '../ai/agents.mjs';

// Seeded randomness keeps every run of this file identical.
function seeded(seed) {
  return () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const ticks = (sim, n) => { for (let i = 0; i < n; i++) sim.tick(); return sim.snapshot(); };
/** A crowd with exactly one bot of each behavior, so every test sees all three. */
function crowdWithBots(users = 30, seed = 7) {
  const sim = new Simulation({ random: seeded(seed) });
  sim.setTraffic({ users, bots: true });
  const [a, b, c] = sim._traffic.userIds.slice(-3);
  sim._traffic.userIds = sim._traffic.userIds.slice(0, -3);
  sim._traffic.bots = [
    { clientId: a, behavior: 'credential-stuffing', startTick: 2, nextFlood: 0 },
    { clientId: b, behavior: 'storage-scraping', startTick: 2, nextFlood: 0 },
    { clientId: c, behavior: 'request-flood', startTick: 2, nextFlood: 0 },
  ];
  return { sim, stuffer: a, scraper: b, flooder: c };
}
const row = (snap, id) => snap.traffic.clients.find(c => c.clientId === id);

test('default traffic is unchanged: one user, one chain per tick, no bots', () => {
  const sim = new Simulation();
  const snap = ticks(sim, 1);
  assert.equal(snap.events.length, 9);
  assert.deepEqual([snap.traffic.users, snap.traffic.botsEnabled, snap.traffic.clients.length], [1, false, 1]);
});

test('traffic settings are validated and locked while a scenario runs', () => {
  const sim = new Simulation();
  for (const bad of [{ users: 0, bots: false }, { users: 61, bots: false }, { users: 1.5, bots: false }, { users: '5', bots: false }, { users: 5, bots: 'yes' }]) {
    assert.throws(() => sim.setTraffic(bad));
  }
  sim.runScenario('exposed-storage');
  assert.throws(() => sim.setTraffic({ users: 10, bots: true }), /scenario/);
});

test('bots stay hidden in every snapshot until the admin reveals them', () => {
  const sim = new Simulation({ random: seeded(3) });
  sim.setTraffic({ users: 30, bots: true });
  const snap = ticks(sim, 30);
  const json = JSON.stringify(snap);
  for (const secret of ['credential-stuffing', 'storage-scraping', 'request-flood', 'behavior']) assert.ok(!json.includes(secret), `${secret} leaked`);
  assert.ok(snap.events.every(e => e.kind !== 'attack'), 'bot events never carry the attack label');
  assert.equal(snap.traffic.revealed, null);
  const bots = sim._traffic.bots.map(b => b.clientId);
  assert.ok(bots.length >= 1 && bots.length <= 3);
  const revealed = sim.revealBots();
  assert.deepEqual(revealed.bots.map(b => b.clientId), bots);
  assert.deepEqual(sim.snapshot().traffic.revealed.bots.map(b => b.clientId), bots);
});

test('each bot behavior leaves a behavioral trace that ordinary users do not', () => {
  const { sim, stuffer, scraper, flooder } = crowdWithBots();
  const snap = ticks(sim, 25);
  assert.ok(row(snap, stuffer).failedSignIns >= 5 && row(snap, stuffer).accountsTried >= 4, 'credential stuffing');
  assert.ok(row(snap, scraper).anonymousStorage >= 4, 'storage scraping');
  assert.ok(row(snap, flooder).peakPerTick >= 8, 'request flood');
  const users = snap.traffic.clients.filter(c => ![stuffer, scraper, flooder].includes(c.clientId));
  assert.ok(users.length > 10);
  for (const u of users) {
    assert.ok(u.failedSignIns <= 2 && u.accountsTried <= 2 && u.peakPerTick <= 3 && u.anonymousStorage === 0, `${u.clientId} looks like a bot: ${JSON.stringify(u)}`);
  }
});

test('the Searcher tripwire blocks a flood, logs it, and the admin can lift it', () => {
  const { sim, flooder } = crowdWithBots();
  let snap = sim.snapshot();
  for (let i = 0; i < 15 && !snap.traffic.autoBlocks.length; i++) snap = ticks(sim, 1);
  const [block] = snap.traffic.autoBlocks;
  assert.equal(block.clientId, flooder);
  assert.match(block.reason, /requests in one tick/);
  assert.equal(snap.agents.searcher.status, 'Auto-blocked client');
  assert.ok(snap.traffic.blocked.some(b => b.clientId === flooder));
  const denied = snap.events.filter(e => e.clientId === flooder && e.control === 'autoBlock');
  assert.ok(denied.length > 0 && denied.every(e => e.outcome === 'denied'));
  sim.unblockClient(flooder);
  assert.ok(!sim.snapshot().traffic.blocked.some(b => b.clientId === flooder));
  assert.throws(() => sim.unblockClient('203.0.113.250'), /not blocked/);
});

test('a tripwire block expires on its own', () => {
  const { sim, flooder } = crowdWithBots();
  let snap = ticks(sim, 3);
  for (let i = 0; i < 10 && !snap.traffic.autoBlocks.length; i++) snap = ticks(sim, 1);
  sim._traffic.bots = sim._traffic.bots.filter(b => b.clientId !== flooder); // stop flooding
  snap = ticks(sim, 21);
  assert.ok(!snap.traffic.blocked.some(b => b.clientId === flooder));
});

test('ordinary users alone never trip the breaker or look suspicious to the fallback', async () => {
  const sim = new Simulation({ random: seeded(11) });
  sim.setTraffic({ users: 60, bots: false });
  const snap = ticks(sim, 60);
  assert.deepEqual(snap.traffic.autoBlocks, []);
  const result = await runAgent('searcher', snap);
  assert.deepEqual(result.suspects, []);
});

test('the Searcher sees per-client activity and may name only listed clients as suspects', async () => {
  assert.ok(DECISION_SCHEMA.required.includes('suspects'));
  const { sim, stuffer, scraper, flooder } = crowdWithBots();
  const snap = ticks(sim, 25);
  const context = prepareContext('searcher', snap);
  assert.ok(context.clients.length > 10);
  assert.deepEqual(Object.keys(context.clients[0]).sort(), ['accountsTried', 'anonymousStorage', 'clientId', 'denied', 'failedSignIns', 'lastSeenTick', 'peakPerTick', 'requests', 'successfulSignIns']);
  assert.deepEqual(prepareContext('searcher', context), context, 'idempotent across trust boundaries');
  assert.ok(JSON.stringify(context).length < 28_000, 'fits the 32 KiB agent request limit');
  const base = { summary: 'Three automated clients.', scenarioId: null, evidenceIds: [], recommendationIds: [], labels: [], suspects: [], plan: [] };
  assert.deepEqual(validateDecision('searcher', { ...base, suspects: [stuffer] }, context).suspects, [stuffer]);
  assert.throws(() => validateDecision('searcher', { ...base, suspects: ['198.51.100.1'] }, context), /suspect/i);
  assert.throws(() => validateDecision('builder', { ...base, suspects: [stuffer] }, prepareContext('builder', snap)), /suspect/i);
  const fallback = await runAgent('searcher', snap);
  assert.deepEqual([...fallback.suspects].sort(), [stuffer, scraper, flooder].sort());
});

test('the dashboard scores the Searcher against the revealed bots', async () => {
  const runtime = new Runtime({ container: false });
  runtime.simulation = crowdWithBots().sim;
  for (let i = 0; i < 25; i++) await runtime.tick();
  await runtime.runAI('searcher');
  await runtime.revealBots();
  const score = runtime.snapshot().botScore;
  assert.equal(score.bots.length, 3);
  assert.equal(score.caught.length, 3);
  assert.deepEqual([score.missed, score.falseAlarms], [[], []]);
  assert.equal(score.searcherMode, 'fallback');
  await runtime.reset();
  assert.equal(runtime.snapshot().botScore, null);
});

test('bot denials never make an admin scenario look blocked', async () => {
  const runtime = new Runtime({ container: false });
  const { sim } = crowdWithBots();
  runtime.simulation = sim;
  sim._policies.storagePrivate = true; // the scraper is now denied with a control on every try
  await runtime.runScenario('credential-abuse');
  for (let i = 0; i < 10 && runtime.snapshot().activeScenario; i++) await runtime.tick();
  assert.ok(runtime.snapshot().events.some(e => e.clientId && e.control === 'storagePrivate' && e.outcome === 'denied'), 'precondition: bot was denied');
  assert.equal(runtime.snapshot().attackHistory[0].result, 'succeeded');
});

test('traffic controls are simulator-only', async () => {
  const runtime = new Runtime({ container: false });
  runtime.mode = 'lab';
  await assert.rejects(() => runtime.setTraffic({ users: 10, bots: true }), /simulator/);
  await assert.rejects(() => runtime.revealBots(), /simulator/);
});
