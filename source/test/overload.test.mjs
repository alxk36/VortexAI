import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { Simulation } from '../src/simulation.mjs';

const seeded = seed => () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const ticks = (sim, n) => { for (let i = 0; i < n; i++) sim.tick(); return sim.snapshot(); };

test('users added gradually, and a steady 60 users, never overload the system', () => {
  const sim = new Simulation({ random: seeded(5) });
  for (const users of [10, 25, 40, 55, 60]) { sim.setTraffic({ users, bots: false }); ticks(sim, 5); }
  const snap = ticks(sim, 60);
  assert.equal(snap.running, true);
  assert.deepEqual(snap.traffic.overloads, []);
});

test('adding many users at once overloads the gateway and pauses the whole system', () => {
  const sim = new Simulation({ random: seeded(5) });
  sim.setTraffic({ users: 5, bots: false });
  ticks(sim, 3);
  sim.setTraffic({ users: 50, bots: false });
  const snap = ticks(sim, 1);
  assert.equal(snap.running, false, 'paused itself');
  const [overload] = snap.traffic.overloads;
  assert.equal(overload.tick, snap.tick);
  assert.ok(overload.requests >= overload.capacity);
  assert.match(overload.reason, /45 users joined at once/);
  assert.equal(snap.agents.searcher.status, 'System overloaded');
  assert.ok(snap.traffic.clients.length >= 45, 'the newcomers are real clients in the activity summary');
  assert.equal(ticks(sim, 3).tick, snap.tick, 'stays paused until the admin resumes');
  sim.setRunning(true);
  const resumed = ticks(sim, 10);
  assert.equal(resumed.running, true, 'normal load after resuming does not trip it again');
  assert.equal(resumed.traffic.overloads.length, 1);
});

test('the per-client tripwire contains simultaneous floods before they overload the system', () => {
  const sim = new Simulation({ random: seeded(9) });
  sim.setTraffic({ users: 20, bots: true });
  const ids = sim._traffic.userIds.slice(-3);
  sim._traffic.userIds = sim._traffic.userIds.slice(0, -3);
  sim._traffic.bots = ids.map(clientId => ({ clientId, behavior: 'request-flood', startTick: 2, nextFlood: 0 }));
  const snap = ticks(sim, 10);
  assert.equal(snap.traffic.autoBlocks.length, 3, 'each flooder was blocked on its own');
  assert.equal(snap.running, true, 'so the system as a whole stays up');
  assert.deepEqual(snap.traffic.overloads, []);
});

test('reset clears the overload log', () => {
  const sim = new Simulation({ random: seeded(5) });
  sim.setTraffic({ users: 1, bots: false });
  sim.setTraffic({ users: 60, bots: false });
  ticks(sim, 1);
  assert.equal(sim.snapshot().traffic.overloads.length, 1);
  sim.reset();
  assert.deepEqual(sim.snapshot().traffic.overloads, []);
});

test('the dashboard explains an overload and how to recover', () => {
  const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
  const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));
  const source = app.slice(app.indexOf('// Live traffic:'), app.indexOf('// End live traffic.'));
  const render = (traffic, running) => { const ctx = { traffic, running }; vm.runInNewContext(`${escapeLine}\n${source}\nresult = overloadMarkup(traffic, running);`, ctx); return ctx.result; };
  const traffic = { overloads: [{ tick: 12, requests: 49, capacity: 24, reason: '45 users joined at once: 49 requests in one tick (capacity 24)' }] };
  const paused = render(traffic, false);
  assert.match(paused, /System overloaded at tick 12/);
  assert.match(paused, /45 users joined at once/);
  assert.match(paused, /Resume/);
  assert.match(render(traffic, true), /Last overload at tick 12/);
  assert.equal(render({ overloads: [] }, false), '');
});
