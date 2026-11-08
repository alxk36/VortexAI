import test from 'node:test';
import assert from 'node:assert/strict';
import { Simulation, WEAK_SPOT_POOL } from '../src/simulation.mjs';
import { Runtime } from '../src/runtime.mjs';
import { Hacker, rewardFor, HACKER_ADDRESSES } from '../src/hacker.mjs';
import { performanceReport } from '../src/performance.mjs';
import { prepareContext } from '../ai/agents.mjs';

const seeded = seed => () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const finish = sim => { while (sim.snapshot().activeScenario) sim.tick(); return sim.snapshot(); };
const runChain = (sim, actions) => { sim.runPlan({ actions }); return finish(sim); };
const attackEvents = snap => snap.events.filter(e => !e.clientId && e.kind !== 'normal').reverse();
const runtime = (seed = 3) => new Runtime({ simulation: new Simulation({ layout: 'random', random: seeded(seed) }), container: false, hacker: new Hacker({ random: seeded(seed + 1) }) });
async function ticks(rt, n) { for (let i = 0; i < n; i++) { await rt.tick(); if (!rt.simulation.running) await rt.setRunning(true); } }

test('the classic layout keeps the original three weak spots; the new controls start in place', () => {
  const { policies, weakSpots } = new Simulation().snapshot();
  assert.deepEqual(weakSpots, ['storagePrivate', 'requireMfa', 'databaseLeastPrivilege']);
  assert.deepEqual(Object.keys(policies), WEAK_SPOT_POOL);
  for (const key of WEAK_SPOT_POOL) assert.equal(policies[key], !weakSpots.includes(key), key);
});

test('a randomized layout draws three or four weak spots, and a reset draws again', () => {
  const sim = new Simulation({ layout: 'random', random: seeded(9) });
  const layouts = new Set();
  for (let i = 0; i < 12; i++) {
    const { weakSpots, policies } = sim.reset();
    assert.ok(weakSpots.length === 3 || weakSpots.length === 4, `${weakSpots.length} weak spots`);
    for (const key of WEAK_SPOT_POOL) assert.equal(policies[key], !weakSpots.includes(key));
    layouts.add(weakSpots.join());
  }
  assert.ok(layouts.size >= 4, 'resets produce different clouds');
  assert.throws(() => new Simulation({ layout: 'fixed' }), /layout/);
});

test('stolen metadata credentials read storage even when storage is private, until metadata is protected', () => {
  const open = new Simulation();
  open._policies.metadataProtection = false;
  open._policies.storagePrivate = true;
  const done = runChain(open, ['discover', 'metadata-ssrf', 'cloud-key-use']);
  assert.deepEqual(attackEvents(done).map(e => [e.action, e.outcome]), [['discover', 'allowed'], ['metadata-request', 'allowed'], ['read-object', 'allowed']]);
  const finding = done.findings.find(f => f.policyKey === 'metadataProtection');
  assert.ok(finding && finding.evidence.length === 2, 'the request and the key use are both evidence');
  open.applyRecommendation(finding.recommendationId);
  const replay = runChain(open, ['discover', 'metadata-ssrf', 'cloud-key-use']);
  assert.deepEqual(attackEvents(replay).slice(-2).map(e => [e.action, e.outcome]), [['metadata-request', 'denied'], ['read-object', 'denied']]);
  assert.equal(replay.recommendations.find(r => r.policyKey === 'metadataProtection').validation, 'blocked-replay');
});

test('a key in the public app bundle unlocks the admin API until it is moved and rotated', () => {
  const sim = new Simulation();
  sim._policies.secretsManager = false;
  const done = runChain(sim, ['bundle-scrape', 'api-key-use']);
  assert.equal(attackEvents(done).at(-1).outcome, 'allowed');
  const rec = done.recommendations.find(r => r.policyKey === 'secretsManager');
  sim.applyRecommendation(rec.id);
  const replay = runChain(sim, ['bundle-scrape', 'api-key-use']);
  assert.equal(attackEvents(replay).at(-1).outcome, 'denied');
  assert.equal(replay.recommendations.find(r => r.policyKey === 'secretsManager').validation, 'blocked-replay');
});

test('password spraying works without lockout; lockout refuses the right guess after five failures', () => {
  const open = new Simulation();
  open._policies.accountLockout = false;
  const done = runChain(open, ['password-spray']);
  const signIns = attackEvents(done).filter(e => e.action === 'sign-in');
  assert.deepEqual(signIns.map(e => e.outcome), ['denied', 'denied', 'denied', 'denied', 'denied', 'allowed']);
  assert.ok(done.findings.some(f => f.policyKey === 'accountLockout'));
  assert.ok(!done.findings.some(f => f.policyKey === 'requireMfa'), 'the legacy sign-in is not an MFA finding');
  const locked = new Simulation(); // lockout is on in the classic layout
  assert.equal(attackEvents(runChain(locked, ['password-spray'])).at(-1).control, 'accountLockout');
});

test('a successful sign-in clears the failure count, so repeated credential abuse is not locked out', () => {
  const sim = new Simulation();
  sim.runScenario('credential-abuse'); finish(sim);
  sim.runScenario('credential-abuse');
  const second = attackEvents(finish(sim)).filter(e => e.action === 'sign-in').at(-1);
  assert.equal(second.outcome, 'allowed');
});

test('three failed sign-ins from one address in one tick trip the tripwire', () => {
  const sim = new Simulation();
  for (let i = 0; i < 3; i++) sim.hackerEmit({ source: 'attacker', target: 'iam', action: 'sign-in', outcome: 'denied', kind: 'blocked', principal: 'lab-admin' }, '192.0.2.10');
  assert.match(sim.snapshot().traffic.autoBlocks[0].reason, /3 failed sign-ins in one tick/);
  const blocked = sim.hackerEmit({ source: 'attacker', target: 'storage', action: 'list-objects', outcome: 'allowed', principal: 'anonymous', control: 'storagePrivate' }, '192.0.2.10');
  assert.equal(blocked.control, 'autoBlock');
  assert.equal(blocked.outcome, 'denied');
});

test('the reward favors breaches and data, and charges for blocks, tripwires, rotation and time', () => {
  assert.equal(rewardFor({ breached: ['storagePrivate'], tookData: true, ticks: 1 }), 1.95);
  assert.equal(rewardFor({ breached: [], ticks: 1 }), -1.05);
  assert.equal(rewardFor({ breached: [], blockedBy: ['requireMfa'], tripped: true, ticks: 2 }), -2.6);
  assert.equal(rewardFor({ breached: ['secretsManager'], spread: 'rotate', ticks: 3 }), 0.55);
});

test('the Hacker enters as an internet client, only with catalog steps, and never leaves the model', () => {
  const sim = new Simulation({ layout: 'random', random: seeded(4) });
  const hacker = new Hacker({ random: seeded(5) });
  hacker.enabled = true;
  const events = [];
  const emit = sim.hackerEmit.bind(sim);
  sim.hackerEmit = (fields, clientId) => { const event = emit(fields, clientId); events.push(event); return event; };
  for (let i = 0; i < 80; i++) { sim.tick(); sim.running = true; hacker.tick(sim); }
  assert.ok(events.length > 10);
  for (const e of events) {
    assert.ok(HACKER_ADDRESSES.includes(e.clientId), e.clientId);
    assert.ok(![e.source, e.target].includes('attacker'), 'it arrives through the client edge');
  }
  assert.throws(() => sim.hackerParts(['discover', 'rm -rf']), /unknown attack action/);
});

test('the Hacker learns: it finds a breach, loses interest once fixes hold, and starts the next run ahead', async () => {
  const rt = runtime(3);
  await rt.setHacker(true);
  await ticks(rt, 120);
  let state = rt.snapshot();
  const runOne = state.hacker.runs.find(r => r.run === rt.runNumber);
  assert.ok(runOne.breaches > 0 && runOne.firstBreachAt !== null);
  assert.ok(state.learningLogs.some(l => l.agent === 'hacker' && /First breach this run/.test(l.text)));
  for (const r of state.recommendations.filter(r => !r.applied)) await rt.applyRecommendation(r.id);
  await ticks(rt, 150);
  state = rt.snapshot();
  assert.equal(state.performance.builder.after.breaches, 0, 'no breach on a fixed path');
  assert.ok(state.performance.builder.after.attempts > 0, 'the Hacker kept testing the fixed paths');
  assert.match(state.performance.lines.hacker, /attempts got through/);
  assert.ok(state.hacker.trend.recent < 1, 'its reward fell once the fixes held');

  const favorite = state.hacker.best;
  await rt.reset(); await rt.setRunning(true);
  const carried = rt.snapshot().hacker;
  assert.ok(carried.remembered > 0 && carried.remembered <= 5, 'its best few attacks survive a reset');
  assert.deepEqual(carried.best.chain, favorite.chain, 'its favorite comes along');
  assert.equal(carried.best.value, Math.round(favorite.value * 50) / 100, 'trusted half as much on a new cloud');
  await ticks(rt, 120);
  const runTwo = rt.snapshot().hacker.runs.find(r => r.run === rt.runNumber);
  assert.ok(runTwo.attempts > 0);
  assert.match(rt.snapshot().performance.lines.hacker, /got through \(\d+%\)/);

  await rt.forgetHacker();
  assert.equal(rt.snapshot().hacker.remembered, 0);
  assert.match(rt.snapshot().learningLogs[0].text, /Learning wiped/);
});

test('a Hacker breach on a fixed path fails the fix and the verdict', async () => {
  const rt = new Runtime({ simulation: new Simulation(), container: false, hacker: new Hacker({ random: seeded(1) }) });
  rt.simulation._policies.secretsManager = false;
  rt.simulation._weakSpots = ['secretsManager'];
  rt.hacker.arms.set('x', { key: 'x', chain: ['bundle-scrape', 'api-key-use'], pace: 'slow', spread: 'single', tries: 1, value: 2, wins: 1, lastReward: 2 });
  await rt.setHacker(true);
  await ticks(rt, 12);
  const rec = rt.snapshot().recommendations.find(r => r.policyKey === 'secretsManager');
  await rt.applyRecommendation(rec.id);
  await ticks(rt, 12);
  assert.equal(rt.snapshot().performance.verdict.status, 'defended');
  rt.simulation._policies.secretsManager = false; // the control silently stops working
  await ticks(rt, 30);
  const { verdict } = rt.snapshot().performance;
  assert.equal(verdict.status, 'failing');
  assert.ok(rt.snapshot().learningLogs.some(l => l.agent === 'builder' && /the Hacker got through/.test(l.text)));
});

test('a Searcher run that names a Hacker address flags that address\'s attempts', async () => {
  const rt = new Runtime({ simulation: new Simulation(), container: false, hacker: new Hacker({ random: seeded(2) }) });
  rt.simulation._policies.storagePrivate = true; // blocked quietly: no finding, no tripwire
  rt.hacker.arms.set('x', { key: 'x', chain: ['storage-list', 'storage-read'], pace: 'slow', spread: 'single', tries: 1, value: 2, wins: 1, lastReward: 2 });
  await rt.setHacker(true);
  await ticks(rt, 8);
  const attempts = rt.hacker.attempts;
  assert.ok(attempts.length && attempts.every(a => !a.flagged));
  await rt.runAI('searcher'); // rule fallback names clients with repeated anonymous storage access
  assert.ok(rt.runs[0].suspects.includes(rt.hacker.home));
  assert.ok(attempts.every(a => a.flagged));
  assert.match(rt.snapshot().performance.lines.searcher, new RegExp(`${attempts.length} of ${attempts.length} Hacker attempt`));
});

test('performance counts weak spots for this run and adds a Hacker line only when asked', () => {
  const report = performanceReport({ weakSpots: ['metadataProtection', 'secretsManager'], hacker: { attempts: [
    { runAttempt: 1, breached: [], touched: [], endTick: 3 },
    { runAttempt: 2, breached: ['secretsManager'], touched: ['secretsManager'], endTick: 6, flagged: true },
  ], previousFirstBreach: 5, trend: { early: -1.2, recent: 1.5 } } });
  assert.equal(report.attacker.total, 2);
  assert.equal(report.lines.hacker, '1 of 2 attempts got through (50%) · found 1 of 2 weak spots · first breach: attempt 2 · avg reward -1.2 → +1.5');
  assert.equal(report.verdict.status, 'at-risk');
  assert.equal(performanceReport({}).lines.hacker, undefined);
});

test('the Claude agents get notes from earlier runs; the Attacker only sees outsider results', async () => {
  const rt = new Runtime({ simulation: new Simulation(), container: false });
  await rt.runScenario('exposed-storage');
  await ticks(rt, 5);
  const rec = rt.snapshot().recommendations[0];
  await rt.applyRecommendation(rec.id);
  await rt.reset();
  const snap = rt.snapshot();
  const attacker = prepareContext('attacker', snap);
  assert.deepEqual(attacker.earlierRuns, [{ run: 1, scenarioId: 'exposed-storage', result: 'succeeded' }]);
  assert.ok(!JSON.stringify(attacker).match(/storagePrivate|private storage|blockedBy/));
  const builder = prepareContext('builder', snap);
  assert.deepEqual(builder.notes, ['Run 1: Applied: Make object storage private.']);
  assert.deepEqual(prepareContext('searcher', snap).notes, []);
  for (const role of ['attacker', 'searcher', 'builder']) assert.deepEqual(prepareContext(role, prepareContext(role, snap)), prepareContext(role, snap), `${role} idempotent`);
});

test('the Hacker is simulator-only, and the server exposes start, stop and forget', async () => {
  const rt = new Runtime({ simulation: new Simulation(), container: false });
  rt.mode = 'lab';
  await assert.rejects(() => rt.setHacker(true), /simulator/);
  rt.mode = 'simulation';
  await rt.setHacker(true);
  assert.equal(rt.snapshot().hacker.enabled, true);
  await assert.rejects(() => rt.setHacker('yes'), /true or false/);
});

test('a demo seed repeats the same clouds, whatever the traffic does', async () => {
  const { streams, parseSeed } = await import('../src/seed.mjs');
  const layouts = seed => {
    const r = streams(seed);
    const sim = new Simulation({ layout: 'random', random: r.traffic, layoutRandom: r.layout });
    const seen = [sim.snapshot().weakSpots.join()];
    for (let i = 0; i < 3; i++) { for (let t = 0; t < i * 7; t++) sim.tick(); seen.push(sim.reset().weakSpots.join()); }
    return seen;
  };
  assert.deepEqual(layouts(6), layouts(6));
  assert.notDeepEqual(layouts(6), layouts(7));
  assert.equal(parseSeed(''), null);
  assert.equal(parseSeed('6'), 6);
  assert.throws(() => parseSeed('six'), /whole number/);
});

test('a fix approved in the middle of a slow attempt is not counted as breached', async () => {
  const rt = new Runtime({ simulation: new Simulation(), container: false, hacker: new Hacker({ random: seeded(1) }) });
  rt.simulation._policies.metadataProtection = false;
  rt.simulation._weakSpots = ['metadataProtection'];
  rt.hacker.arms.set('x', { key: 'x', chain: ['discover', 'metadata-ssrf', 'cloud-key-use'], pace: 'slow', spread: 'single', tries: 1, value: 3, wins: 1, lastReward: 3 });
  await rt.setHacker(true);
  while (!rt.simulation.snapshot().recommendations.length) await ticks(rt, 1);
  assert.ok(rt.hacker.current, 'stolen credentials, read not yet attempted');
  await rt.applyRecommendation(rt.simulation.snapshot().recommendations[0].id);
  await ticks(rt, 20);
  const { performance, events } = rt.snapshot();
  assert.ok(rt.hacker.attempts[0].breached.includes('metadataProtection'), 'the theft before the fix still counts as a breach');
  assert.equal(performance.builder.failed, 0, 'but not as a failed fix');
  assert.equal(performance.builder.after.breaches, 0);
  assert.ok(events.some(e => e.action === 'read-object' && e.principal === 'app-service' && e.outcome === 'denied'), 'the stolen credentials were rotated');
  assert.notEqual(performance.verdict.status, 'failing');
});

test('the dashboard proof shows only measured numbers from the comparison file', async () => {
  const { readFileSync } = await import('node:fs');
  const vm = (await import('node:vm')).default;
  const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
  const source = app.slice(app.indexOf('// Proof:'), app.indexOf('// End proof.'));
  const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));
  const render = proof => { const ctx = { proof }; vm.runInNewContext(`${escapeLine}\n${source}\nresult = proofMarkup(proof);`, ctx); return ctx.result; };
  const proof = JSON.parse(readFileSync(new URL('../data/hacker-proof.json', import.meta.url), 'utf8'));
  const markup = render(proof);
  assert.match(markup, new RegExp(`${proof.results.randomRun1.successRate}%`));
  assert.match(markup, new RegExp(`${proof.results.hackerRun1.successRate}%`));
  assert.match(markup, /npm run eval:hacker/);
  assert.equal(render(null), '');
});

test('Restart demo replays the pinned first cloud from scratch; Reset then releases the seed', async () => {
  const { streams } = await import('../src/seed.mjs');
  const r = streams(6);
  const rt = new Runtime({ container: false, seed: 6, simulation: new Simulation({ layout: 'random', random: r.traffic, layoutRandom: r.layout }), hacker: new Hacker({ random: r.hacker }) });
  const hero = rt.snapshot().weakSpots;
  await rt.setHacker(true);
  await ticks(rt, 30);
  await rt.runScenario('exposed-storage');
  await ticks(rt, 5);
  await rt.reset();
  assert.equal(rt.snapshot().seed, null, 'Reset releases the pin');
  assert.equal(rt.runNumber, 2);

  await rt.restartDemo(6);
  const fresh = rt.snapshot();
  assert.deepEqual(fresh.weakSpots, hero, 'the same hero cloud');
  assert.equal(fresh.seed, 6);
  assert.equal(fresh.runNumber, 1);
  assert.equal(fresh.running, false, 'paused until the presenter resumes');
  assert.equal(fresh.hacker.enabled, false);
  assert.equal(fresh.hacker.remembered, 0, 'Hacker learning wiped');
  assert.deepEqual([fresh.attackHistory.length, fresh.learningLogs.length, fresh.findings.length], [0, 0, 0]);

  // Two restarts on the same seed play out identically.
  const replay = async () => { await rt.restartDemo(6); await rt.setHacker(true); await rt.setRunning(true); await ticks(rt, 40); return rt.hacker.attempts.map(a => `${a.chain.join('>')}:${a.result}`); };
  assert.deepEqual(await replay(), await replay());

  rt.mode = 'lab';
  await assert.rejects(() => rt.restartDemo(6), /simulator/);
  rt.mode = 'simulation';
  await assert.rejects(() => rt.restartDemo(-1), /whole number/);
});

test('the reveal scores Hacker addresses separately: flagging the Hacker is never a false alarm', async () => {
  const rt = new Runtime({ simulation: new Simulation({ random: seeded(8) }), container: false, hacker: new Hacker({ random: seeded(2) }) });
  await rt.setTraffic({ users: 10, bots: true });
  rt.hacker.arms.set('x', { key: 'x', chain: ['storage-list', 'storage-read'], pace: 'slow', spread: 'single', tries: 1, value: 2, wins: 1, lastReward: 2 });
  await rt.setHacker(true);
  await ticks(rt, 12);
  const hackerIp = rt.hacker.attempts[0].clientIds[0];
  const user = rt.simulation._traffic.userIds[0];
  const bot = rt.simulation._traffic.bots[0].clientId;
  rt.runs.unshift({ agent: 'searcher', mode: 'model', time: 't', suspects: [hackerIp, bot, user], evidenceIds: [] });
  await rt.revealBots();
  const score = rt.snapshot().botScore;
  assert.deepEqual(score.falseAlarms, [user], 'only the real user is a false alarm');
  assert.ok(score.caught.includes(bot));
  assert.deepEqual(score.hacker.caught, [hackerIp]);
  assert.match(rt.snapshot().learningLogs[0].text, /Hacker: 1 of \d+ addresses flagged/);

  const { readFileSync } = await import('node:fs');
  const vm = (await import('node:vm')).default;
  const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
  const source = app.slice(app.indexOf('// Live traffic:'), app.indexOf('// End live traffic.'));
  const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));
  const ctx = { score };
  vm.runInNewContext(`${escapeLine}\n${source}\nresult = botScoreMarkup(score);`, ctx);
  assert.match(ctx.result, /1 of \d+ Hacker addresses, 1 false alarm on real users \(AI\)/);
  assert.match(ctx.result, /Hacker<\/span> flagged 1 of \d+ addresses it used/);
});

test('long runs count every Hacker attempt, not only the records it keeps', () => {
  const attempts = Array.from({ length: 120 }, (_, i) => ({ runAttempt: 111 + i, breached: ['storagePrivate'], touched: ['storagePrivate'], endTick: 500 + i, flagged: i % 2 === 0 }));
  const report = performanceReport({ weakSpots: ['storagePrivate', 'requireMfa'], hacker: { attempts, stats: { attempts: 230, breaches: 200, firstBreachAt: 2, found: ['storagePrivate', 'requireMfa'] }, trend: null } });
  assert.match(report.lines.hacker, /^200 of 230 attempts got through \(87%\) · found 2 of 2 weak spots · first breach: attempt 2/);
  assert.match(report.lines.searcher, /60 of the last 120 Hacker attempts/);
});
