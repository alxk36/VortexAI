import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { Runtime } from '../src/runtime.mjs';
import { Simulation } from '../src/simulation.mjs';

const seeded = seed => () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const lab = () => new Runtime({ container: false });
async function settle(runtime) { for (let i = 0; i < 20 && runtime.snapshot().activeScenario; i++) await runtime.tick(); }
async function attack(runtime, id) { await runtime.runScenario(id); await settle(runtime); return runtime.snapshot(); }
const perf = runtime => runtime.snapshot().performance;

test('before anything runs there is nothing to report', () => {
  const p = perf(lab());
  assert.equal(p.verdict.status, 'idle');
  assert.deepEqual([p.attacker.found, p.attacker.total], [0, 3]);
});

test('an unfixed weak spot is reported as at risk', async () => {
  const runtime = lab();
  await attack(runtime, 'exposed-storage');
  const p = perf(runtime);
  assert.deepEqual([p.attacker.found, p.attacker.total, p.attacker.runs, p.attacker.gotThrough], [1, 3, 1, 1]);
  assert.deepEqual([p.searcher.flagged, p.searcher.attempts], [1, 1], 'the rules finding flags the attack');
  assert.equal(p.builder.applied, 0);
  assert.equal(p.verdict.status, 'at-risk');
});

test('a fix counts as held only after a replay is blocked, and then the system is defended', async () => {
  const runtime = lab();
  await attack(runtime, 'exposed-storage');
  await runtime.applyRecommendation('recommendation-storagePrivate');
  let p = perf(runtime);
  assert.deepEqual([p.builder.applied, p.builder.held], [1, 0]);
  assert.equal(p.verdict.status, 'at-risk', 'applied but not proven yet');
  await attack(runtime, 'exposed-storage');
  p = perf(runtime);
  assert.deepEqual([p.builder.applied, p.builder.held, p.builder.failed], [1, 1, 0]);
  assert.deepEqual(p.builder.before, { breaches: 1, attempts: 1 });
  assert.deepEqual(p.builder.after, { breaches: 0, attempts: 1 });
  assert.deepEqual([p.searcher.flagged, p.searcher.attempts], [2, 2], 'the blocked replay is flagged too');
  assert.equal(p.verdict.status, 'defended');
});

test('if a fixed path is breached again, the system reports itself as failing', async () => {
  const runtime = lab();
  await attack(runtime, 'exposed-storage');
  await runtime.applyRecommendation('recommendation-storagePrivate');
  await attack(runtime, 'exposed-storage');
  runtime.simulation._policies.storagePrivate = false; // the control silently stops working
  await attack(runtime, 'exposed-storage');
  const p = perf(runtime);
  assert.equal(p.verdict.status, 'failing');
  assert.match(p.verdict.text, /private storage/);
  assert.equal(p.builder.failed, 1);
});

test('hidden bots count toward the Searcher flag rate once revealed, including tripwire blocks', async () => {
  const runtime = lab();
  const sim = new Simulation({ random: seeded(7) });
  sim.setTraffic({ users: 20, bots: true });
  const [stuffer, flooder] = sim._traffic.userIds.slice(-2);
  sim._traffic.userIds = sim._traffic.userIds.slice(0, -2);
  sim._traffic.bots = [
    { clientId: stuffer, behavior: 'credential-stuffing', startTick: 2, nextFlood: 0 },
    { clientId: flooder, behavior: 'request-flood', startTick: 2, nextFlood: 0 },
  ];
  runtime.simulation = sim;
  for (let i = 0; i < 12; i++) await runtime.tick();
  assert.equal(perf(runtime).searcher.bots, null, 'no bot numbers before the reveal');
  await runtime.revealBots(); // no Searcher run yet: only the tripwire caught anything
  const p = perf(runtime);
  assert.deepEqual([p.searcher.bots.caught, p.searcher.bots.total, p.searcher.bots.falseAlarms], [1, 2, 0]);
});

test('each agent keeps a log of what it learned, and the logs survive a lab reset', async () => {
  const runtime = lab();
  await attack(runtime, 'exposed-storage');
  await runtime.runAI('searcher');
  await runtime.applyRecommendation('recommendation-storagePrivate');
  await attack(runtime, 'exposed-storage');
  const logs = runtime.snapshot().learningLogs;
  const by = agent => logs.filter(l => l.agent === agent).map(l => l.text).join(' | ');
  assert.match(by('attacker'), /Exposed storage got through/);
  assert.match(by('attacker'), /Exposed storage was blocked by private storage/);
  assert.match(by('searcher'), /Flagged/);
  assert.match(by('builder'), /Applied: Make object storage private/);
  assert.match(by('builder'), /Held: Make object storage private blocked the replay/);
  assert.ok(logs.every(l => l.run === 1));
  await runtime.reset();
  const after = runtime.snapshot();
  assert.equal(after.performance.verdict.status, 'idle', 'numbers start over');
  assert.equal(after.learningLogs.length, logs.length, 'learnings are kept');
  await runtime.setRunning(true); // Reset lab leaves the simulation paused
  await attack(runtime, 'credential-abuse');
  assert.equal(runtime.snapshot().learningLogs[0].run, 2);
});

test('the dropdown shows the verdict and the three numbers, escaped', () => {
  const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /<details id="performance"/);
  const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));
  const source = app.slice(app.indexOf('// Agent performance:'), app.indexOf('// End agent performance.'));
  const ctx = { input: {
    verdict: { status: 'failing', text: 'Failing: <b>private storage</b> was breached after its fix.' },
    lines: { attacker: 'Found 2 of 3 weak spots', searcher: 'Flagged 4 of 4 attack attempts', builder: '1 of 2 fixes held' },
    definitions: { attacker: 'a', searcher: 'b', builder: 'c' },
  }, logs: [{ agent: 'builder', run: 1, tick: 9, text: 'Failed: <i>x</i>' }] };
  vm.runInNewContext(`${escapeLine}\n${source}\nresult = performanceMarkup(input, logs);`, ctx);
  assert.match(ctx.result.summary, /class="verdict failing"/);
  assert.match(ctx.result.summary, /Found 2 of 3 weak spots/);
  assert.match(ctx.result.body, /Flagged 4 of 4 attack attempts/);
  assert.ok(!ctx.result.summary.includes('<b>') && !ctx.result.body.includes('<i>'));
});
