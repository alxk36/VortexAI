import test from 'node:test';
import assert from 'node:assert/strict';
import { Simulation } from '../src/simulation.mjs';

/** Complete one bounded scenario while keeping all observations for assertions. */
function run(simulation, id) {
  simulation.runScenario(id);
  for (let i = 0; i < 10 && simulation.snapshot().activeScenario; i++) simulation.tick();
  assert.equal(simulation.snapshot().activeScenario, null);
  return simulation.snapshot();
}

for (const [scenario, policy, prohibitedEffect] of [
  ['exposed-storage', 'storagePrivate', 'read-object'],
  ['credential-abuse', 'requireMfa', 'admin-request'],
  ['lateral-movement', 'databaseLeastPrivilege', 'export-response'],
]) {
  test(`${scenario}: evidence, admin approval, and blocked replay`, () => {
    const sim = new Simulation();
    const baseline = run(sim, scenario);
    assert.equal(baseline.findings.length, 1);
    assert.equal(baseline.findings[0].status, 'open');
    assert.equal(baseline.findings[0].policyKey, policy);
    assert.ok(baseline.findings[0].evidenceDetails.some(event => event.outcome === 'allowed'));
    assert.equal(baseline.policies[policy], false, 'Builder must not apply its own fix');
    assert.ok(baseline.events.some(event => event.action === prohibitedEffect && event.outcome === 'allowed'));

    const patched = sim.applyRecommendation(baseline.recommendations[0].id);
    assert.equal(patched.policies[policy], true);
    assert.equal(patched.recommendations[0].validation, 'pending');
    assert.equal(patched.findings[0].status, 'resolved');
    const cutoff = patched.tick;
    const replay = run(sim, scenario);
    assert.equal(replay.findings.length, 1, 'blocked replay must not create another vulnerability');
    assert.equal(replay.metrics.openFindings, 0);
    assert.equal(replay.recommendations[0].validation, 'blocked-replay');
    assert.equal(replay.agents.attacker.status, 'Blocked');
    assert.equal(replay.events.filter(event => event.tick > cutoff && event.action === prohibitedEffect && event.outcome === 'allowed').length, 0);
    assert.ok(replay.events.some(event => event.tick > cutoff && event.source === 'app' && event.action === 'read' && event.outcome === 'allowed'), 'legitimate application access must remain available');
  });
}

test('normal traffic produces no findings and all endpoints belong to the lab', () => {
  const sim = new Simulation();
  for (let i = 0; i < 40; i++) sim.tick();
  const state = sim.snapshot();
  const ids = new Set(state.nodes.map(node => node.id));
  assert.equal(state.findings.length, 0);
  assert.equal(state.metrics.totalEvents, 360);
  assert.equal(state.events.length, 160);
  assert.ok(state.events.every(event => ids.has(event.source) && ids.has(event.target)));
  const responses = state.events.filter(event => event.tick === state.tick && event.action === 'response').reverse();
  assert.deepEqual(responses.map(event => [event.source, event.target]), [['storage', 'app'], ['app', 'lb'], ['lb', 'gateway'], ['gateway', 'client']]);
});

test('controls cannot change during a scenario, preserving baseline and replay separation', () => {
  const sim = new Simulation();
  sim.runScenario('credential-abuse');
  for (let i = 0; i < 4; i++) sim.tick();
  const before = sim.snapshot();
  const id = before.recommendations[0].id;
  assert.throws(() => sim.applyRecommendation(id), /Wait for the scenario to finish/);
  assert.deepEqual(sim.snapshot(), before);
  sim.tick();
  assert.ok(sim.snapshot().events.some(event => event.action === 'admin-request' && event.outcome === 'allowed'));
  const applied = sim.applyRecommendation(id);
  assert.equal(applied.recommendations[0].validation, 'pending');
  assert.equal(applied.policies.requireMfa, true);
  run(sim, 'credential-abuse');
  assert.equal(sim.snapshot().recommendations[0].validation, 'blocked-replay');
});

test('pause preserves state and queues a scenario without progressing it', () => {
  const sim = new Simulation();
  sim.setRunning(false);
  sim.runScenario('exposed-storage');
  const paused = sim.snapshot();
  assert.deepEqual(sim.tick(), paused);
  sim.setRunning(true);
  sim.tick();
  assert.equal(sim.snapshot().activeScenario.step, 1);
});

test('invalid inputs and overlap are rejected without state changes', () => {
  const sim = new Simulation();
  const fresh = sim.snapshot();
  for (const invalid of ['https://example.test', '__proto__', null, {}, 1]) {
    assert.throws(() => sim.runScenario(invalid), /Unknown scenario/);
    assert.throws(() => sim.applyRecommendation(invalid), /Unknown recommendation/);
  }
  assert.throws(() => sim.setRunning('false'), /boolean/);
  assert.deepEqual(sim.snapshot(), fresh);
  sim.runScenario('credential-abuse');
  const active = sim.snapshot();
  assert.throws(() => sim.runScenario('exposed-storage'), /already running/);
  assert.deepEqual(sim.snapshot(), active);
});

test('snapshots cannot mutate state; reset restores the original lab', () => {
  const sim = new Simulation();
  const fresh = sim.snapshot();
  const state = run(sim, 'exposed-storage');
  sim.applyRecommendation(state.recommendations[0].id);
  state.nodes[0].label = 'Changed';
  state.policies.requireMfa = true;
  state.findings[0].status = 'anything';
  assert.equal(sim.snapshot().nodes[0].label, 'Users');
  assert.equal(sim.snapshot().policies.requireMfa, false);
  assert.deepEqual(sim.reset(), fresh);
});

test('evidence survives rolling-feed eviction and finding counts stay bounded', () => {
  const sim = new Simulation();
  run(sim, 'exposed-storage');
  for (let i = 0; i < 60; i++) sim.tick();
  const state = sim.snapshot();
  assert.equal(state.events.length, 160);
  assert.ok(state.findings[0].evidenceDetails.length > 0);
  assert.ok(!state.events.some(event => event.id === state.findings[0].evidence[0]));
  for (let i = 0; i < 8; i++) run(sim, 'exposed-storage');
  assert.equal(sim.snapshot().findings.length, 1);
  assert.ok(sim.snapshot().findings[0].evidence.length <= 8);
});

test('credential failures alone do not prove account compromise', () => {
  const sim = new Simulation();
  sim.runScenario('credential-abuse');
  for (let i = 0; i < 3; i++) sim.tick();
  assert.equal(sim.snapshot().findings.length, 0);
  sim.tick();
  assert.equal(sim.snapshot().findings.length, 1);
  assert.equal(sim.snapshot().findings[0].evidence.length, 4);
});

test('all three fixes coexist and replays preserve ordinary traffic', () => {
  const sim = new Simulation();
  const ids = ['exposed-storage', 'credential-abuse', 'lateral-movement'];
  for (const id of ids) run(sim, id);
  assert.equal(sim.snapshot().metrics.openFindings, 3);
  for (const recommendation of sim.snapshot().recommendations) sim.applyRecommendation(recommendation.id);
  for (const id of ids) run(sim, id);
  const state = sim.snapshot();
  assert.equal(state.metrics.openFindings, 0);
  assert.ok(state.recommendations.every(item => item.validation === 'blocked-replay'));
  assert.ok(Object.values(state.policies).every(Boolean));
});
