import test from 'node:test';
import assert from 'node:assert/strict';
import { Runtime } from '../src/runtime.mjs';

test('Reset lab leaves the simulator paused until the admin resumes it', async () => {
  const runtime = new Runtime({ container: false });
  assert.equal(runtime.snapshot().running, true, 'a fresh start still runs');
  await runtime.tick();
  await runtime.reset();
  const state = runtime.snapshot();
  assert.equal(state.running, false);
  assert.equal(state.tick, 0);
  await runtime.tick();
  assert.equal(runtime.snapshot().tick, 0, 'no traffic while paused');
  await runtime.setRunning(true);
  await runtime.tick();
  assert.equal(runtime.snapshot().tick, 1);
});

test('Reset lab also pauses the real-service lab', async () => {
  const calls = [];
  let remote = { generation: 'g1', tick: 3, events: [], policies: { storagePrivate: false, requireMfa: false, databaseLeastPrivilege: false }, running: true, activeScenario: null, containmentVerified: true, metrics: {}, nodeSettings: {} };
  const fetchImpl = async (url, options) => {
    const path = new URL(url).pathname;
    const body = options.body ? JSON.parse(options.body) : undefined;
    calls.push(path);
    if (path === '/reset') remote = { ...remote, generation: 'g2', tick: 0, events: [], running: true };
    if (path === '/running') remote = { ...remote, running: body.running };
    return Response.json(remote);
  };
  const runtime = new Runtime({ container: true, executorToken: 'e'.repeat(32), fetchImpl });
  await runtime.setMode('lab');
  await runtime.reset();
  assert.deepEqual(calls.slice(-2), ['/reset', '/running']);
  assert.equal(runtime.snapshot().running, false);
});
