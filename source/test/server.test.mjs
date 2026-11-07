import { after, before, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, rmdir, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from '../server.mjs';
import { Simulation } from '../src/simulation.mjs';

// Real loopback requests exercise route, body, browser-origin, and asset boundaries.
// A temporary static directory makes these tests independent of UI authoring.
describe('local HTTP interface', () => {
  const simulation = new Simulation();
  let server;
  let directory;
  let port;
  before(async () => {
    directory = await mkdtemp(join(tmpdir(), 'vortexai-http-test-'));
    await Promise.all([
      writeFile(join(directory, 'index.html'), '<!doctype html><title>VortexAI</title>'),
      writeFile(join(directory, 'app.mjs'), 'export const ready = true;'),
      writeFile(join(directory, 'styles.css'), 'body { color: white; }'),
    ]);
    server = createServer({ simulation, autoTick: false, publicDirectory: directory });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    port = server.address().port;
  });
  beforeEach(() => simulation.reset());
  after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (directory) {
      await Promise.all(['index.html', 'app.mjs', 'styles.css'].map((name) => unlink(join(directory, name))));
      await rmdir(directory);
    }
  });

  function request(path, { method = 'GET', body, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
      const req = http.request({ hostname: '127.0.0.1', port, path, method, headers, agent: false }, (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString();
          resolve({ status: response.statusCode, headers: response.headers, text,
            json: () => JSON.parse(text) });
        });
      });
      req.on('error', reject);
      req.end(body);
    });
  }
  const post = (path, body, headers = {}) => request(path, {
    method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', ...headers },
  });

  it('returns a snapshot and protective response headers', async () => {
    const response = await request('/api/state');
    assert.equal(response.status, 200);
    assert.ok(Array.isArray(response.json().nodes));
    assert.ok(Array.isArray(response.json().events));
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.match(response.headers['content-security-policy'], /connect-src 'self'/);
    assert.equal(response.headers['access-control-allow-origin'], undefined);
  });

  it('serves only allowlisted assets with the correct types', async () => {
    for (const [path, type] of [['/', 'text/html'], ['/app.mjs', 'text/javascript'], ['/styles.css', 'text/css']]) {
      const response = await request(path);
      assert.equal(response.status, 200);
      assert.ok(response.headers['content-type'].startsWith(type));
    }
    const head = await request('/', { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.text, '');
    for (const path of ['/../server.mjs', '/%2e%2e/server.mjs', '/server.mjs', '/.env', '/api/missing']) {
      assert.equal((await request(path)).status, 404, path);
    }
  });

  it('validates methods, JSON content type, body size and field types', async () => {
    assert.equal((await post('/api/state', {})).status, 405);
    assert.equal((await request('/api/reset')).status, 405);
    assert.equal((await request('/', { method: 'POST' })).status, 405);
    assert.equal((await request('/api/reset', { method: 'POST', body: '{}' })).status, 415);
    const jsonHeaders = { 'Content-Type': 'application/json' };
    assert.equal((await request('/api/reset', { method: 'POST', body: '{', headers: jsonHeaders })).status, 400);
    assert.equal((await request('/api/reset', { method: 'POST', body: 'x'.repeat(5000), headers: jsonHeaders })).status, 413);
    for (const value of [null, [], 'string', 1]) {
      assert.equal((await post('/api/reset', value)).status, 400);
    }
    assert.equal((await post('/api/running', { running: 'true' })).status, 400);
    assert.equal((await post('/api/reset', { unrecognized: true })).status, 400);
    assert.equal((await post('/api/scenario', {})).status, 400);
    assert.equal((await post('/api/scenario', { id: 'missing' })).status, 400);
    assert.equal((await post('/api/recommendation', { id: 'missing' })).status, 400);
  });

  it('rejects foreign hosts, origins and cross-site browser requests', async () => {
    assert.equal((await request('/api/state', { headers: { Host: `evil.example:${port}` } })).status, 403);
    assert.equal((await post('/api/reset', {}, { Origin: 'https://evil.example' })).status, 403);
    assert.equal((await post('/api/reset', {}, { Origin: `http://127.0.0.1:${port + 1}` })).status, 403);
    assert.equal((await post('/api/reset', {}, { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await post('/api/reset', {}, { Origin: `http://127.0.0.1:${port}` })).status, 200);
  });

  it('pauses, queues a scenario, changes only simulated policy, and resets', async () => {
    const pause = await post('/api/running', { running: false });
    assert.equal(pause.status, 200);
    assert.equal(pause.json().running, false);
    const launch = await post('/api/scenario', { id: 'exposed-storage' });
    assert.equal(launch.status, 200);
    assert.equal((await post('/api/scenario', { id: 'credential-abuse' })).status, 400);
    await post('/api/running', { running: true });
    for (let i = 0; i < 12; i++) simulation.tick();
    const state = (await request('/api/state')).json();
    assert.ok(state.recommendations.length > 0);
    const apply = await post('/api/recommendation', { id: state.recommendations[0].id });
    assert.equal(apply.status, 200);
    assert.equal(apply.json().recommendations[0].applied, true);
    const reset = await post('/api/reset', {});
    assert.equal(reset.status, 200);
    assert.equal(reset.json().findings.length, 0);
    assert.equal(reset.json().running, true);
  });
});
