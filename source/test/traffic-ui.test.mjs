import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { createServer } from '../server.mjs';
import { Simulation } from '../src/simulation.mjs';

const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));
const source = app.slice(app.indexOf('// Live traffic:'), app.indexOf('// End live traffic.'));
const render = (expr, input) => { const ctx = { input }; vm.runInNewContext(`${escapeLine}\n${source}\nresult = ${expr};`, ctx); return ctx.result; };

test('the dashboard has traffic controls wired to the API', () => {
  for (const id of ['traffic-users', 'traffic-bots', 'traffic-apply', 'bots-reveal', 'bot-score', 'auto-blocks']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(app, /command\('traffic',\{users,bots\}/);
  assert.match(app, /command\('bots\/reveal'/);
  assert.match(app, /command\('unblock',\{clientId/);
});

test('the score shows caught, missed and false alarms, and is escaped', () => {
  const markup = render('botScoreMarkup(input)', {
    bots: [{ clientId: '203.0.113.10', behavior: 'credential-stuffing' }, { clientId: '<img>', behavior: 'request-flood' }],
    caught: ['203.0.113.10'], missed: ['<img>'], falseAlarms: ['198.51.100.12'], searcherRunAt: 't', searcherMode: 'model',
  });
  assert.match(markup, /Searcher caught 1 of 2 hidden bots, 1 false alarm on real users \(AI\)/);
  assert.match(markup, /Caught.*203\.0\.113\.10.*credential stuffing/);
  assert.match(markup, /Missed.*&lt;img&gt;/);
  assert.match(markup, /False alarm.*198\.51\.100\.12/);
  assert.ok(!markup.includes('<img>'));
  assert.match(render('botScoreMarkup(input)', { bots: [], caught: [], missed: [], falseAlarms: [], searcherRunAt: null }), /Run the Searcher before revealing/);
  assert.equal(render('botScoreMarkup(input)', null), '');
});

test('the tripwire log offers Unblock only while a block is active', () => {
  const markup = render('autoBlocksMarkup(input)', {
    blocked: [{ clientId: '203.0.113.15', untilTick: 30 }],
    autoBlocks: [{ clientId: '203.0.113.15', reason: '12 requests in one tick (limit 8)' }, { clientId: '198.51.100.18', reason: '9 requests in one tick (limit 8)' }],
  });
  assert.match(markup, /Blocked.*203\.0\.113\.15.*data-unblock="203\.0\.113\.15"/);
  assert.match(markup, /Lifted.*198\.51\.100\.18/);
  assert.equal((markup.match(/data-unblock/g) || []).length, 1);
  assert.equal(render('autoBlocksMarkup(input)', { blocked: [], autoBlocks: [] }), '');
});

test('the server validates traffic, reveal and unblock requests', async () => {
  const simulation = new Simulation();
  const server = createServer({ simulation, autoTick: false });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const post = (path, body) => fetch(`http://127.0.0.1:${server.address().port}/api/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  try {
    assert.equal((await post('traffic', { users: 20, bots: true })).status, 200);
    assert.deepEqual([simulation.snapshot().traffic.users, simulation.snapshot().traffic.botsEnabled], [20, true]);
    for (const bad of [{ users: '20', bots: true }, { users: 20 }, { users: 20, bots: true, extra: 1 }, { users: 0, bots: false }]) {
      assert.equal((await post('traffic', bad)).status, 400, JSON.stringify(bad));
    }
    assert.equal((await post('bots/reveal', {})).status, 200);
    assert.ok(simulation.snapshot().traffic.revealed);
    assert.equal((await post('unblock', { clientId: '203.0.113.10' })).status, 400, 'not blocked');
    assert.equal((await post('unblock', { clientId: 5 })).status, 400);
  } finally { server.close(); }
});
