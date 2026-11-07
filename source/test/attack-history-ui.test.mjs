import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

// Load only the attack-history renderer from the real browser module.
const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const start = app.indexOf('// Attack history:');
const end = app.indexOf('// End attack history.');
const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));

function render(history) {
  assert.ok(start >= 0 && end > start, 'renderer markers present in app.mjs');
  const ctx = {};
  vm.runInNewContext(`${escapeLine}\n${app.slice(start, end)}\nresult = attackHistoryMarkup(input);`, Object.assign(ctx, { input: history }));
  return ctx.result;
}

const history = [
  { scenarioId: 'credential-abuse', name: 'Credential abuse', source: 'ai', result: 'succeeded', blockedBy: [] },
  { scenarioId: 'exposed-storage', name: 'Exposed storage', source: 'admin', result: 'blocked', blockedBy: ['storagePrivate'] },
  { scenarioId: 'exposed-storage', name: 'Exposed storage', source: 'admin', result: 'succeeded', blockedBy: [] },
];

test('the dashboard has a slot for the attack history and fills it from state', () => {
  assert.match(html, /id="attack-history"/);
  assert.match(app, /\$\('attack-history'\)\.innerHTML/);
  assert.match(app, /attackHistoryMarkup\(state\.attackHistory\)/);
});

test('history renders newest first with outcome, fix, and who launched it', () => {
  const markup = render(history);
  const rows = markup.match(/<li>.*?<\/li>/g);
  assert.equal(rows.length, 3);
  assert.match(rows[0], /Got through.*Credential abuse.*AI attacker/);
  assert.match(rows[1], /Blocked.*Exposed storage.*by private storage.*admin/);
  assert.match(rows[2], /Got through.*Exposed storage/);
});

test('history is escaped, capped at six rows, and empty when there is none', () => {
  const hostile = [{ scenarioId: 'x', name: '<img src=x onerror=alert(1)>', source: 'ai', result: 'blocked', blockedBy: ['<b>'] }];
  const markup = render(hostile);
  assert.ok(!markup.includes('<img') && !markup.includes('<b>'));
  assert.match(markup, /&lt;img/);
  assert.equal(render(Array(10).fill(history[0])).match(/<li>/g).length, 6);
  assert.equal(render([]), '');
  assert.equal(render(undefined), '');
});
