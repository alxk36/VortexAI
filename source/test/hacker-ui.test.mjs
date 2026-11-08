import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));
const section = (start, end) => app.slice(app.indexOf(start), app.indexOf(end));
const render = (source, expr, input) => { const ctx = { input }; vm.runInNewContext(`${escapeLine}\n${source}\nresult = ${expr};`, ctx); return ctx.result; };
const hacker = (expr, input) => render(section('// Hacker:', '// End hacker.'), expr, input);

const view = {
  available: true, enabled: true, current: null, total: 14,
  best: { chain: ['bundle-scrape', 'api-key-use'], pace: 'slow', spread: 'single', value: 1.9, tries: 6 },
  recent: [
    { chain: ['bundle-scrape', 'api-key-use'], pace: 'slow', spread: 'single', result: 'breached', reward: 1.9, explored: false },
    { chain: ['<script>'], pace: 'fast', spread: 'rotate', result: 'tripped', reward: -2.4, explored: true },
  ],
  trend: { early: -1.2, recent: 1.4, attempts: 14 },
  runs: [{ run: 1, attempts: 9, firstBreachAt: 6 }, { run: 2, attempts: 5, firstBreachAt: 1 }],
};

test('the dashboard has a Hacker panel wired to start, stop and forget', () => {
  assert.match(html, /id="hacker"/);
  assert.match(html, /legend-dot hacker/);
  assert.match(app, /command\('hacker',\{enabled:/);
  assert.match(app, /command\('hacker\/forget'/);
});

test('the Hacker panel shows its last attempt, favorite, trend and first breach by run, escaped', () => {
  const markup = hacker('hackerMarkup(input)', view);
  assert.match(markup, /Learning/);
  assert.match(markup, /Last attempt: Got through · bundle-scrape → api-key-use \(slow, one address\) · reward \+1.9/);
  assert.match(markup, /Favorite: bundle-scrape → api-key-use \(slow, one address\) · value \+1.9 after 6 tries/);
  assert.match(markup, /-1.2 in its first five attempts, \+1.4 in its latest ten/);
  assert.match(markup, /First breach by run: Run 1: attempt 6 · Run 2: attempt 1/);
  assert.match(markup, /Tripwire.*rotating, exploring/);
  assert.match(markup, /data-hacker="stop">Stop Hacker/);
  assert.ok(!markup.includes('<script>'));
});

test('the Hacker panel says when it is off, not started, or simulator-only', () => {
  assert.match(hacker('hackerMarkup(input)', { available: true, enabled: false, recent: [], runs: [] }), /Off.*Not started.*data-hacker="start">Start Hacker/s);
  assert.match(hacker('hackerMarkup(input)', { ...view, available: false }), /Simulator only/);
  assert.match(hacker('hackerMarkup(input)', { ...view, current: { chain: ['password-spray'], pace: 'slow', spread: 'rotate', step: 2, parts: 6 } }), /Attacking: password-spray \(slow, rotating addresses\), part 2 of 6/);
  assert.equal(hacker('hackerMarkup(input)', null), '');
});

test('agent performance adds a Hacker row when the report has one', () => {
  const perf = section('// Agent performance:', '// End agent performance.');
  const report = { verdict: { status: 'at-risk', text: 'At risk.' }, lines: { attacker: 'Found 1 of 4 weak spots', searcher: 'Flagged 0 of 0', builder: 'No fixes applied yet', hacker: '3 of 9 attempts got through · found 2 of 4 weak spots' }, definitions: { attacker: 'a', searcher: 's', builder: 'b', hacker: 'h' } };
  const { summary, body } = render(perf, 'performanceMarkup(input, [{ agent: "hacker", run: 2, tick: 40, text: "New favorite" }])', report);
  assert.match(summary, /3 of 9 attempts got through/);
  assert.match(body, /<strong>Hacker<\/strong>/);
  assert.match(body, /log-agent hacker/);
});
