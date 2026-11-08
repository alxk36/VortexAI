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

test('the judge view shows one large number per agent with what it counts, escaped', () => {
  const tiles = (perf, agents, h) => render(section('// Agent tiles:', '// End agent tiles.'), 'agentTilesMarkup(input.perf, input.agents, input.hacker)', { perf, agents, hacker: h });
  const perf = {
    attacker: { found: 2, total: 4, runs: 2, gotThrough: 1 },
    searcher: { attempts: 2, flagged: 2, bots: { caught: 2, total: 2, falseAlarms: 0 }, hacker: { attempts: 17, flagged: 16 } },
    builder: { applied: 3, held: 3, failed: 0, before: { breaches: 13, attempts: 13 }, after: { breaches: 0, attempts: 7 } },
    hacker: { attempts: 20, gotThrough: 17, foundControls: ['storagePrivate', 'metadataProtection'], total: 4 },
  };
  const markup = tiles(perf, { attacker: { status: 'Ready' }, searcher: { status: '<b>x</b>' }, builder: { status: 'Validated' } }, { available: true, enabled: true, best: { chain: ['discover', 'metadata-ssrf'] } });
  for (const [number, caption] of [['2/4', 'weak spots found'], ['18/19', 'attempts flagged'], ['3/3', 'fixes held'], ['85%', 'of 20 attempts got through']]) {
    assert.match(markup, new RegExp(`tile-number">${number}</div><div class="tile-caption">${caption}`));
  }
  assert.match(markup, /breaches on fixed paths 13\/13 → 0\/7/);
  assert.match(markup, /2 of 2 hidden bots/);
  assert.match(markup, /favorite discover → metadata-ssrf/);
  assert.ok(!markup.includes('<b>x</b>'));
  const idle = tiles({ ...perf, attacker: { found: 0, total: 3, runs: 0, gotThrough: 0 }, builder: { applied: 0, held: 0, failed: 0, before: {}, after: {} }, hacker: null }, {}, null);
  assert.match(idle, /no attack runs yet/);
  assert.match(idle, /approve a finding to start/);
  assert.ok(!idle.includes('agent-tile hacker'), 'no Hacker tile in the container lab');
});

test('the judge view keeps every control in the toolbar and the events beside the map', () => {
  for (const id of ['toolbar', 'attack-menu', 'traffic-menu', 'hacker-toggle', 'verdict-line', 'agent-tiles', 'proof-panel', 'agents-panel', 'events', 'findings']) assert.match(html, new RegExp(`id="${id}"`));
  for (const agent of ['attacker', 'searcher', 'builder']) assert.match(html, new RegExp(`data-ai="${agent}"`));
  assert.match(html, /<ol id="events" class="event-feed">/);
});
