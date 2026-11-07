import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { Simulation } from '../src/simulation.mjs';
import { SYSTEM_PROMPTS, runAgent, AGENT_ROLES } from '../ai/agents.mjs';

const app = readFileSync(new URL('../public/app.mjs', import.meta.url), 'utf8');
const escapeLine = app.split('\n').find(line => line.startsWith('const escape ='));
const cardSource = app.slice(app.indexOf('// AI run card:'), app.indexOf('// End AI run card.'));
const card = run => { const ctx = { run }; vm.runInNewContext(`${escapeLine}\n${cardSource}\nresult = aiRunMarkup(run);`, ctx); return ctx.result; };

test('every agent is told to be brief and lead with the point', () => {
  for (const role of AGENT_ROLES) {
    assert.match(SYSTEM_PROMPTS[role], /under 50 words/, role);
    assert.match(SYSTEM_PROMPTS[role], /key point first/, role);
  }
});

test('rule fallbacks answer in one short line', async () => {
  const sim = new Simulation();
  sim.runScenario('exposed-storage');
  while (sim.snapshot().activeScenario) sim.tick();
  for (const role of AGENT_ROLES) {
    const { summary } = await runAgent(role, sim.snapshot());
    assert.ok(summary.length <= 160, `${role}: ${summary.length} chars: ${summary}`);
  }
});

test('an AI run card shows a one-line headline and tucks the rest into Details', () => {
  const summary = 'Three hidden bots found. 198.51.100.216 scraped storage 16 times with no normal requests, and 198.51.100.114 flooded the gateway. The rest of the traffic looks routine.';
  const markup = card({ agent: 'searcher', mode: 'model', provider: 'anthropic', model: 'claude-opus-5-5', summary,
    suspects: ['198.51.100.216', '198.51.100.114'], labels: [{ id: 'event-1', origin: 'internal' }, { id: 'event-2', origin: 'external' }, { id: 'event-3', origin: 'external' }], plan: [] });
  const [visible, hidden] = markup.split('<details');
  assert.match(visible, /<p class="headline">Three hidden bots found\.<\/p>/);
  assert.match(visible, /Suspects.*198\.51\.100\.216/, 'key facts stay visible as chips');
  assert.match(visible, /Internal · team mistake ×1.*External · outside attack ×2/, 'labels collapse to counts');
  assert.ok(!visible.includes('scraped storage 16 times'), 'the long explanation is hidden');
  assert.match(hidden, /<summary>Details<\/summary>/);
  assert.match(hidden, /scraped storage 16 times/);
  assert.match(hidden, /event-2/);
  assert.match(hidden, /claude-opus-5-5/);
});

test('a card shows the AI chain and the serving model, and escapes everything', () => {
  const markup = card({ agent: 'attacker', mode: 'model', provider: 'anthropic', model: 'claude-opus-5-5', servedBy: 'claude-opus-4-8',
    summary: '<img src=x onerror=alert(1)> chose a new chain.', plan: ['discover', 'token-replay'], labels: [], suspects: [] });
  assert.ok(!markup.includes('<img'));
  assert.match(markup, /AI chain.*discover.*token-replay/);
  assert.match(markup, /claude-opus-4-8 \(Opus 5\.5 declined\)/);
});

test('scenario descriptions and fix details are collapsed in the page', () => {
  assert.match(app, /<details class="scenario-about"><summary>What it does<\/summary>/);
  assert.match(app, /<summary>Fix details<\/summary>/);
  assert.match(app, /class="clamp" title=/, 'long agent status lines are clipped with the full text on hover');
});
