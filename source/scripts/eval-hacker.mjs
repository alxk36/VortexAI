/**
 * Does the Hacker actually learn? A seeded, offline comparison: no API calls, no network.
 *
 * For each seed, the same two randomized clouds (run 1, then run 2 after a reset) are attacked by:
 *   random   a control with learning switched off: every attempt is a fresh random chain
 *   hacker   the learning Hacker; in run 2 it keeps what it learned in run 1
 * Each run lasts ATTACK_TICKS, then the admin approves every open Builder fix and the run
 * continues for FIX_TICKS, so we also see whether any fix is breached.
 *
 * Usage: npm run eval:hacker [-- seeds]   (default 30). Writes data/hacker-proof.json.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { Simulation } from '../src/simulation.mjs';
import { Runtime } from '../src/runtime.mjs';
import { Hacker } from '../src/hacker.mjs';
import { streams } from '../src/seed.mjs';

const SEEDS = Number(process.argv[2] ?? 30);
const ATTACK_TICKS = 120;
const FIX_TICKS = 100;
if (!Number.isInteger(SEEDS) || SEEDS < 1 || SEEDS > 500) throw new Error('seeds must be a whole number from 1 to 500.');

async function ticks(rt, n) {
  for (let i = 0; i < n; i++) { await rt.tick(); if (!rt.simulation.running) await rt.setRunning(true); }
}

/** One run: attack, then approve every open fix and keep attacking. */
async function run(rt) {
  await ticks(rt, ATTACK_TICKS);
  const stats = { ...rt.hacker.runStats.get(rt.runNumber) };
  const coverage = rt.snapshot().performance.hacker;
  for (const r of rt.simulation.snapshot().recommendations.filter(r => !r.applied)) await rt.applyRecommendation(r.id);
  await ticks(rt, FIX_TICKS);
  const { builder, hacker } = rt.snapshot().performance;
  return { found: coverage.foundControls.length, foundByEnd: hacker.foundControls.length, present: coverage.total, attempts: stats.attempts, breaches: stats.breaches, firstBreachAt: stats.firstBreachAt, fixedBreaches: builder.after.breaches, fixedAttempts: builder.after.attempts };
}

async function adversary(seed, learn) {
  const random = streams(seed);
  const rt = new Runtime({ container: false,
    simulation: new Simulation({ layout: 'random', random: random.traffic, layoutRandom: random.layout }),
    hacker: new Hacker({ random: random.hacker, learn }) });
  await rt.setHacker(true);
  const first = await run(rt);
  await rt.reset(); await rt.setRunning(true);
  // The control starts every run from nothing; the Hacker keeps its memory.
  if (!learn) rt.hacker.forget();
  const second = await run(rt);
  return [first, second];
}

const mean = list => list.length ? Math.round(list.reduce((a, b) => a + b, 0) / list.length * 10) / 10 : null;
const median = list => { if (!list.length) return null; const s = [...list].sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
function summarize(runs) {
  const found = runs.filter(r => r.firstBreachAt !== null).map(r => r.firstBreachAt);
  return {
    runs: runs.length,
    breachedWithinWindow: found.length,
    meanAttemptsToFirstBreach: mean(found), medianAttemptsToFirstBreach: median(found),
    successRate: Math.round(runs.reduce((a, r) => a + r.breaches, 0) / Math.max(1, runs.reduce((a, r) => a + r.attempts, 0)) * 1000) / 10,
    weakSpotsFound: Math.round(runs.reduce((a, r) => a + r.found, 0) / Math.max(1, runs.reduce((a, r) => a + r.present, 0)) * 1000) / 10,
    weakSpotsFoundByEnd: Math.round(runs.reduce((a, r) => a + r.foundByEnd, 0) / Math.max(1, runs.reduce((a, r) => a + r.present, 0)) * 1000) / 10,
    breachesOnFixedPaths: runs.reduce((a, r) => a + r.fixedBreaches, 0),
    attemptsOnFixedPaths: runs.reduce((a, r) => a + r.fixedAttempts, 0),
  };
}

const started = Date.now();
const rows = { random: [[], []], hacker: [[], []] };
for (let seed = 1; seed <= SEEDS; seed++) {
  for (const [name, learn] of [['random', false], ['hacker', true]]) {
    const [first, second] = await adversary(seed, learn);
    rows[name][0].push(first); rows[name][1].push(second);
  }
}
const results = {
  randomRun1: summarize(rows.random[0]), randomRun2: summarize(rows.random[1]),
  hackerRun1: summarize(rows.hacker[0]), hackerRun2: summarize(rows.hacker[1]),
};
const proof = {
  measuredAt: new Date().toISOString(), command: 'npm run eval:hacker', seeds: SEEDS,
  attackTicks: ATTACK_TICKS, fixTicks: FIX_TICKS, results,
  note: 'Seeds 1..N; each seed gives both adversaries the same two randomized clouds. Random is the Hacker with learning switched off. Claude Attacker is not included: it needs paid API calls.',
};
mkdirSync(new URL('../data/', import.meta.url), { recursive: true });
writeFileSync(new URL('../data/hacker-proof.json', import.meta.url), JSON.stringify(proof, null, 2) + '\n');

const line = (label, r) => `${label.padEnd(22)} ${String(r.meanAttemptsToFirstBreach ?? '-').padStart(6)} ${String(r.medianAttemptsToFirstBreach ?? '-').padStart(7)} ${`${r.breachedWithinWindow}/${r.runs}`.padStart(9)} ${`${r.successRate}%`.padStart(8)} ${`${r.weakSpotsFound}→${r.weakSpotsFoundByEnd}%`.padStart(12)} ${`${r.breachesOnFixedPaths}/${r.attemptsOnFixedPaths}`.padStart(12)}`;
console.log(`Seeds 1-${SEEDS}, ${ATTACK_TICKS} ticks of attack, then every open fix applied and ${FIX_TICKS} more ticks.\n`);
console.log(`${'adversary'.padEnd(22)} ${'mean'.padStart(6)} ${'median'.padStart(7)} ${'breached'.padStart(9)} ${'success'.padStart(8)} ${'found→end'.padStart(12)} ${'fixed paths'.padStart(12)}`);
console.log(`${''.padEnd(22)} ${'tries to 1st breach'.padStart(14)}`);
console.log(line('Random, run 1', results.randomRun1));
console.log(line('Random, run 2', results.randomRun2));
console.log(line('Hacker, run 1', results.hackerRun1));
console.log(line('Hacker, run 2 (memory)', results.hackerRun2));
console.log(`\nWrote data/hacker-proof.json in ${Math.round((Date.now() - started) / 100) / 10}s.`);
