/**
 * The Hacker: an automated outside adversary that learns by trial and error.
 *
 * It is not a language model. It keeps a value for every attack it has tried:
 * a chain of allowlisted steps plus how it runs it (pace: fast or slow; spread:
 * one address or rotating addresses). After each attempt it scores what happened
 * (the reward) and moves that attack's value toward it, so recent results count
 * most and a fix that closes a path drags its value down within a few tries.
 * Usually it repeats its best attack; sometimes, or whenever nothing is paying
 * off, it explores: a variation of its best attack or a fresh one.
 *
 * What it learned survives lab resets, so each run starts from experience, but
 * the cloud is re-randomized each run, so old favorites can stop working.
 *
 * Containment: it only picks step ids from the simulator's catalog. The
 * simulator decides what each step does, and nothing leaves the in-memory model.
 */
import { ATTACK_ACTIONS, planProblem } from './simulation.mjs';
import { controlText } from './performance.mjs';

export const REWARD = Object.freeze({ breach: 1, data: 1, nothing: -1, blocked: -0.5, tripped: -1, rotate: -0.3, perTick: -0.05 });
const EXPLORE = 0.2;          // chance of trying something new even when the best attack pays off
const LEARNING_RATE = 0.35;   // how far one result moves an attack's value
const COOLDOWN_TICKS = 3;     // pause between attempts
const MAX_ARMS = 40;          // attacks remembered
const MAX_ATTEMPTS = 120;     // attempt records kept
const PROBES = Object.freeze({ fast: 2, slow: 1 }); // gateway requests sent with each part
// RFC 5737 TEST-NET-1 addresses: never routable, and separate from the user and bot ranges.
export const HACKER_ADDRESSES = Object.freeze(Array.from({ length: 48 }, (_, i) => `192.0.2.${10 + i * 5}`));
const STEPS = new Map(ATTACK_ACTIONS.map(a => [a.id, a]));
const round = n => Math.round(n * 100) / 100;
const unique = list => [...new Set(list)];
const average = list => list.length ? round(list.reduce((a, b) => a + b, 0) / list.length) : null;

/** Score one finished attempt. */
export function rewardFor({ breached = [], blockedBy = [], tookData = false, tripped = false, spread = 'single', ticks = 1 } = {}) {
  let reward = breached.length ? breached.length * REWARD.breach + (tookData ? REWARD.data : 0) : REWARD.nothing;
  // Each control that stopped a step costs a little: a wasted, noisy step.
  reward += REWARD.blocked * blockedBy.length;
  if (tripped) reward += REWARD.tripped;
  if (spread === 'rotate') reward += REWARD.rotate;
  return round(reward + REWARD.perTick * ticks);
}

export const attackText = ({ chain, pace, spread }) => `${chain.join(' → ')} (${pace}, ${spread === 'rotate' ? 'rotating addresses' : 'one address'})`;

/** Add a step and, first, whatever it requires. Steps are not repeated. */
function addStep(chain, stepId) {
  const next = [...chain];
  const visit = id => { if (next.includes(id)) return; for (const req of STEPS.get(id).requires) visit(req); next.push(id); };
  visit(stepId);
  return next;
}
/** Remove a step and every step that depends on it. */
function dropStep(chain, stepId) {
  const removed = new Set([stepId]);
  for (let changed = true; changed;) {
    changed = false;
    for (const id of chain) if (!removed.has(id) && STEPS.get(id).requires.some(req => removed.has(req))) { removed.add(id); changed = true; }
  }
  return chain.filter(id => !removed.has(id));
}
const keyOf = ({ chain, pace, spread }) => `${chain.join('>')}|${pace}|${spread}`;

export class Hacker {
  constructor({ random = Math.random } = {}) {
    this.random = random;
    this.enabled = false;
    this.run = 1;
    this.forget();
  }

  /** Wipe everything it has learned. */
  forget() {
    this.arms = new Map();
    this.attempts = [];
    this.firstRewards = []; // its first five rewards ever, kept for the learning trend
    this.runStats = new Map();
    this.total = 0;
    this.announced = null; // the favorite last written to the learning log
    this.newRun(this.run);
  }

  /** A new lab run: a fresh cloud and a fresh address, same experience. */
  newRun(run) {
    this.run = run;
    this.current = null;
    this.cooldown = 0;
    this.home = this._pick(HACKER_ADDRESSES);
    if (!this.runStats.has(run)) this.runStats.set(run, { attempts: 0, breaches: 0, firstBreachAt: null, reward: 0 });
  }

  /** Highest-valued attack it has tried; ties go to the one tried less. */
  best() {
    let top = null;
    for (const arm of this.arms.values()) if (arm.tries && (!top || arm.value > top.value || (arm.value === top.value && arm.tries < top.tries))) top = arm;
    return top;
  }

  /** Exploit the best attack, or explore when nothing pays off or by chance. */
  choose() {
    const best = this.best();
    if (best && best.value > 0 && this.random() >= EXPLORE) return { arm: best, explored: false };
    const spec = best && this.random() < 0.6 ? this._mutate(best) : this._randomSpec();
    return { arm: this._arm(spec), explored: true };
  }

  /** Advance the current attempt by one tick. Returns the attempt when it finishes. */
  tick(sim) {
    if (!this.enabled || !sim.running) return null;
    if (!this.current) {
      if (this.cooldown > 0) { this.cooldown -= 1; return null; }
      const { arm, explored } = this.choose();
      this.current = { arm, explored, parts: sim.hackerParts(arm.chain), index: 0, context: { blocked: false }, startTick: sim._tick, events: [], addresses: new Set() };
    }
    const current = this.current;
    const { pace, spread } = current.arm;
    // Fast runs the whole chain in one tick; slow runs one part per tick.
    const partsNow = pace === 'fast' ? current.parts.length : 1;
    for (let i = 0; i < partsNow && current.index < current.parts.length; i++) {
      const address = spread === 'rotate' ? this._pick(HACKER_ADDRESSES) : this.home;
      current.addresses.add(address);
      const emit = fields => { const event = sim.hackerEmit(fields, address); current.events.push(event); return event; };
      for (let p = 0; p < PROBES[pace]; p++) emit({ source: 'attacker', target: 'gateway', protocol: 'HTTPS', action: 'request', outcome: 'allowed', principal: 'anonymous', bytes: 900, detail: 'Hacker: a request arrives at the gateway.' });
      current.parts[current.index++].run(current.context, emit);
    }
    if (current.index < current.parts.length) return null;
    return this._finish(sim);
  }

  _finish(sim) {
    const { arm, explored, events, startTick, addresses } = this.current;
    this.current = null;
    this.cooldown = COOLDOWN_TICKS;
    const real = events.filter(e => e.control && e.control !== 'autoBlock');
    const breached = unique(real.filter(e => e.outcome === 'allowed').map(e => e.control));
    const blockedBy = unique(real.filter(e => e.outcome === 'denied').map(e => e.control));
    const touched = unique(real.map(e => e.control));
    const tripped = events.some(e => e.control === 'autoBlock') || [...addresses].some(a => sim._traffic.isBlocked(a, sim._tick));
    const tookData = breached.length > 0 && events.some(e => e.outcome === 'allowed' && (e.bytes ?? 0) >= 5000);
    const ticks = sim._tick - startTick + 1;
    const reward = rewardFor({ breached, blockedBy, tookData, tripped, spread: arm.spread, ticks });
    // A tripped address is burned; the next attempt starts from a new one.
    if (tripped && arm.spread !== 'rotate') this.home = this._pick(HACKER_ADDRESSES.filter(a => a !== this.home));

    const top = this.best();
    const bestBefore = top && { key: top.key, value: top.value };
    const valueBefore = arm.value;
    arm.value = arm.tries ? round(arm.value + LEARNING_RATE * (reward - arm.value)) : reward;
    arm.tries += 1;
    if (breached.length) arm.wins += 1;
    arm.lastReward = reward;
    this._trim();

    const stats = this.runStats.get(this.run);
    stats.attempts += 1;
    stats.reward = round(stats.reward + reward);
    const firstBreach = breached.length > 0 && stats.firstBreachAt === null;
    if (breached.length) { stats.breaches += 1; if (firstBreach) stats.firstBreachAt = stats.attempts; }

    const result = breached.length ? 'breached' : tripped ? 'tripped' : blockedBy.length ? 'blocked' : 'nothing';
    const attempt = {
      n: ++this.total, run: this.run, runAttempt: stats.attempts, key: arm.key, chain: [...arm.chain], pace: arm.pace, spread: arm.spread, explored,
      startTick, endTick: sim._tick, ticks, result, breached, blockedBy, touched, tookData, tripped, reward, valueBefore, value: arm.value,
      eventIds: events.map(e => e.id), clientIds: [...addresses], flagged: false,
    };
    attempt.lessons = this._lessons(attempt, bestBefore, firstBreach);
    this.attempts.push(attempt);
    if (this.firstRewards.length < 5) this.firstRewards.push(reward);
    if (this.attempts.length > MAX_ATTEMPTS) this.attempts.shift();
    return attempt;
  }

  /** Only the moments worth a learning-log line: a first breach, a new favorite, a favorite lost. */
  _lessons(attempt, bestBefore, firstBreach) {
    const lessons = [];
    const text = attackText(attempt);
    const sign = n => `${n > 0 ? '+' : ''}${n}`;
    if (firstBreach) {
      const previous = this.previousRun();
      lessons.push(`First breach this run on attempt ${attempt.runAttempt}${previous ? ` (run ${previous.run}: ${previous.firstBreachAt ? `attempt ${previous.firstBreachAt}` : 'none'})` : ''}: ${attempt.chain.join(' → ')} got through ${attempt.breached.map(controlText).join(', ')}.`);
    }
    // Announce a favorite only when it really pays (value 1 or more) and clearly beats the last one announced.
    const bestAfter = this.best();
    const announced = this.announced && this.arms.get(this.announced);
    if (bestAfter && bestAfter.value >= 1 && bestAfter.key !== this.announced && (!announced || announced.value <= 0 || bestAfter.value >= announced.value + 0.3)) {
      this.announced = bestAfter.key;
      lessons.push(`New favorite: ${attackText(bestAfter)}, value ${bestAfter.value}.`);
    }
    // Losing an announced favorite is the other moment worth logging: usually a fix closed its path.
    if (this.announced === attempt.key && attempt.valueBefore > 0 && attempt.value <= 0) {
      const why = attempt.result === 'tripped' ? 'the tripwire caught it' : attempt.blockedBy.length ? `blocked by ${attempt.blockedBy.map(controlText).join(', ')}` : 'it got nothing';
      lessons.push(`${text} stopped paying off (${why}, reward ${sign(attempt.reward)}); value fell to ${attempt.value}. Exploring.`);
    }
    return lessons;
  }

  /** The latest earlier run that had any attempts. */
  previousRun() {
    const earlier = [...this.runStats.entries()].filter(([run, s]) => run < this.run && s.attempts).sort((a, b) => b[0] - a[0]);
    return earlier.length ? { run: earlier[0][0], ...earlier[0][1] } : null;
  }

  /** A new random attack: one or two goal steps with what they require. */
  _randomSpec() {
    let chain = addStep([], this._pick(ATTACK_ACTIONS).id);
    if (this.random() < 0.35) {
      const longer = addStep(chain, this._pick(ATTACK_ACTIONS).id);
      if (!planProblem(longer)) chain = longer;
    }
    return { chain, pace: this.random() < 0.5 ? 'fast' : 'slow', spread: this.random() < 0.3 ? 'rotate' : 'single' };
  }

  /** A small change to an attack: its pace, its spread, or one step added, dropped or swapped. */
  _mutate(arm) {
    for (let attempt = 0; attempt < 6; attempt++) {
      const spec = { chain: [...arm.chain], pace: arm.pace, spread: arm.spread };
      const op = this._pick(['pace', 'spread', 'add', 'drop', 'swap']);
      if (op === 'pace') spec.pace = arm.pace === 'fast' ? 'slow' : 'fast';
      if (op === 'spread') spec.spread = arm.spread === 'rotate' ? 'single' : 'rotate';
      if (op === 'add') spec.chain = addStep(spec.chain, this._pick(ATTACK_ACTIONS).id);
      if (op === 'drop') spec.chain = dropStep(spec.chain, this._pick(spec.chain));
      if (op === 'swap') spec.chain = addStep(dropStep(spec.chain, this._pick(spec.chain)), this._pick(ATTACK_ACTIONS).id);
      if (spec.chain.length && !planProblem(spec.chain) && keyOf(spec) !== arm.key) return spec;
    }
    return this._randomSpec();
  }

  _arm(spec) {
    const key = keyOf(spec);
    if (!this.arms.has(key)) this.arms.set(key, { key, chain: [...spec.chain], pace: spec.pace, spread: spec.spread, tries: 0, value: 0, wins: 0, lastReward: null });
    return this.arms.get(key);
  }

  /** Forget the worst attacks once too many are remembered. */
  _trim() {
    const keep = new Set([this.best()?.key, this.current?.arm.key]);
    while (this.arms.size > MAX_ARMS) {
      const worst = [...this.arms.values()].filter(a => !keep.has(a.key)).sort((a, b) => a.value - b.value)[0];
      this.arms.delete(worst.key);
    }
  }

  _pick(list) { return list[Math.floor(this.random() * list.length)]; }

  /** Dashboard view: status, favorite, recent attempts, per-run first breach and the reward trend. */
  view() {
    const best = this.best();
    const rewards = this.attempts.map(a => a.reward);
    const shape = a => ({ n: a.n, run: a.run, chain: a.chain, pace: a.pace, spread: a.spread, result: a.result, reward: a.reward, breached: a.breached, blockedBy: a.blockedBy, explored: a.explored, flagged: a.flagged });
    return {
      enabled: this.enabled, run: this.run, total: this.total, remembered: this.arms.size,
      best: best ? { chain: [...best.chain], pace: best.pace, spread: best.spread, value: best.value, tries: best.tries, wins: best.wins } : null,
      current: this.current ? { chain: [...this.current.arm.chain], pace: this.current.arm.pace, spread: this.current.arm.spread, step: this.current.index, parts: this.current.parts.length } : null,
      recent: this.attempts.slice(-8).reverse().map(shape),
      // Its first five attempts ever (naive) against its latest ten.
      trend: this.total >= 6 ? { early: average(this.firstRewards), recent: average(rewards.slice(-10)), attempts: this.total } : null,
      runs: [...this.runStats.entries()].sort((a, b) => a[0] - b[0]).slice(-6).map(([run, s]) => ({ run, ...s })),
    };
  }
}
