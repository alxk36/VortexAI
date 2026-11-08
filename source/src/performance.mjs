/**
 * Agent performance, measured from what actually happened in this lab run:
 * which attack runs got through and which control each one went through,
 * which of them were flagged, and whether each applied fix held.
 *
 * The defense has to come out ahead: if a path is breached after its fix,
 * by the Attacker or the Hacker, the verdict is Failing rather than a lower number.
 */
// The classic layout's weak spots. Randomized runs pass their own list.
export const WEAK_SPOTS = Object.freeze(['storagePrivate', 'requireMfa', 'databaseLeastPrivilege']);
export const CONTROL_TEXT = Object.freeze({
  storagePrivate: 'private storage', requireMfa: 'MFA', databaseLeastPrivilege: 'least-privilege database role',
  accountLockout: 'account lockout', metadataProtection: 'metadata protection', secretsManager: 'secret storage',
});
export const controlText = key => CONTROL_TEXT[key] ?? key;

const DEFINITIONS = Object.freeze({
  attacker: 'Weak spots in this run that at least one attack run got through, and how many runs got through.',
  searcher: 'Attack runs and Hacker attempts flagged by a finding, an AI analysis citing their events or addresses, the tripwire, or a blocked-replay check. Hidden bots count after they are revealed.',
  builder: 'Applied fixes that blocked a replay and were never breached afterwards, and breaches on fixed paths (Attacker and Hacker) before and after each fix.',
  hacker: 'Automated trial-and-error attempts this run, how many got through, which weak spots it found, and its average reward in its first five attempts ever versus its latest ten.',
});
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
const signed = n => `${n > 0 ? '+' : ''}${n}`;

/**
 * @param attackHistory finished attack runs, newest first, each with exploited/touched controls and a flagged flag
 * @param fixes ledger of applied fixes: { policyKey, title, appliedTick, heldTick, failedTick }
 * @param botScore result of revealing hidden bots, or null
 * @param autoBlocked client addresses the Searcher tripwire has blocked
 * @param weakSpots controls missing at the start of this run
 * @param hacker null, or { attempts: this run's attempts, previousFirstBreach, trend }
 */
export function performanceReport({ attackHistory = [], fixes = [], botScore = null, autoBlocked = [], weakSpots = WEAK_SPOTS, hacker = null } = {}) {
  const foundControls = weakSpots.filter(c => attackHistory.some(h => (h.exploited ?? []).includes(c)));
  const attacker = {
    found: foundControls.length, total: weakSpots.length, foundControls,
    runs: attackHistory.length,
    gotThrough: attackHistory.filter(h => h.result === 'succeeded').length,
    aiChains: attackHistory.filter(h => h.plan).length,
  };

  // Hacker attempts read like attack runs: what they touched, what they got through, when they ended.
  const attempts = hacker?.attempts ?? [];
  const hackerEvents = attempts.map(a => a.controlEvents ?? (a.touched ?? []).map(control => ({ control, tick: a.endTick, allowed: (a.breached ?? []).includes(control) })));
  const hackerStats = hacker ? {
    attempts: attempts.length,
    gotThrough: attempts.filter(a => (a.breached ?? []).length).length,
    foundControls: weakSpots.filter(c => attempts.some(a => (a.breached ?? []).includes(c))),
    firstBreachAt: attempts.find(a => (a.breached ?? []).length)?.runAttempt ?? null,
    previousFirstBreach: hacker.previousFirstBreach ?? null,
    trend: hacker.trend ?? null,
    total: weakSpots.length,
  } : null;

  let bots = null;
  if (botScore?.bots) {
    const ids = new Set(botScore.bots.map(b => b.clientId));
    const caught = new Set([...(botScore.caught ?? []), ...autoBlocked.filter(id => ids.has(id))]);
    bots = { caught: caught.size, total: ids.size, falseAlarms: (botScore.falseAlarms ?? []).length };
  }
  const searcher = {
    attempts: attackHistory.length, flagged: attackHistory.filter(h => h.flagged).length, bots,
    hacker: attempts.length ? { attempts: attempts.length, flagged: attempts.filter(a => a.flagged).length } : null,
  };

  const before = { breaches: 0, attempts: 0 };
  const after = { breaches: 0, attempts: 0 };
  for (const fix of fixes) {
    for (const h of attackHistory) {
      if (!(h.touched ?? []).includes(fix.policyKey)) continue;
      const side = h.endTick <= fix.appliedTick ? before : after;
      side.attempts += 1;
      if ((h.exploited ?? []).includes(fix.policyKey)) side.breaches += 1;
    }
    // Hacker attempts are judged per event: an attempt that spans the fix counts on the side of each step.
    for (const events of hackerEvents) {
      const relevant = events.filter(e => e.control === fix.policyKey);
      if (!relevant.length) continue;
      const later = relevant.filter(e => e.tick > fix.appliedTick);
      const side = later.length ? after : before;
      side.attempts += 1;
      if ((later.length ? later : relevant).some(e => e.allowed)) side.breaches += 1;
    }
  }
  const builder = {
    applied: fixes.length,
    held: fixes.filter(f => f.heldTick !== undefined && f.failedTick === undefined).length,
    failed: fixes.filter(f => f.failedTick !== undefined).length,
    before, after,
  };

  return {
    verdict: verdictFor(attacker, builder, fixes, hackerStats), attacker, searcher, builder, hacker: hackerStats,
    lines: linesFor(attacker, searcher, builder, hackerStats), definitions: DEFINITIONS,
  };
}

function verdictFor(attacker, builder, fixes, hacker) {
  const failed = fixes.filter(f => f.failedTick !== undefined);
  if (failed.length) return { status: 'failing', text: `Failing: ${failed.map(f => controlText(f.policyKey)).join(', ')} ${failed.length === 1 ? 'was' : 'were'} breached after the fix.` };
  if (!attacker.runs && !hacker?.attempts) return { status: 'idle', text: 'No attacks yet.' };
  const found = [...new Set([...attacker.foundControls, ...(hacker?.foundControls ?? [])])];
  const held = new Set(fixes.filter(f => f.heldTick !== undefined).map(f => f.policyKey));
  const open = found.filter(c => !held.has(c));
  if (!open.length) return { status: 'defended', text: found.length ? 'Defended: every weak spot found has a fix that held.' : 'Defended: no attack got through.' };
  const awaiting = open.filter(c => fixes.some(f => f.policyKey === c));
  const detail = awaiting.length ? ` (${awaiting.map(controlText).join(', ')} applied, awaiting a replay)` : '';
  return { status: 'at-risk', text: `At risk: ${open.map(controlText).join(', ')} ${open.length === 1 ? 'is' : 'are'} not proven fixed${detail}.` };
}

function linesFor(attacker, searcher, builder, hacker) {
  const chains = attacker.aiChains ? ` · ${plural(attacker.aiChains, 'AI-invented chain')}` : '';
  const bots = searcher.bots ? ` · ${searcher.bots.caught} of ${plural(searcher.bots.total, 'hidden bot')}${searcher.bots.falseAlarms ? `, ${plural(searcher.bots.falseAlarms, 'false alarm')}` : ''}` : '';
  const hackerFlags = searcher.hacker ? ` · ${searcher.hacker.flagged} of ${plural(searcher.hacker.attempts, 'Hacker attempt')}` : '';
  const lines = {
    attacker: `Found ${attacker.found} of ${attacker.total} weak spots · ${attacker.gotThrough} of ${plural(attacker.runs, 'attack run')} got through${chains}`,
    searcher: `Flagged ${searcher.flagged} of ${plural(searcher.attempts, 'attack attempt')}${bots}${hackerFlags}`,
    builder: builder.applied
      ? `${builder.held} of ${plural(builder.applied, 'fix', 'fixes')} held${builder.failed ? ` · ${builder.failed} failed` : ''} · breaches on fixed paths ${builder.before.breaches}/${builder.before.attempts} before, ${builder.after.breaches}/${builder.after.attempts} after`
      : 'No fixes applied yet',
  };
  if (hacker) {
    const trend = hacker.trend ? ` · avg reward ${signed(hacker.trend.early)} → ${signed(hacker.trend.recent)}` : '';
    lines.hacker = hacker.attempts
      // Success rate leads: first-breach timing is mostly luck (see npm run eval:hacker), so no run-to-run race.
      ? `${hacker.gotThrough} of ${plural(hacker.attempts, 'attempt')} got through (${Math.round(hacker.gotThrough / hacker.attempts * 100)}%) · found ${hacker.foundControls.length} of ${hacker.total} weak spots · first breach: ${hacker.firstBreachAt ? `attempt ${hacker.firstBreachAt}` : 'none yet'}${trend}`
      : `No attempts this run${trend}`;
  }
  return lines;
}
