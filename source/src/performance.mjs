/**
 * Agent performance, measured from what actually happened in this lab run:
 * which attack runs got through and which control each one went through,
 * which of them were flagged, and whether each applied fix held.
 *
 * The defense has to come out ahead: if a path is breached after its fix,
 * the verdict is Failing rather than a lower number.
 */
export const WEAK_SPOTS = Object.freeze(['storagePrivate', 'requireMfa', 'databaseLeastPrivilege']);
export const CONTROL_TEXT = Object.freeze({ storagePrivate: 'private storage', requireMfa: 'MFA', databaseLeastPrivilege: 'least-privilege database role' });
export const controlText = key => CONTROL_TEXT[key] ?? key;

const DEFINITIONS = Object.freeze({
  attacker: 'Known weak spots that at least one attack run got through, and how many runs got through.',
  searcher: 'Attack runs flagged by a finding, an AI analysis citing their events, or a blocked-replay check. Hidden bots count after they are revealed.',
  builder: 'Applied fixes that blocked a replay and were never breached afterwards, and breaches on fixed paths before and after each fix.',
});
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

/**
 * @param attackHistory finished attack runs, newest first, each with exploited/touched controls and a flagged flag
 * @param fixes ledger of applied fixes: { policyKey, title, appliedTick, heldTick, failedTick }
 * @param botScore result of revealing hidden bots, or null
 * @param autoBlocked client addresses the Searcher tripwire has blocked
 */
export function performanceReport({ attackHistory = [], fixes = [], botScore = null, autoBlocked = [] } = {}) {
  const foundControls = WEAK_SPOTS.filter(c => attackHistory.some(h => (h.exploited ?? []).includes(c)));
  const attacker = {
    found: foundControls.length, total: WEAK_SPOTS.length, foundControls,
    runs: attackHistory.length,
    gotThrough: attackHistory.filter(h => h.result === 'succeeded').length,
    aiChains: attackHistory.filter(h => h.plan).length,
  };

  let bots = null;
  if (botScore?.bots) {
    const ids = new Set(botScore.bots.map(b => b.clientId));
    const caught = new Set([...(botScore.caught ?? []), ...autoBlocked.filter(id => ids.has(id))]);
    bots = { caught: caught.size, total: ids.size, falseAlarms: (botScore.falseAlarms ?? []).length };
  }
  const searcher = { attempts: attackHistory.length, flagged: attackHistory.filter(h => h.flagged).length, bots };

  const before = { breaches: 0, attempts: 0 };
  const after = { breaches: 0, attempts: 0 };
  for (const fix of fixes) {
    for (const h of attackHistory) {
      if (!(h.touched ?? []).includes(fix.policyKey)) continue;
      const side = h.endTick <= fix.appliedTick ? before : after;
      side.attempts += 1;
      if ((h.exploited ?? []).includes(fix.policyKey)) side.breaches += 1;
    }
  }
  const builder = {
    applied: fixes.length,
    held: fixes.filter(f => f.heldTick !== undefined && f.failedTick === undefined).length,
    failed: fixes.filter(f => f.failedTick !== undefined).length,
    before, after,
  };

  return { verdict: verdictFor(attacker, builder, fixes), attacker, searcher, builder, lines: linesFor(attacker, searcher, builder), definitions: DEFINITIONS };
}

function verdictFor(attacker, builder, fixes) {
  const failed = fixes.filter(f => f.failedTick !== undefined);
  if (failed.length) return { status: 'failing', text: `Failing: ${failed.map(f => controlText(f.policyKey)).join(', ')} ${failed.length === 1 ? 'was' : 'were'} breached after the fix.` };
  if (!attacker.runs) return { status: 'idle', text: 'No attacks yet.' };
  const held = new Set(fixes.filter(f => f.heldTick !== undefined).map(f => f.policyKey));
  const open = attacker.foundControls.filter(c => !held.has(c));
  if (!open.length) return { status: 'defended', text: attacker.found ? 'Defended: every weak spot found has a fix that held.' : 'Defended: no attack got through.' };
  const awaiting = open.filter(c => fixes.some(f => f.policyKey === c));
  const detail = awaiting.length ? ` (${awaiting.map(controlText).join(', ')} applied, awaiting a replay)` : '';
  return { status: 'at-risk', text: `At risk: ${open.map(controlText).join(', ')} ${open.length === 1 ? 'is' : 'are'} not proven fixed${detail}.` };
}

function linesFor(attacker, searcher, builder) {
  const chains = attacker.aiChains ? ` · ${plural(attacker.aiChains, 'AI-invented chain')}` : '';
  const bots = searcher.bots ? ` · ${searcher.bots.caught} of ${plural(searcher.bots.total, 'hidden bot')}${searcher.bots.falseAlarms ? `, ${plural(searcher.bots.falseAlarms, 'false alarm')}` : ''}` : '';
  return {
    attacker: `Found ${attacker.found} of ${attacker.total} weak spots · ${attacker.gotThrough} of ${plural(attacker.runs, 'attack run')} got through${chains}`,
    searcher: `Flagged ${searcher.flagged} of ${plural(searcher.attempts, 'attack attempt')}${bots}`,
    builder: builder.applied
      ? `${builder.held} of ${plural(builder.applied, 'fix', 'fixes')} held${builder.failed ? ` · ${builder.failed} failed` : ''} · breaches on fixed paths ${builder.before.breaches}/${builder.before.attempts} before, ${builder.after.breaches}/${builder.after.attempts} after`
      : 'No fixes applied yet',
  };
}
