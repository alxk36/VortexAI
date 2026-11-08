/**
 * Repeatable randomness for demos and evaluations. With the same seed, the
 * randomized cloud draws the same weak spots on every reset and the Hacker
 * makes the same choices from the same situations.
 */
/** A small, fast seeded generator (mulberry32) returning numbers in [0, 1). */
export function seeded(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6D2B79F5) >>> 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** VORTEX_SEED as a whole number, or null when unset or blank. */
export function parseSeed(value) {
  if (value === undefined || value === null || String(value).trim() === '') return null;
  const seed = Number(value);
  if (!Number.isInteger(seed) || seed < 0 || seed > 2 ** 32 - 1) throw new Error('VORTEX_SEED must be a whole number from 0 to 4294967295.');
  return seed;
}

/** Independent streams for one seed, so traffic timing cannot shift the layouts or the Hacker. */
export const streams = seed => ({ traffic: seeded(seed), layout: seeded(seed ^ 0x5bd1e995), hacker: seeded(seed ^ 0x27d4eb2f) });
