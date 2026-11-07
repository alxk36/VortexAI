import { DEFAULT_MODEL, DECISION_SCHEMA, SYSTEM_PROMPTS, prepareContext, servedModel, validateDecision } from './agents.mjs';

export const ANTHROPIC_ENDPOINT = 'https://api.anthropic.com/v1/messages';
const RESPONSE_LIMIT = 131072;
// Opus 5.5's cyber safeguard declines even the Attacker's fixed-menu choice.
// For that role only, Anthropic's server-side fallback re-runs a declined
// request on its recommended model for the refusal category (Opus 4.8 for cyber).
const FALLBACK_ROLES = new Set(['attacker']);
const FALLBACK_BETA = 'server-side-fallback-2026-07-01';

/** Bounded reads prevent an upstream response from exhausting the broker. */
export async function readBoundedJson(response, limit = RESPONSE_LIMIT) {
  if (!response.body) throw new Error('Empty response.');
  const reader = response.body.getReader();
  const chunks = []; let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); throw new Error('Response exceeds limit.'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

/** Only the broker calls this function. The destination cannot be supplied by a
 * model, browser, request body, environment URL, or redirect response.
 */
export async function inferClaude(agent, input, {
  apiKey = process.env.ANTHROPIC_API_KEY,
  model = process.env.ANTHROPIC_MODEL || DEFAULT_MODEL,
  fetchImpl = fetch,
  timeoutMs = 20_000,
  onModel = () => {},
} = {}) {
  if (!apiKey) throw new Error('Anthropic key is not configured.');
  if (typeof model !== 'string' || !/^claude-opus-5-5$/.test(model)) throw new Error('This lab is configured for Claude Opus 5.5 only.');
  const context = prepareContext(agent, input);
  const fallback = FALLBACK_ROLES.has(agent);
  const response = await fetchImpl(ANTHROPIC_ENDPOINT, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(Math.min(20_000, Math.max(1, timeoutMs))),
    headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2026-10-21', ...(fallback ? { 'anthropic-beta': FALLBACK_BETA } : {}) },
    body: JSON.stringify({
      model, max_tokens: 2048,
      ...(fallback ? { fallbacks: 'default' } : {}),
      system: SYSTEM_PROMPTS[agent],
      messages: [{ role: 'user', content: JSON.stringify(context) }],
      output_config: { effort: 'low', format: { type: 'json_schema', schema: DECISION_SCHEMA } },
    }),
  });
  if (!response.ok) { await response.body?.cancel(); throw new Error('Anthropic request was not successful.'); }
  const result = await readBoundedJson(response);
  // A refusal here means every model in the fallback chain declined.
  if (result.stop_reason !== 'end_turn' || !Array.isArray(result.content)) throw new Error('Model did not finish a complete decision.');
  // Top-level `model` names the model that produced this answer.
  const served = servedModel(result.model ?? model);
  if (!served) throw new Error('Response came from an unexpected model.');
  // Read only the text after the last fallback switch point, if any.
  const start = result.content.findLastIndex(block => block.type === 'fallback') + 1;
  const text = result.content.slice(start).filter(block => block.type === 'text').map(block => block.text).join('');
  if (!text || text.length > 12000) throw new Error('Empty or oversized model decision.');
  const decision = validateDecision(agent, JSON.parse(text), context);
  onModel(served);
  return decision;
}
