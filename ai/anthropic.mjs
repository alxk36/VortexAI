import { DEFAULT_MODEL, DECISION_SCHEMA, SYSTEM_PROMPTS, prepareContext, validateDecision } from './agents.mjs';

export const ANTHROPIC_ENDPOINT = 'https://api.anthropic.com/v1/messages';
const RESPONSE_LIMIT = 131072;

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
} = {}) {
  if (!apiKey) throw new Error('Anthropic key is not configured.');
  if (typeof model !== 'string' || !/^claude-opus-5-5$/.test(model)) throw new Error('This lab is configured for Claude Opus 5.5 only.');
  const context = prepareContext(agent, input);
  const response = await fetchImpl(ANTHROPIC_ENDPOINT, {
    method: 'POST', redirect: 'error', signal: AbortSignal.timeout(Math.min(20_000, Math.max(1, timeoutMs))),
    headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2026-10-21' },
    body: JSON.stringify({
      model, max_tokens: 2048,
      system: SYSTEM_PROMPTS[agent],
      messages: [{ role: 'user', content: JSON.stringify(context) }],
      output_config: { effort: 'low', format: { type: 'json_schema', schema: DECISION_SCHEMA } },
    }),
  });
  if (!response.ok) { await response.body?.cancel(); throw new Error('Anthropic request was not successful.'); }
  const result = await readBoundedJson(response);
  if (result.stop_reason !== 'end_turn' || !Array.isArray(result.content)) throw new Error('Model did not finish a complete decision.');
  const text = result.content.filter(block => block.type === 'text').map(block => block.text).join('');
  if (!text || text.length > 12000) throw new Error('Empty or oversized model decision.');
  return validateDecision(agent, JSON.parse(text), context);
}
