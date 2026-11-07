import http from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runAgent, DEFAULT_MODEL, assertRole } from './agents.mjs';
import { inferClaude } from './anthropic.mjs';
import { authorized, send, readBody } from './http.mjs';

/** This narrow broker is not a generic HTTP proxy and cannot execute tools. */
export function createBroker({ token = process.env.AGENT_BROKER_TOKEN, apiKey = process.env.ANTHROPIC_API_KEY, model = process.env.ANTHROPIC_MODEL || DEFAULT_MODEL, infer = inferClaude } = {}) {
  let busy = false;
  const server = http.createServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/health') return send(response, 200, { ok: true, configured: Boolean(apiKey), provider: 'anthropic', model });
    if (!authorized(request, token)) return send(response, 401, { error: 'Unauthorized.' });
    if (request.method !== 'POST' || request.url !== '/infer') return send(response, 404, { error: 'Not found.' });
    if (busy) return send(response, 429, { error: 'One model request is already in progress.' });
    busy = true;
    try {
      const body = await readBody(request, ['agent', 'context']);
      assertRole(body.agent);
      const result = await runAgent(body.agent, body.context, {
        model,
        infer: apiKey ? (agent, context) => infer(agent, context, { apiKey, model }) : undefined,
      });
      if (!apiKey) result.reason = 'Anthropic API key is not configured; deterministic fallback used.';
      send(response, 200, result);
    } catch { send(response, 400, { error: 'Invalid agent request.' }); }
    finally { busy = false; }
  });
  server.requestTimeout = 25_000;
  server.headersTimeout = 10_000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.env.VORTEX_CONTAINER !== '1') throw new Error('Run the model broker through the lab Compose configuration.');
  if (!process.env.AGENT_BROKER_TOKEN || process.env.AGENT_BROKER_TOKEN.length < 24) throw new Error('A generated broker token is required.');
  const server = createBroker();
  server.listen(8080, '0.0.0.0', () => console.log('VortexAI model broker ready.'));
}
