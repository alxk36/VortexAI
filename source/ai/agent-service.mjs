import http from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AGENT_ROLES, DEFAULT_MODEL, assertRole, prepareContext, runAgent, servedModel, validateDecision } from './agents.mjs';
import { readBoundedJson } from './anthropic.mjs';
import { authorized, send, readBody } from './http.mjs';

const BROKER_URL = 'http://model-broker:8080/infer';

/** Agents know only the broker and their input catalog; they have no targets,
 * shell tools, provider keys, or authority to apply a Builder recommendation.
 */
export async function callBroker(agent, input, { token = process.env.AGENT_BROKER_TOKEN, fetchImpl = fetch } = {}) {
  const context = prepareContext(agent, input);
  if (!token || token.length < 24) return runAgent(agent, context);
  try {
    const response = await fetchImpl(BROKER_URL, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(23_000),
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ agent, context }),
    });
    if (!response.ok) { await response.body?.cancel(); throw new Error('Broker unavailable.'); }
    const result = await readBoundedJson(response, 32768);
    if (result.agent !== agent || !['model', 'fallback'].includes(result.mode) || result.provider !== 'anthropic' || result.model !== DEFAULT_MODEL) throw new Error('Invalid broker result.');
    const decision = validateDecision(agent, {
      summary: result.summary, scenarioId: result.scenarioId,
      evidenceIds: result.evidenceIds, recommendationIds: result.recommendationIds, labels: result.labels,
    }, context);
    const servedBy = result.mode === 'model' ? servedModel(result.servedBy) : undefined;
    return { agent, mode: result.mode, provider: 'anthropic', model: DEFAULT_MODEL, ...decision,
      ...(servedBy ? { servedBy } : {}),
      ...(result.mode === 'fallback' ? { reason: 'Broker returned deterministic fallback; no model decision was used.' } : {}) };
  } catch {
    const result = await runAgent(agent, context);
    result.reason = 'Model broker could not provide a validated response; deterministic fallback used.';
    return result;
  }
}

export function createAgentServer({ role = process.env.AGENT_ROLE, controlToken = process.env.AGENT_CONTROL_TOKEN, brokerToken = process.env.AGENT_BROKER_TOKEN, broker = callBroker } = {}) {
  assertRole(role); let busy = false;
  const server = http.createServer(async (request, response) => {
    if (request.method === 'GET' && request.url === '/health') return send(response, 200, { ok: true, agent: role, model: DEFAULT_MODEL, provider: 'anthropic' });
    if (!authorized(request, controlToken)) return send(response, 401, { error: 'Unauthorized.' });
    if (request.method !== 'POST' || request.url !== '/run') return send(response, 404, { error: 'Not found.' });
    if (busy) return send(response, 429, { error: 'This agent is already working.' });
    busy = true;
    try {
      const body = await readBody(request, ['context']);
      const context = prepareContext(role, body.context);
      send(response, 200, await broker(role, context, { token: brokerToken }));
    } catch { send(response, 400, { error: 'Invalid agent context.' }); }
    finally { busy = false; }
  });
  server.requestTimeout = 25_000; server.headersTimeout = 10_000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.env.VORTEX_CONTAINER !== '1') throw new Error('Run agents through the lab Compose configuration.');
  if (!AGENT_ROLES.includes(process.env.AGENT_ROLE)) throw new Error('AGENT_ROLE must name one supported agent.');
  if (!process.env.AGENT_CONTROL_TOKEN || process.env.AGENT_CONTROL_TOKEN.length < 24) throw new Error('A generated agent control token is required.');
  const server = createAgentServer();
  server.listen(8080, '0.0.0.0', () => console.log(`VortexAI ${process.env.AGENT_ROLE} agent ready.`));
}
