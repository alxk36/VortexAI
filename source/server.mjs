/** Dashboard entry point: serve local assets and validate named runtime commands.
 * Runtime owns environment/agent state; this module owns HTTP and timer lifetimes.
 * Importing createServer is safe for tests and does not start a listener.
 */
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { Simulation } from './src/simulation.mjs';
import { Runtime } from './src/runtime.mjs';
import { sharedFindings } from './src/findings.mjs';
import { Hacker } from './src/hacker.mjs';
import { parseSeed, streams } from './src/seed.mjs';

const PUBLIC_DIRECTORY = fileURLToPath(new URL('./public/', import.meta.url));
const BODY_LIMIT = 4096;
const ASSETS = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/app.mjs', ['app.mjs', 'text/javascript; charset=utf-8']],
  ['/grid-math.mjs', ['grid-math.mjs', 'text/javascript; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/favicon.svg', ['favicon.svg', 'image/svg+xml']],
]);

// The browser can talk only to this loopback server. No remote scripts or services
// are needed; the simulation itself never opens a network connection.
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

function sendJson(response, status, value) {
  response.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(value));
}

function fail(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  return error;
}

// Bound request bodies before parsing. Invalid JSON and unexpected structures
// cannot become simulation commands.
async function readJson(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] ?? '')) {
    throw fail('Use Content-Type: application/json.', 415);
  }
  const bytes = await new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    let size = 0;
    let exceeded = false;
    request.on('data', (chunk) => {
      if (exceeded) return; // Drain excess input without retaining it in memory.
      size += chunk.length;
      if (size > BODY_LIMIT) {
        exceeded = true;
        chunks.length = 0;
        rejectBody(fail('Request body exceeds 4 KiB.', 413));
      } else chunks.push(chunk);
    });
    request.on('end', () => { if (!exceeded) resolveBody(Buffer.concat(chunks)); });
    request.on('error', rejectBody);
    request.on('aborted', () => rejectBody(fail('Request was interrupted.')));
  });
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { throw fail('Request body must be valid JSON.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw fail('Request body must be a JSON object.');
  }
  return value;
}

function validateFields(body, fields) {
  if (Object.keys(body).some((field) => !fields.includes(field))) {
    throw fail('Unexpected request field.');
  }
}

function validateId(body) {
  validateFields(body, ['id']);
  if (typeof body.id !== 'string' || !body.id.length || body.id.length > 120) {
    throw fail('A valid id is required.');
  }
  return body.id;
}

/**
 * Build the local HTTP interface. Importing this module starts neither a listener
 * nor a timer, so tests and future integrations can own the server lifecycle.
 */
export function createServer({ simulation = new Simulation(), tickMs = 900, autoTick = true, publicDirectory = PUBLIC_DIRECTORY } = {}) {
  let interval;
  const server = http.createServer(async (request, response) => {
    try {
      const port = server.address()?.port;
      const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
      // Host checking prevents DNS rebinding; Origin and Fetch Metadata checking
      // prevents an unrelated website from controlling this local application.
      if (!hosts.has(request.headers.host)) throw fail('Only this local server is allowed.', 403);
      const origin = request.headers.origin;
      if (origin && ![...hosts].some((host) => origin === `http://${host}`)) {
        throw fail('Cross-origin requests are not allowed.', 403);
      }
      if (request.headers['sec-fetch-site'] === 'cross-site') {
        throw fail('Cross-site requests are not allowed.', 403);
      }

      // Read only explicit routes. Do not map arbitrary URL paths to disk.
      const path = request.url?.split('?')[0];
      if (path === '/api/findings') {
        if (request.method !== 'GET') throw fail('Use GET for this endpoint.',405);
        return sendJson(response,200,sharedFindings(await simulation.snapshot()));
      }
      if (path === '/api/state') {
        if (request.method !== 'GET') throw fail('Use GET for this endpoint.', 405);
        return sendJson(response, 200, await simulation.snapshot());
      }
      const mutations = new Set(['/api/scenario', '/api/recommendation', '/api/running', '/api/reset', '/api/node', '/api/mode', '/api/ai/run', '/api/traffic', '/api/bots/reveal', '/api/unblock', '/api/hacker', '/api/hacker/forget', '/api/demo/restart']);
      if (mutations.has(path)) {
        if (request.method !== 'POST') throw fail('Use POST for this endpoint.', 405);
        const body = await readJson(request);
        if (path === '/api/scenario') await simulation.runScenario(validateId(body));
        if (path === '/api/recommendation') await simulation.applyRecommendation(validateId(body));
        if (path === '/api/running') {
          validateFields(body, ['running']);
          if (typeof body.running !== 'boolean') throw fail('running must be a boolean.');
          await simulation.setRunning(body.running);
        }
        if (path === '/api/reset') {
          validateFields(body, []);
          await simulation.reset();
        }
        if (path === '/api/node') {
          validateFields(body, ['id','status','action']);
          if (typeof body.id !== 'string') throw fail('A node id is required.');
          await simulation.updateNode(body.id, body.status, body.action);
        }
        if (path === '/api/mode') {
          validateFields(body,['mode']);
          if (!simulation.setMode) throw fail('Runtime mode switching is unavailable.');
          await simulation.setMode(body.mode);
        }
        if (path === '/api/traffic') {
          validateFields(body, ['users', 'bots']);
          if (!Number.isInteger(body.users) || typeof body.bots !== 'boolean') throw fail('users must be a whole number and bots true or false.');
          await simulation.setTraffic({ users: body.users, bots: body.bots });
        }
        if (path === '/api/bots/reveal') {
          validateFields(body, []);
          await simulation.revealBots();
        }
        if (path === '/api/unblock') {
          validateFields(body, ['clientId']);
          if (typeof body.clientId !== 'string' || body.clientId.length > 40) throw fail('A client address is required.');
          await simulation.unblockClient(body.clientId);
        }
        if (path === '/api/hacker') {
          validateFields(body, ['enabled']);
          if (typeof body.enabled !== 'boolean') throw fail('enabled must be true or false.');
          if (!simulation.setHacker) throw fail('The Hacker is unavailable.');
          await simulation.setHacker(body.enabled);
        }
        if (path === '/api/hacker/forget') {
          validateFields(body, []);
          if (!simulation.forgetHacker) throw fail('The Hacker is unavailable.');
          await simulation.forgetHacker();
        }
        if (path === '/api/demo/restart') {
          validateFields(body, ['seed']);
          if (!Number.isInteger(body.seed) || body.seed < 0 || body.seed > 2 ** 32 - 1) throw fail('seed must be a whole number.');
          if (!simulation.restartDemo) throw fail('Demo restart is unavailable.');
          await simulation.restartDemo(body.seed);
        }
        if (path === '/api/ai/run') {
          validateFields(body,['agent']);
          if (!simulation.runAI) throw fail('Agent runtime is unavailable.');
          await simulation.runAI(body.agent);
        }
        return sendJson(response, 200, await simulation.snapshot());
      }
      const asset = ASSETS.get(path);
      if (!asset) throw fail('Not found.', 404);
      if (!['GET', 'HEAD'].includes(request.method)) throw fail('Use GET or HEAD for assets.', 405);
      let bytes;
      try { bytes = await readFile(resolve(publicDirectory, asset[0])); }
      catch (error) {
        if (error.code === 'ENOENT') throw fail('Asset not found.', 404);
        throw error;
      }
      response.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': asset[1], 'Content-Length': bytes.length });
      response.end(request.method === 'HEAD' ? undefined : bytes);
    } catch (error) {
      if (response.headersSent || response.destroyed) return;
      // Engine validation errors are safe to display; filesystem/internal details
      // are not returned to the browser.
      const status = error.status ?? (error.code ? 500 : 400);
      sendJson(response, status, { error: status === 500 ? 'Internal server error.' : error.message });
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.on('listening', () => {
    if (autoTick) interval = setInterval(() => Promise.resolve(simulation.tick()).catch(()=>{}), tickMs).unref();
  });
  server.on('close', () => clearInterval(interval));
  return server;
}

// Local CLI usage binds to loopback; Compose uses a container listener whose
// only published host binding is loopback. A HOST environment variable is unused.
const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (isDirectRun) {
  const port = Number(process.env.PORT ?? 4173);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('PORT must be an integer from 1 to 65535.');
    process.exitCode = 1;
  } else {
    // Every reset draws a new set of weak spots in the in-memory cloud. VORTEX_SEED makes
    // the sequence of clouds and the Hacker's choices repeatable, for demos and recordings.
    const seed = parseSeed(process.env.VORTEX_SEED);
    const random = seed === null ? null : streams(seed);
    // The measured comparison from npm run eval:hacker, if it has been run.
    let proof = null;
    try { proof = JSON.parse(readFileSync(new URL('./data/hacker-proof.json', import.meta.url), 'utf8')); } catch {}
    const server = createServer({simulation:new Runtime({seed, proof,
      simulation:new Simulation({layout:'random', ...(random ? {random:random.traffic, layoutRandom:random.layout} : {})}),
      ...(random ? {hacker:new Hacker({random:random.hacker})} : {})})});
    server.on('error', (error) => {
      console.error(`VortexAI could not start: ${error.message}`);
      process.exitCode = 1;
    });
    // Docker publishes this container listener on host loopback only. Local mode
    // still binds directly to loopback; browser Host/Origin checks apply to both.
    server.listen(port, process.env.VORTEX_CONTAINER === '1' ? '0.0.0.0' : '127.0.0.1', () => {
      console.log(`VortexAI local simulation: http://127.0.0.1:${port}`);
      console.log('Starts in simulator mode. Verified Docker services can be selected in the dashboard.');
      if (seed !== null) console.log(`Demo seed ${seed}: clouds and Hacker choices repeat on every restart.`);
    });
    for (const signal of ['SIGINT', 'SIGTERM']) {
      process.once(signal, () => server.close());
    }
  }
}
