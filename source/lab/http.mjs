import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';

/** Small JSON HTTP boundary shared only by the container-only lab processes. */
export const MAX_BODY = 16 * 1024;
export function tokenMatches(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string' || expected.length < 16) return false;
  const a = Buffer.from(actual), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
export function authorized(headers, token) {
  return tokenMatches(headers.authorization, `Bearer ${token}`) && token?.length >= 16;
}
// This checks allowed keys, not required fields; each handler validates values.
export function strictObject(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key));
}
export async function readJson(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] || '')) throw new Error('JSON content type required.');
  let size = 0; const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error('Request too large.');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
// Adapt injectable service handlers to real HTTP while keeping errors generic.
// Tests can call the same handlers directly without opening network sockets.
export function createJsonServer(handler) {
  const server = http.createServer(async (req, res) => {
    try {
      const body = req.method === 'POST' ? await readJson(req) : {};
      const result = await handler({method:req.method, path:req.url, headers:req.headers, body});
      const bytes = JSON.stringify(result.body);
      res.writeHead(result.status, {'Content-Type':'application/json', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff'});
      res.end(bytes);
    } catch {
      if (!res.destroyed) { res.writeHead(400, {'Content-Type':'application/json'}); res.end(JSON.stringify({error:'Invalid lab request.'})); }
    }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  return server;
}

const SERVICES = new Set(['gateway','lb','app','storage','iam','db']);
const PATHS = new Set(['/health','/data/db','/data/storage','/objects','/objects/demo-customers','/login','/session','/admin','/export','/records','/control/policy','/control/reset','/control/node']);

/** No hostname, URL, redirect or free-form route is accepted from an agent. */
export function createLabTransport({fetchImpl=fetch}={}) {
  return async (service, {method='GET', path, headers={}, body, signal}={}) => {
    if (!SERVICES.has(service) || !PATHS.has(path) || !['GET','POST'].includes(method)) throw new Error('Target or operation is outside the lab catalog.');
    const deadline = AbortSignal.timeout(1200);
    const response = await fetchImpl(`http://${service}:8080${path}`, {
      method, redirect:'error', signal:signal ? AbortSignal.any([signal,deadline]) : deadline,
      headers:{...headers, ...(body === undefined ? {} : {'Content-Type':'application/json'})},
      ...(body === undefined ? {} : {body:JSON.stringify(body)})
    });
    // Bounded response consumption protects the controller even if a target misbehaves.
    const reader = response.body?.getReader();
    let size=0; const parts=[];
    if (reader) while (true) {
      const {value,done} = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > 256*1024) { await reader.cancel(); throw new Error('Lab response exceeded its limit.'); }
      parts.push(value);
    }
    const data = JSON.parse(Buffer.concat(parts).toString('utf8'));
    return {status:response.status,body:data};
  };
}

// Startup guard only. Actual isolation comes from Compose plus live verification,
// not from trusting this environment variable as a security boundary.
export function requireContainer() {
  if (process.env.VORTEX_CONTAINER !== '1') throw new Error('Real lab services must run through the isolated Docker Compose environment.');
}
