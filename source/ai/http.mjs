import { timingSafeEqual } from 'node:crypto';

export function authorized(request, token) {
  if (typeof token !== 'string' || token.length < 24) return false;
  const supplied = Buffer.from(request.headers.authorization || '');
  const expected = Buffer.from(`Bearer ${token}`);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export function send(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  response.end(JSON.stringify(body));
}

export async function readBody(request, allowedKeys, limit = 32768) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] || '')) throw new Error('JSON required.');
  let size = 0; const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) throw new Error('Request exceeds limit.');
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !allowedKeys.includes(k))) throw new Error('Invalid request.');
  return value;
}
