import type { IncomingMessage, ServerResponse } from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';

/**
 * Shared HTTP plumbing for the example-test-suite backend — the pieces every scenario family's handler
 * and the router reuse: the static-bundle server, JSON/text responders, and the request-body readers.
 * Nothing here is SDK-specific; the SDK calls live in the per-family handlers under src/handlers/.
 */

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.webp': 'image/webp',
};

export function sendJson(res: ServerResponse, data: unknown, status = 200): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

export function sendText(res: ServerResponse, body: string, status = 200): void {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
}

/** The raw request body bytes (webhook verify/parse need the exact bytes the HMAC was computed over). */
export async function readRawBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
}

/** Parse a JSON request body into a plain object ({} for empty/non-object/invalid bodies). */
export async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const raw = (await readRawBody(req)).toString('utf8');
  if (raw === '') return {};
  try {
    const decoded = JSON.parse(raw);
    return decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : {};
  } catch {
    return {};
  }
}

/** Serve a file from the pinned frontend bundle with a path-traversal guard + SPA fallback to index.html. */
export function serveStatic(frontendDir: string, path: string, res: ServerResponse): void {
  const root = resolve(frontendDir);
  const rel = path === '/' ? '/index.html' : path;
  const full = resolve(join(root, normalize(rel)));

  if ((full === root || full.startsWith(root + sep)) && existsSync(full) && statSync(full).isFile()) {
    res.writeHead(200, { 'Content-Type': MIME[extname(full).toLowerCase()] ?? 'application/octet-stream' });
    createReadStream(full).pipe(res);
    return;
  }
  const index = join(root, 'index.html');
  if (existsSync(index)) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    createReadStream(index).pipe(res);
    return;
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('bundle not found');
}

/** First value of a possibly-array header, or null. */
export function headerValue(v: string | string[] | undefined): string | null {
  if (v === undefined) return null;
  return Array.isArray(v) ? (v[0] ?? null) : v;
}

/** Coerce any config/body value to a string (missing → ''). */
export function str(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}
