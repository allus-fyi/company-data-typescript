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

/**
 * The contract's FAILURE envelope: `{"error": "<token> — <reason>", "message": "<reason>"}`.
 *
 * The consuming client is documented to raise `body.error` VERBATIM and ignore every other key,
 * so a bare token in `error` reaches the developer as one uninformative word and the REASON —
 * which the backend has right there — is dropped. That is the swallowed failure of standards.html
 * §9: a failure converted into something indistinguishable from any other failure. The token is
 * kept and the reason appended in the shape this contract already uses for exactly this
 * (`no_origin — …`); `message` keeps the bare reason for a programmatic reader.
 *
 * `reason` may be a thrown value or a sentence. A thrown non-Error (or an `Error` with an empty
 * message) would otherwise report nothing at all, so it is stringified rather than dropped.
 *
 * NOT used for the token-only refusals the suite handles by STATUS rather than body — `409
 * not_configured` (mapped from the status before the body is read) and `404 not_found`.
 *
 * A failure raised AFTER the first byte is on the wire cannot be re-answered by anyone (a static file
 * is streamed, so this is reachable), and `writeHead` would itself throw there. It is reported on
 * stderr instead of being swallowed — standards §9's "emit a distinguishable marker" for the one path
 * where the envelope is no longer available. Handling it HERE keeps one implementation for every
 * caller, including the launcher's last-resort guard (standards §1).
 */
export function sendFailure(res: ServerResponse, reason: unknown, token = 'server_error', status = 500): void {
  let text = (reason instanceof Error ? reason.message : String(reason)).trim();
  if (!text && reason instanceof Error) text = reason.name;
  const shown = text || 'no reason was reported';
  if (res.headersSent) {
    process.stderr.write(`example-suite ${token}: ${shown} (response already started — cannot answer)\n`);
    res.end();
    return;
  }
  sendJson(res, { error: `${token} — ${shown}`, message: text }, status);
}

/**
 * Serve a JSON document that is already encoded, byte for byte — the stored setup snapshot. The bytes
 * are passed through as they are because parsing and re-serialising them here, or decoding them to a
 * string and back, would rewrite content this server is not allowed to interpret.
 */
export function sendRawJson(res: ServerResponse, blob: Buffer, status = 200): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(blob);
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
