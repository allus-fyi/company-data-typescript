import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { VERSION } from '@allus-fyi/company-data';

import { Runtime } from '../src/runtime.js';
import { Server, CONTRACT_VERSION } from '../src/server.js';

/**
 * One-command launcher for the flow example (`npm start`).
 *
 * Steps:
 *   1. wipe .runtime/ (fresh state each boot)
 *   2. on a missing/unverified bundle: fetch the pinned frontend release (frontend.lock), VERIFY sha256,
 *      unpack to .frontend/<tag>/  (a present, verified bundle is a cache hit — nothing is re-fetched)
 *   3. assert the bundle's contract.json version == the backend's implemented CONTRACT_VERSION
 *   4. refuse a busy port with a clear message
 *   5. serve bundle + API on ONE port — SINGLE process = single worker
 */

const RELEASE_BASE = 'https://github.com/allme-sdk/example-test-suite/releases/download';
const base = dirname(dirname(fileURLToPath(import.meta.url))); // examples/flow
process.chdir(base);

async function main(): Promise<void> {
  log('flow example — starting up');

  // 1. fresh runtime state
  const rt = new Runtime(base);
  rt.wipeAll();

  // 2. frontend bundle (pinned release, checksum-verified, TAG-specific cache)
  const lock = readJson(join(base, 'frontend.lock'));
  if (!lock || typeof lock.tag !== 'string' || typeof lock.sha256 !== 'string') {
    fail('frontend.lock missing or malformed (need {"tag","sha256"}).');
  }
  const tag = lock.tag as string;
  const wantSha = (lock.sha256 as string).toLowerCase();
  const frontend = join(base, '.frontend', tag); // per-tag cache dir — a pin bump serves a NEW dir

  const markSha = safeRead(join(frontend, '.sha')).trim().toLowerCase();
  const cacheValid =
    existsSync(join(frontend, 'index.html')) &&
    existsSync(join(frontend, 'contract.json')) &&
    markSha !== '' &&
    markSha === wantSha;
  if (cacheValid) {
    log(`frontend ${tag} present + checksum-verified (cache hit) — skipping fetch`);
  } else {
    await fetchBundle(frontend, tag, wantSha);
  }

  // 3. contract guard
  const bundleContract = readJson(join(frontend, 'contract.json'));
  const bundleVersion = bundleContract ? bundleContract.contractVersion : null;
  if (Number(bundleVersion) !== CONTRACT_VERSION) {
    fail(
      `contract mismatch: bundle contractVersion=${JSON.stringify(bundleVersion)}, backend implements ${CONTRACT_VERSION}.\n` +
        'Bump the frontend.lock pin to a release whose contract.json matches, or update the backend.',
    );
  }

  // 4 + 5. serve — SINGLE process
  const port = Number(process.env.PORT ?? 8091);
  const server = new Server(rt, frontend, VERSION, port);
  const http = createServer((req, res) => {
    server.handle(req, res).catch((e) => {
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'server_error', message: (e as Error).message }));
    });
  });

  http.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code === 'EADDRINUSE') {
      fail(
        `port ${port} is busy. Set PORT=<n> to use another port ` +
          '(one browser origin is shared across SDK examples, so only one runs at a time).',
      );
    }
    fail(`server error: ${e.message}`);
  });

  http.listen(port, 'localhost', () => {
    log(`serving http://localhost:${port}  (Ctrl-C to stop)`);
  });
}

async function fetchBundle(frontend: string, tag: string, wantSha: string): Promise<void> {
  const url = `${RELEASE_BASE}/${encodeURIComponent(tag)}/dist.tar.gz`;
  log(`fetching frontend ${tag} → ${url}`);
  const tmp = join(base, '.frontend.download.tar.gz');
  rmSync(tmp, { force: true });

  let bytes: Buffer;
  try {
    const resp = await fetch(url, { redirect: 'follow' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    bytes = Buffer.from(await resp.arrayBuffer());
  } catch (e) {
    fail(
      `could not download the pinned frontend release (${url}): ${(e as Error).message}\n` +
        'If the release does not exist yet, seed it manually: build the frontend, then\n' +
        `  mkdir -p ${frontend} && tar -xzf dist.tar.gz -C ${frontend}\n` +
        `  printf %s ${wantSha} > ${join(frontend, '.sha')}   # the recorded checksum makes it a verified cache-hit`,
    );
  }
  writeFileSync(tmp, bytes!);

  const gotSha = createHash('sha256').update(bytes!).digest('hex').toLowerCase();
  if (gotSha !== wantSha) {
    rmSync(tmp, { force: true });
    fail(
      `frontend checksum MISMATCH.\n  expected ${wantSha}\n  got      ${gotSha}\n` +
        'Refusing to serve an unverified bundle. Fix frontend.lock or re-download.',
    );
  }

  rmSync(frontend, { recursive: true, force: true });
  mkdirSync(frontend, { recursive: true });
  try {
    execFileSync('tar', ['-xzf', tmp, '-C', frontend]);
  } catch (e) {
    fail(`failed to unpack the frontend bundle: ${(e as Error).message}`);
  }
  rmSync(tmp, { force: true });
  if (!existsSync(join(frontend, 'index.html'))) fail('failed to unpack the frontend bundle (no index.html).');

  // Record the verified checksum so the next start recognises THIS tag/sha as a valid cache-hit.
  writeFileSync(join(frontend, '.sha'), wantSha);
  log(`frontend ${tag} verified + unpacked → ${frontend}`);
}

// ── helpers ────────────────────────────────────────────────────────────────

function readJson(path: string): Record<string, unknown> | null {
  try {
    const decoded = JSON.parse(readFileSync(path, 'utf8'));
    return decoded && typeof decoded === 'object' ? decoded : null;
  } catch {
    return null;
  }
}

function safeRead(path: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return '';
  }
}

function log(msg: string): void {
  process.stderr.write(msg + '\n');
}

function fail(msg: string): never {
  process.stderr.write(`\nERROR: ${msg}\n`);
  process.exit(1);
}

main().catch((e) => fail((e as Error).stack ?? (e as Error).message));
