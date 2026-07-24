import type { IncomingMessage, ServerResponse } from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';

import {
  ApiError,
  Client,
  Config,
  Connection,
  DEFAULT_AUTHORIZE_URL,
  OAuthClient,
  type Claim,
  type OAuthClientOptions,
} from '@allus-fyi/company-data';
import * as oidc from 'openid-client';

import { generatePkce } from './pkce.js';
import { Runtime, type RunRecord } from './runtime.js';
import { TimeoutTransport } from './timeoutTransport.js';

/**
 * The demo-backend contract (v1). One class, one worker (Node's built-in http): HTTP dispatch →
 * handler → the SDK's intended top-level surface (or the openid-client library for scenarios 5/6).
 * Handlers NEVER perform raw platform HTTP and NEVER block on SDK defaults — detached / challenge waits
 * are short-cycled (timeout=2) inside GET /api/runs.
 *
 * Settings flow (config-file model): the browser POSTs a scenario's setup values to
 * POST /api/scenarios/{id}/config, which writes them to a canonical SDK config FILE
 * (.runtime/config/{id}.json). /start and /enroll then build the SDK from that file via the
 * role-appropriate file constructor (OAuthClient.fromConfig → Config.fromIdwFile; Client.fromConfig →
 * Config.fromFile) and run OFF the config — exactly as a real integrator wires the SDK. The request body
 * of /start is ignored; a /start with no saved config → 409 not_configured.
 */

export const CONTRACT_VERSION = 1;
export const SDK = 'typescript';

/** id => kind. Scenario 7 is the guide card (no /start). */
const SCENARIOS: Record<number, 'runnable' | 'guide'> = {
  1: 'runnable',
  2: 'runnable',
  3: 'runnable',
  4: 'runnable',
  5: 'runnable',
  6: 'runnable',
  7: 'guide',
  8: 'runnable',
};

/** Scenarios that also read live values through the service data {@link Client} (service-role keys). */
const SERVICE_SCENARIOS = new Set([4, 8]);
/** Scenarios that build an OAuth consent URL via {@link OAuthClient} (need the authorize base). */
const OAUTH_URL_SCENARIOS = new Set([1, 2, 3, 4, 8]);

const DEFAULT_API_URL = 'https://api.allme.fyi';
const DEFAULT_AUTHORIZE_BASE = DEFAULT_AUTHORIZE_URL; // https://web.allme.fyi/auth

/** Short-cycled poll timeout (ms) for the detached/challenge waits — bounds one worker per poll. */
const POLL_TIMEOUT_MS = 2000;

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

export class Server {
  constructor(
    private readonly rt: Runtime,
    private readonly frontendDir: string,
    private readonly sdkVersion: string,
    private readonly port: number,
  ) {}

  // ── entry point ────────────────────────────────────────────────────────

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    this.rt.ensureDirs();
    this.rt.sweep(); // lazy TTL sweep on every request

    const method = req.method ?? 'GET';
    const host = String(req.headers.host ?? `localhost:${this.port}`);
    const url = new URL(req.url ?? '/', `http://${host}`);
    const path = decodeURIComponent(url.pathname);

    try {
      let m: RegExpMatchArray | null;
      if (path === '/api/meta' && method === 'GET') {
        this.meta(res);
      } else if (path === '/callback' && method === 'GET') {
        await this.callback(url, host, res);
      } else if (path === '/api/clear' && method === 'POST') {
        this.rt.clearAll();
        this.json(res, { ok: true });
      } else if ((m = path.match(/^\/api\/scenarios\/(\d+)\/config$/)) && method === 'POST') {
        await this.config(Number(m[1]), host, req, res);
      } else if ((m = path.match(/^\/api\/scenarios\/(\d+)\/start$/)) && method === 'POST') {
        await this.start(Number(m[1]), host, res);
      } else if ((m = path.match(/^\/api\/scenarios\/(\d+)\/enroll$/)) && method === 'POST') {
        await this.enroll(Number(m[1]), req, res);
      } else if ((m = path.match(/^\/api\/scenarios\/(\d+)\/clear$/)) && method === 'POST') {
        this.rt.clearScenario(Number(m[1]));
        this.json(res, { ok: true });
      } else if ((m = path.match(/^\/api\/runs\/([0-9a-f]{32})$/)) && method === 'GET') {
        await this.run(m[1], host, res);
      } else if (path.startsWith('/api/')) {
        this.json(res, { error: 'not_found' }, 404);
      } else {
        this.serveStatic(path, res);
      }
    } catch (e) {
      this.json(res, { error: 'server_error', message: (e as Error).message }, 500);
    }
  }

  // ── GET /api/meta ──────────────────────────────────────────────────────

  private meta(res: ServerResponse): void {
    const scenarios = Object.entries(SCENARIOS).map(([id, kind]) => ({ id: Number(id), kind }));
    this.json(res, { sdk: SDK, sdkVersion: this.sdkVersion, contractVersion: CONTRACT_VERSION, scenarios });
  }

  // ── POST /api/scenarios/{id}/config ─────────────────────────────────────

  private async config(id: number, host: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (SCENARIOS[id] !== 'runnable') return this.json(res, { error: 'not_found' }, 404);
    const in_ = await this.body(req);

    // Canonical SDK config — the idw role for every OAuth scenario (sdk.html §12c).
    const cfg: Record<string, unknown> = {
      api_url: (str(in_.apiUrl) || DEFAULT_API_URL).replace(/\/+$/, ''),
      oauth_client_id: str(in_.oauthClientId),
      oauth_redirect_uri: this.redirectUri(host),
    };
    const secret = str(in_.oauthClientSecret);
    if (secret !== '') cfg.oauth_client_secret = secret;

    // Scenario 3 (one_time): the OAuth app private key decrypts the claim values (config-only keys).
    if (id === 3) {
      const pem = str(in_.oauthPrivateKeyPem);
      if (pem !== '') cfg.oauth_private_key = this.rt.materializeConfigKey(pem);
      const pass = str(in_.oauthKeyPassphrase);
      if (pass !== '') cfg.oauth_key_passphrase = pass;
    }

    // Scenarios 4/8 also read live values via the service data Client — add the service-role keys to
    // the SAME file (role only decides which fields are REQUIRED; Config loads whatever is present).
    if (SERVICE_SCENARIOS.has(id)) {
      cfg.client_id = str(in_.clientId);
      cfg.client_secret = str(in_.clientSecret);
      const sPem = str(in_.servicePrivateKeyPem);
      if (sPem !== '') cfg.service_private_key = this.rt.materializeConfigKey(sPem);
      cfg.key_passphrase = str(in_.keyPassphrase);
    }

    const configPath = this.rt.writeConfig(id, cfg);

    // Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
    const meta: Record<string, unknown> = {};
    if (OAUTH_URL_SCENARIOS.has(id)) {
      meta.authorize_base = str(in_.authorizeBase) || DEFAULT_AUTHORIZE_BASE;
    }
    if (id === 3) meta.claims = this.claims(in_);
    if (id === 8) {
      meta.share_code = str(in_.shareCode);
      if (str(in_.context) !== '') meta.context = str(in_.context);
    }
    this.rt.writeConfigMeta(id, meta);

    this.json(res, { ok: true, configPath });
  }

  // ── POST /api/scenarios/{id}/start ──────────────────────────────────────

  private async start(id: number, host: string, res: ServerResponse): Promise<void> {
    if (SCENARIOS[id] !== 'runnable') return this.json(res, { error: 'not_found' }, 404);
    if (!this.rt.hasConfig(id)) return this.json(res, { error: 'not_configured' }, 409); // built from the file

    const runId = this.rt.newRunId();
    const run: RunRecord = { scenario: id, status: 'pending', state: runId, calls: [] };

    switch (id) {
      case 1: // Sign in — redirect
      case 3: // One-time claims
      case 4: {
        // Connect (stay-connected)
        const pkce = generatePkce();
        run.verifier = pkce.verifier;
        const mode = id === 1 ? 'signin' : id === 3 ? 'one_time' : 'connect';
        const claims: Claim[] = id === 3 ? this.claimObjects((this.rt.readConfigMeta(id).claims as string[]) ?? []) : [];
        const oauth = this.oauthClientFor(id);
        // redirectUri omitted → the OAuthClient uses its config's oauth_redirect_uri.
        const url = oauth.authorizeUrl(mode, { claims, state: runId, responseMode: 'redirect', codeChallenge: pkce.challenge });
        run.calls = ['OAuthClient.authorizeUrl'];
        this.rt.writeRun(runId, run);
        return this.json(res, { runId, action: { type: 'redirect', url } });
      }

      case 2: {
        // Sign in — detached
        const pkce = generatePkce();
        run.verifier = pkce.verifier;
        run.wait = 'detached_signin';
        const oauth = this.oauthClientFor(id);
        const url = oauth.authorizeUrl('signin', { state: runId, responseMode: 'detached', codeChallenge: pkce.challenge });
        run.calls = ['OAuthClient.authorizeUrl'];
        this.rt.writeRun(runId, run);
        return this.json(res, { runId, action: { type: 'detached', url } });
      }

      case 5: // OIDC login
      case 6: {
        // OIDC — continue on your phone (#431)
        const config = await this.oidcConfigFor(id, host);
        const verifier = oidc.randomPKCECodeVerifier();
        const challenge = await oidc.calculatePKCECodeChallenge(verifier);
        const nonce = oidc.randomNonce();
        run.verifier = verifier;
        run.nonce = nonce;
        const url = oidc.buildAuthorizationUrl(config, {
          redirect_uri: this.configRedirectUri(id, host),
          scope: 'openid profile email',
          state: runId,
          nonce,
          code_challenge: challenge,
          code_challenge_method: 'S256',
        });
        run.calls = ['(oidc) discovery', '(oidc) buildAuthorizationUrl'];
        this.rt.writeRun(runId, run);
        return this.json(res, { runId, action: { type: 'redirect', url: url.href } });
      }

      case 8: {
        // Standalone service-2FA — the challenge step
        const meta = this.rt.readConfigMeta(id);
        const shareCode = str(meta.share_code);
        const context = str(meta.context) !== '' ? str(meta.context) : null;
        const idempotencyKey = `demo-${runId}`.slice(0, 64); // backend-generated, per-run (SDK requires it)
        run.wait = 'challenge';
        const client = this.serviceClientFor(id);
        const challenge = await client.twoFactor.challenge(shareCode, { context, idempotencyKey });
        run.challengeId = challenge.challengeId;
        run.calls = ['Client.twoFactor', 'TwoFactorClient.challenge'];
        this.rt.writeRun(runId, run);
        return this.json(res, { runId, action: { type: 'challenge', matchingDigits: challenge.matchingDigits } });
      }
    }
  }

  // ── POST /api/scenarios/{id}/enroll (scenario 8) ────────────────────────

  private async enroll(id: number, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (id !== 8) return this.json(res, { error: 'not_found' }, 404);
    if (!this.rt.hasConfig(id)) return this.json(res, { error: 'not_configured' }, 409);

    const in_ = await this.body(req);
    const responseMode = in_.responseMode === 'detached' ? 'detached' : 'redirect';
    const runId = this.rt.newRunId();

    const oauth = this.oauthClientFor(id);
    const url = oauth.authorizeUrl('2fa_enroll', { state: runId, responseMode });

    const run: RunRecord = {
      scenario: 8,
      isEnroll: true,
      status: 'pending',
      state: runId,
      calls: ['OAuthClient.authorizeUrl'],
      wait: responseMode === 'detached' ? 'detached_enroll' : 'enroll_redirect',
    };
    this.rt.writeRun(runId, run);

    const action = responseMode === 'detached' ? { type: 'detached', url } : { type: 'redirect', url };
    this.json(res, { runId, action });
  }

  // ── GET /callback ───────────────────────────────────────────────────────

  private async callback(url: URL, host: string, res: ServerResponse): Promise<void> {
    const state = url.searchParams.get('state') ?? '';
    const run = this.rt.readRun(state);
    if (run === null) {
      res.writeHead(302, { Location: '/?error=unknown_run' });
      res.end();
      return;
    }
    const id = Number(run.scenario ?? 0);

    try {
      if (url.searchParams.get('enrolled') === 'true') {
        // Redirect-leg enrollment outcome (#436) — nothing to exchange; record it.
        run.status = 'done';
        run.result = { enrolled: true };
        (run.calls as string[]).push('callback(enrolled=true)');
      } else if (url.searchParams.get('code')) {
        const code = url.searchParams.get('code')!;
        if (id === 5 || id === 6) {
          await this.completeOidc(run, url, host);
        } else {
          await this.completeSignin(run, code, id);
        }
      } else {
        run.status = 'failed';
        run.error = 'callback missing code / enrolled';
      }
    } catch (e) {
      run.status = 'failed';
      run.error = (e as Error).message;
    }

    this.rt.writeRun(state, run);
    res.writeHead(302, { Location: `/?scenario=${id}&run=${encodeURIComponent(state)}` });
    res.end();
  }

  // ── GET /api/runs/{runId} ────────────────────────────────────────────────

  private async run(runId: string, host: string, res: ServerResponse): Promise<void> {
    let run = this.rt.readRun(runId);
    if (run === null) return this.json(res, { error: 'not_found' }, 404);

    // Idempotent: a terminal outcome is returned on every poll until TTL/Clear.
    if ((run.status ?? 'pending') === 'pending') {
      run = await this.advance(run, host);
      this.rt.writeRun(runId, run);
    }

    const out: Record<string, unknown> = { status: run.status ?? 'pending', calls: run.calls ?? [] };
    if (run.result !== undefined) out.result = run.result;
    if (run.error !== undefined) out.error = run.error;
    this.json(res, out);
  }

  /**
   * Short-cycled advance for a pending run awaiting a detached / challenge outcome. ONE SDK wait with
   * timeout=2 per poll; an SDK logical timeout is treated as still-pending. Clients are rebuilt from the
   * run's scenario config file — the run stores no credentials.
   */
  private async advance(run: RunRecord, host: string): Promise<RunRecord> {
    const wait = run.wait as string | undefined;
    const id = Number(run.scenario ?? 0);
    const calls = run.calls as string[];
    try {
      if (wait === 'detached_signin') {
        const oauth = this.oauthClientFor(id, POLL_TIMEOUT_MS);
        const body = await oauth.pollResult(String(run.state), { timeout: 2, interval: 2 });
        calls.push('OAuthClient.pollResult');
        const code = str(body.code);
        if (code !== '') await this.completeSignin(run, code, id);
      } else if (wait === 'detached_enroll') {
        const oauth = this.oauthClientFor(id, POLL_TIMEOUT_MS);
        const body = await oauth.pollResult(String(run.state), { timeout: 2, interval: 2 });
        calls.push('OAuthClient.pollResult');
        if (body.enrolled) {
          run.status = 'done';
          run.result = { enrolled: true };
        }
      } else if (wait === 'challenge') {
        const client = this.serviceClientFor(id, POLL_TIMEOUT_MS);
        const r = await client.twoFactor.waitForResult(String(run.challengeId), { timeout: 2, interval: 2 });
        calls.push('TwoFactorClient.waitForResult');
        run.status = 'done';
        run.result = { status: r.status, completed_at: r.completedAt };
      }
      // else (redirect / continue-on-phone flows): completion arrives via /callback — stay pending.
    } catch (e) {
      // The SDK poll helpers signal a LOGICAL "not completed within Ns" timeout as ApiError(0) with that
      // exact sentinel message. A real transport failure surfaces differently (an aborted fetch, or a
      // non-sentinel ApiError) → a failed run. Only the logical timeout is "still pending".
      if (e instanceof ApiError && e.status === 0 && e.message.includes('not completed within')) {
        return run; // logical short-cycle timeout → still pending
      }
      run.status = 'failed';
      run.error = (e as Error).message;
    }
    return run;
  }

  // ── SDK / OIDC completion helpers ────────────────────────────────────────

  /**
   * Complete a redirect / detached SIGN-IN (scenarios 1, 2, 3, 4): exchange + read identity via
   * completeSignIn, and for connect read the person's LIVE values via the service data client.
   */
  private async completeSignin(run: RunRecord, code: string, id: number): Promise<void> {
    const oauth = this.oauthClientFor(id);
    const out = await oauth.completeSignIn(code, run.verifier ? String(run.verifier) : undefined);
    (run.calls as string[]).push('OAuthClient.completeSignIn');
    const result: Record<string, unknown> = {
      user: out.user ?? null,
      mode: out.mode ?? null,
      two_factor: out.two_factor ?? false,
      values: out.values ?? {},
    };

    if (id === 4) {
      // Connect: read the person's LIVE values via the service data client.
      const shareCode = str(out.user?.share_code);
      const client = this.serviceClientFor(id);
      let live: Record<string, unknown> = {};
      for await (const conn of client.connections()) {
        if (shareCode !== '' && conn.shareCode === shareCode) {
          live = this.plainValues(conn);
          break;
        }
      }
      (run.calls as string[]).push('Client.connections');
      result.live_values = live;
    }

    run.status = 'done';
    run.result = result;
  }

  /** Complete an OIDC sign-in (scenarios 5/6) via the openid-client library — id_token verified. */
  private async completeOidc(run: RunRecord, currentUrl: URL, host: string): Promise<void> {
    const id = Number(run.scenario ?? 0);
    const config = await this.oidcConfigFor(id, host);
    const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: String(run.verifier ?? ''),
      expectedNonce: String(run.nonce ?? ''),
      expectedState: String(run.state ?? ''),
    });
    (run.calls as string[]).push('(oidc) discovery', '(oidc) authorizationCodeGrant');
    run.status = 'done';
    run.result = { claims: tokens.claims() ?? null };
  }

  // ── SDK / OIDC client builders — built from the persisted config FILE ─────

  /**
   * Build the OAuth client OFF the scenario's config file via the idw file constructor. The named
   * OAuthClient.fromConfig() is used for the default (deployed) authorize base; a non-default base
   * (local-stack option) still loads Config from the file via Config.fromIdwFile, only supplying the
   * alternate base the wrapper cannot set. `pollTimeoutMs` bounds the HTTP network wait for the
   * short-cycled polls so one blackholed request cannot pin the single worker.
   */
  private oauthClientFor(id: number, pollTimeoutMs?: number): OAuthClient {
    const path = this.rt.configPathFor(id);
    const base = str(this.rt.readConfigMeta(id).authorize_base);
    const opts: OAuthClientOptions = {};
    if (pollTimeoutMs !== undefined) opts.transport = new TimeoutTransport(pollTimeoutMs);
    if (base === '' || base === DEFAULT_AUTHORIZE_URL) {
      return OAuthClient.fromConfig(path, opts);
    }
    opts.authorizeUrl = base;
    return new OAuthClient(Config.fromIdwFile(path), opts);
  }

  /** Build the service data client OFF the scenario's config file (service role). */
  private serviceClientFor(id: number, pollTimeoutMs?: number): Client {
    const path = this.rt.configPathFor(id);
    if (pollTimeoutMs === undefined) return Client.fromConfig(path);
    return Client.fromConfig(path, { httpOptions: { transport: new TimeoutTransport(pollTimeoutMs) } });
  }

  /**
   * Build the openid-client Configuration (the #314 compliance surface) from the config file, sessionless.
   * Discovery is driven off the configured api base (issuer override); http bases enable insecure requests
   * for the local stack. Auth uses client_secret_post — the token endpoint's method.
   */
  private async oidcConfigFor(id: number, host: string): Promise<oidc.Configuration> {
    const cfg = this.rt.readConfig(id);
    const server = new URL(str(cfg.api_url) || DEFAULT_API_URL);
    const options: oidc.DiscoveryRequestOptions = {};
    if (server.protocol === 'http:') options.execute = [oidc.allowInsecureRequests];
    return oidc.discovery(
      server,
      str(cfg.oauth_client_id),
      { redirect_uris: [this.configRedirectUri(id, host)], response_types: ['code'] },
      oidc.ClientSecretPost(str(cfg.oauth_client_secret)),
      options,
    );
  }

  /** The redirect URI recorded in the scenario's config file (used by the OIDC library). */
  private configRedirectUri(id: number, host: string): string {
    return str(this.rt.readConfig(id).oauth_redirect_uri) || this.redirectUri(host);
  }

  // ── input / config plumbing ──────────────────────────────────────────────

  /** The registered redirect URI: http://{host}/callback (host = the serving origin). */
  private redirectUri(host: string): string {
    return `http://${host}/callback`;
  }

  private claims(in_: Record<string, unknown>): string[] {
    const raw = in_.claims;
    if (Array.isArray(raw) && raw.length > 0) return raw.map((c) => String(c));
    return ['email', 'phone']; // a small default claim set (spec §4 scenario 3)
  }

  private claimObjects(types: string[]): Claim[] {
    return types.map((t) => ({ type: t }));
  }

  /** Map a Connection's typed values to a plain {slug: value} object for the result payload. */
  private plainValues(conn: Connection): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [slug, v] of Object.entries(conn.values)) out[slug] = v.value;
    return out;
  }

  // ── HTTP plumbing ─────────────────────────────────────────────────────────

  private async body(req: IncomingMessage): Promise<Record<string, unknown>> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString('utf8');
    if (raw === '') return {};
    try {
      const decoded = JSON.parse(raw);
      return decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : {};
    } catch {
      return {};
    }
  }

  private json(res: ServerResponse, data: unknown, status = 200): void {
    const body = JSON.stringify(data);
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(body);
  }

  private serveStatic(path: string, res: ServerResponse): void {
    const root = resolve(this.frontendDir);
    const rel = path === '/' ? '/index.html' : path;
    const full = resolve(join(root, normalize(rel)));

    // Path-traversal guard + SPA fallback to index.html.
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
}

/** Coerce any config/body value to a trimmed-ish string (missing → ''). */
function str(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}
