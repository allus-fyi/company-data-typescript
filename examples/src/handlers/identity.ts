import type { ServerResponse } from 'node:http';

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

import { generatePkce } from '../pkce.js';
import { Runtime, addCall, type RunRecord } from '../runtime.js';
import { TimeoutTransport } from '../timeoutTransport.js';
import { sendJson, str } from '../http.js';

/**
 * The IDENTITY scenario family (ids 1–5, 7–8). Every handler here reaches the SDK's intended top-level
 * surface — OAuthClient (authorizeUrl / completeSignIn / pollResult), the service data Client (connections /
 * twoFactor), or the openid-client library for the OIDC scenario (5) — so a reader sees exactly which
 * call implements each flow. The scaffolding (routing, config files, run store, static bundle) lives in
 * src/; this file is the identity example.
 *
 * Settings flow (config-file model): the browser POSTs a scenario's setup values to
 * POST /api/scenarios/{id}/config, which writes them to a canonical SDK config FILE
 * (.runtime/config/{id}.json). /start and /enroll then build the SDK from that file via the
 * role-appropriate file constructor (OAuthClient.fromConfig → Config.fromIdwFile; Client.fromConfig →
 * Config.fromFile) and run OFF the config. The request body of /start is ignored; a /start with no saved
 * config → 409 not_configured.
 */

/** id => kind. Scenario 7 is the guide card (no /start). */
const SCENARIOS: Record<number, 'runnable' | 'guide'> = {
  1: 'runnable',
  2: 'runnable',
  3: 'runnable',
  4: 'runnable',
  5: 'runnable',
  7: 'guide',
  8: 'runnable',
};

/** Scenarios that also read live values through the service data {@link Client} (service-role keys). */
const SERVICE_SCENARIOS = new Set([4, 8]);
/**
 * Scenarios whose {@link OAuthClient.completeSignIn} response can carry claim values (userinfo `values`
 * non-empty) and therefore need the OAuth app private key configured to decrypt them: mode one_time and
 * mode connect, both delivered as app-key ciphertext through userinfo. Mode signin (scenarios 1, 2) never
 * carries values; scenario 8 never calls this leg at all; scenario 5 runs the openid-client library
 * instead of this SDK's decrypt path.
 */
const CLAIM_VALUE_SCENARIOS = new Set([3, 4]);
/** Scenarios that build an OAuth consent URL via {@link OAuthClient} (need the authorize base). */
const OAUTH_URL_SCENARIOS = new Set([1, 2, 3, 4, 8]);

const DEFAULT_API_URL = 'https://api.allme.fyi';
const DEFAULT_AUTHORIZE_BASE = DEFAULT_AUTHORIZE_URL; // https://web.allme.fyi/auth

/** Short-cycled poll timeout (ms) for the detached/challenge waits — bounds one worker per poll. */
const POLL_TIMEOUT_MS = 2000;

/**
 * Refusal when the request carries no Host header, so the browser's origin is unknown. There is NO
 * default host: substituting one (localhost) silently sends the round-trip to a DIFFERENT origin than the
 * browser is on — a different localStorage and a redirect URI the OAuth app never registered.
 */
const NO_ORIGIN =
  'no_origin — this request carried no Host header, so the OAuth redirect URI cannot be derived from ' +
  'the origin your browser is using. Open the example by its address (http://<host>:<port>/) and save ' +
  'the setup again.';

/**
 * The "what just happened" trace. Every entry is `<SDK method> — <what that call did in THIS
 * scenario>`, appended AT the call site, in the order the calls were made; an entry wrapped in
 * parentheses is a step that is deliberately NOT an SDK call. Keep them in step when this handler
 * changes: the panel is headed "What just happened", and a list that no longer matches the code is
 * worse than a short one.
 */
const CALL_IDW_BUILD =
  'OAuthClient.fromConfig — builds the RP client from the saved config file: client id, secret and the registered redirect URI';
const CALL_IDW_BUILD_LOCAL =
  'new OAuthClient(Config.fromIdwFile(…)) — builds the RP client from the saved config file: client id, secret and the registered redirect URI';
const CALL_AUTH_SIGNIN =
  'OAuthClient.authorizeUrl — the consent URL the person is sent to (mode signin, response_mode redirect, PKCE S256, state = this run id)';
const CALL_AUTH_SIGNIN_DETACHED =
  'OAuthClient.authorizeUrl — the sign-in URL behind the link + QR (mode signin, response_mode detached, PKCE S256, state = this run id)';
const CALL_AUTH_ONE_TIME =
  'OAuthClient.authorizeUrl — the consent URL the person is sent to (mode one_time, claims email + phone, PKCE S256, state = this run id)';
const CALL_AUTH_CONNECT =
  'OAuthClient.authorizeUrl — the consent URL the person is sent to (mode connect, PKCE S256, state = this run id)';
const CALL_AUTH_ENROLL =
  'OAuthClient.authorizeUrl — the enrollment URL the person is sent to (mode 2fa_enroll, response_mode redirect)';
const CALL_AUTH_ENROLL_DETACHED =
  'OAuthClient.authorizeUrl — the enrollment URL behind the link + QR (mode 2fa_enroll, response_mode detached)';
const CALL_POLL_SIGNIN =
  'OAuthClient.pollResult — polls POST /oauth2/result until the phone delivers the code (one 2s-bounded call per browser poll)';
const CALL_POLL_ENROLL =
  'OAuthClient.pollResult — polls POST /oauth2/result until the phone delivers {enrolled: true} (one 2s-bounded call per browser poll)';
const CALL_COMPLETE_SIGNIN =
  'OAuthClient.completeSignIn — exchanges the code + PKCE verifier at POST /oauth2/token, then reads GET /api/oauth/userinfo; mode signin returns the identity only, no claim values';
const CALL_COMPLETE_ONE_TIME =
  'OAuthClient.completeSignIn — exchanges the code + PKCE verifier at POST /oauth2/token, reads GET /api/oauth/userinfo, and decrypts every claim value with the OAuth app private key';
const CALL_COMPLETE_CONNECT =
  "OAuthClient.completeSignIn — exchanges the code + PKCE verifier at POST /oauth2/token, reads GET /api/oauth/userinfo, and decrypts the consented claim values with the OAuth app private key; the connection's live values still come separately from the data client below";
const CALL_ENROLLED_CALLBACK =
  '(callback ?enrolled=true) — the redirect-leg enrollment outcome; there is nothing to exchange, so no further SDK call';
const CALL_SERVICE_BUILD =
  'Client.fromConfig — builds the SERVICE-role data client from the saved config file: client credentials plus the service private key, decrypted with its passphrase';
const CALL_CONNECTIONS_LIVE =
  "Client.connections — pages GET /api/company-data/connections and decrypts each person's values with the service key; the run keeps the one whose share code just signed in";
const CALL_TWO_FACTOR = 'Client.twoFactor — the service-2FA sub-client, on the same data-client credentials';
const CALL_CHALLENGE =
  "TwoFactorClient.challenge — POST /api/service-2fa/challenges for the person's share code with a per-run idempotency key; returns the challenge id, plus matching digits when the service has number matching on";
const CALL_WAIT_RESULT =
  'TwoFactorClient.waitForResult — polls GET /api/service-2fa/challenges/{id} until the status leaves pending: approved, denied, expired or revoked (one 2s-bounded call per browser poll; the first terminal read burns the result)';
const CALL_OIDC_DISCOVERY =
  '(oidc) discovery — discovery: fetches /.well-known/openid-configuration from the configured API base';
const CALL_OIDC_AUTH_URL =
  '(oidc) buildAuthorizationUrl — the authorization URL (scope openid profile email, PKCE S256, nonce, state = this run id)';
const CALL_OIDC_COMPLETE =
  "(oidc) authorizationCodeGrant — exchanges the code at the discovered token endpoint (client_secret_post + PKCE verifier), then verifies the id_token against the JWKS: signature, issuer, audience and nonce; the claims shown are that verified token's";


export class IdentityHandler {
  constructor(private readonly rt: Runtime) {}

  /** The identity scenarios for GET /api/meta (ids 1–8, with 7 as the guide card). */
  scenarios(): { id: number; kind: string }[] {
    return Object.entries(SCENARIOS).map(([id, kind]) => ({ id: Number(id), kind }));
  }

  /** True when this family owns the scenario id (an integer id). */
  owns(id: string): boolean {
    return /^\d+$/.test(id) && SCENARIOS[Number(id)] !== undefined;
  }

  /** True when a stored run belongs to this family. */
  ownsRun(run: RunRecord): boolean {
    return /^\d+$/.test(String(run.scenario ?? ''));
  }

  // ── POST /api/scenarios/{id}/config ─────────────────────────────────────

  async config(idStr: string, host: string, in_: Record<string, unknown>, res: ServerResponse): Promise<void> {
    const id = Number(idStr);
    if (SCENARIOS[id] !== 'runnable') return sendJson(res, { error: 'not_found' }, 404);
    // The redirect URI is derived from THIS request's origin and from nothing else. Refuse rather
    // than invent a host: the suite renders this sentence on Save.
    if (host === '') return sendJson(res, { error: NO_ORIGIN }, 400);

    // Canonical SDK config — the idw role for every OAuth scenario (sdk.html §12c).
    const cfg: Record<string, unknown> = {
      api_url: (str(in_.apiUrl) || DEFAULT_API_URL).replace(/\/+$/, ''),
      oauth_client_id: str(in_.oauthClientId),
      oauth_redirect_uri: this.redirectUri(host),
    };
    const secret = str(in_.oauthClientSecret);
    if (secret !== '') cfg.oauth_client_secret = secret;

    // Any scenario whose run can carry claim values (CLAIM_VALUE_SCENARIOS) needs the OAuth app
    // private key to decrypt them (config-only keys).
    if (CLAIM_VALUE_SCENARIOS.has(id)) {
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

    const configPath = this.rt.writeConfig(idStr, cfg);

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
    this.rt.writeConfigMeta(idStr, meta);

    sendJson(res, { ok: true, configPath });
  }

  // ── POST /api/scenarios/{id}/start ──────────────────────────────────────

  async start(idStr: string, host: string, res: ServerResponse): Promise<void> {
    const id = Number(idStr);
    if (SCENARIOS[id] !== 'runnable') return sendJson(res, { error: 'not_found' }, 404);
    if (!this.rt.hasConfig(idStr)) return sendJson(res, { error: 'not_configured' }, 409); // built from the file

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
        const claims: Claim[] = id === 3 ? this.claimObjects((this.rt.readConfigMeta(idStr).claims as string[]) ?? []) : [];
        run.calls = [
          this.idwBuildCall(idStr),
          id === 3 ? CALL_AUTH_ONE_TIME : id === 4 ? CALL_AUTH_CONNECT : CALL_AUTH_SIGNIN,
        ];
        const oauth = this.oauthClientFor(idStr);
        // redirectUri omitted → the OAuthClient uses its config's oauth_redirect_uri.
        const url = oauth.authorizeUrl(mode, { claims, state: runId, responseMode: 'redirect', codeChallenge: pkce.challenge });
        this.rt.writeRun(runId, run);
        return sendJson(res, { runId, action: { type: 'redirect', url } });
      }

      case 2: {
        // Sign in — detached
        const pkce = generatePkce();
        run.verifier = pkce.verifier;
        run.wait = 'detached_signin';
        run.calls = [this.idwBuildCall(idStr), CALL_AUTH_SIGNIN_DETACHED];
        const oauth = this.oauthClientFor(idStr);
        const url = oauth.authorizeUrl('signin', { state: runId, responseMode: 'detached', codeChallenge: pkce.challenge });
        this.rt.writeRun(runId, run);
        return sendJson(res, { runId, action: { type: 'detached', url } });
      }

      case 5: {
        // OIDC login
        const config = await this.oidcConfigFor(idStr, host);
        const verifier = oidc.randomPKCECodeVerifier();
        const challenge = await oidc.calculatePKCECodeChallenge(verifier);
        const nonce = oidc.randomNonce();
        run.verifier = verifier;
        run.nonce = nonce;
        const url = oidc.buildAuthorizationUrl(config, {
          redirect_uri: this.configRedirectUri(idStr, host),
          scope: 'openid profile email',
          state: runId,
          nonce,
          code_challenge: challenge,
          code_challenge_method: 'S256',
        });
        run.calls = [CALL_OIDC_DISCOVERY, CALL_OIDC_AUTH_URL];
        this.rt.writeRun(runId, run);
        return sendJson(res, { runId, action: { type: 'redirect', url: url.href } });
      }

      case 8: {
        // Standalone service-2FA — the challenge step
        const meta = this.rt.readConfigMeta(idStr);
        const shareCode = str(meta.share_code);
        const context = str(meta.context) !== '' ? str(meta.context) : null;
        const idempotencyKey = `demo-${runId}`.slice(0, 64); // backend-generated, per-run (SDK requires it)
        run.wait = 'challenge';
        run.calls = [CALL_SERVICE_BUILD, CALL_TWO_FACTOR, CALL_CHALLENGE];
        const client = this.serviceClientFor(idStr);
        const challenge = await client.twoFactor.challenge(shareCode, { context, idempotencyKey });
        run.challengeId = challenge.challengeId;
        this.rt.writeRun(runId, run);
        return sendJson(res, { runId, action: { type: 'challenge', matchingDigits: challenge.matchingDigits } });
      }
    }
  }

  // ── POST /api/scenarios/{id}/enroll (scenario 8) ────────────────────────

  async enroll(idStr: string, in_: Record<string, unknown>, res: ServerResponse): Promise<void> {
    const id = Number(idStr);
    if (id !== 8) return sendJson(res, { error: 'not_found' }, 404);
    if (!this.rt.hasConfig(idStr)) return sendJson(res, { error: 'not_configured' }, 409);

    const responseMode = in_.responseMode === 'detached' ? 'detached' : 'redirect';
    const runId = this.rt.newRunId();

    const oauth = this.oauthClientFor(idStr);
    const url = oauth.authorizeUrl('2fa_enroll', { state: runId, responseMode });

    const run: RunRecord = {
      scenario: 8,
      isEnroll: true,
      status: 'pending',
      state: runId,
      calls: [this.idwBuildCall(idStr), responseMode === 'detached' ? CALL_AUTH_ENROLL_DETACHED : CALL_AUTH_ENROLL],
      wait: responseMode === 'detached' ? 'detached_enroll' : 'enroll_redirect',
    };
    this.rt.writeRun(runId, run);

    const action = responseMode === 'detached' ? { type: 'detached', url } : { type: 'redirect', url };
    sendJson(res, { runId, action });
  }

  // ── GET /callback ───────────────────────────────────────────────────────

  async callback(url: URL, host: string, res: ServerResponse): Promise<void> {
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
        // Redirect-leg enrollment outcome — nothing to exchange; record it.
        run.status = 'done';
        run.result = { enrolled: true };
        run.calls = addCall(run.calls, CALL_ENROLLED_CALLBACK);
      } else if (url.searchParams.get('code')) {
        const code = url.searchParams.get('code')!;
        if (id === 5) {
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

  async runRespond(runId: string, run: RunRecord, host: string, res: ServerResponse): Promise<void> {
    // Idempotent: a terminal outcome is returned on every poll until TTL/Clear.
    if ((run.status ?? 'pending') === 'pending') {
      run = await this.advance(run, host);
      this.rt.writeRun(runId, run);
    }

    const out: Record<string, unknown> = { status: run.status ?? 'pending', calls: run.calls ?? [] };
    if (run.result !== undefined) out.result = run.result;
    if (run.error !== undefined) out.error = run.error;
    sendJson(res, out);
  }

  /**
   * Short-cycled advance for a pending run awaiting a detached / challenge outcome. ONE SDK wait with
   * timeout=2 per poll; an SDK logical timeout is treated as still-pending. Clients are rebuilt from the
   * run's scenario config file — the run stores no credentials.
   */
  private async advance(run: RunRecord, host: string): Promise<RunRecord> {
    const wait = run.wait as string | undefined;
    const id = Number(run.scenario ?? 0);
    const idStr = String(id);
    try {
      if (wait === 'detached_signin') {
        run.calls = addCall(run.calls, CALL_POLL_SIGNIN);
        const oauth = this.oauthClientFor(idStr, POLL_TIMEOUT_MS);
        const body = await oauth.pollResult(String(run.state), { timeout: 2, interval: 2 });
        const code = str(body.code);
        if (code !== '') await this.completeSignin(run, code, id);
      } else if (wait === 'detached_enroll') {
        run.calls = addCall(run.calls, CALL_POLL_ENROLL);
        const oauth = this.oauthClientFor(idStr, POLL_TIMEOUT_MS);
        const body = await oauth.pollResult(String(run.state), { timeout: 2, interval: 2 });
        if (body.enrolled) {
          run.status = 'done';
          run.result = { enrolled: true };
        }
      } else if (wait === 'challenge') {
        run.calls = addCall(run.calls, CALL_WAIT_RESULT);
        const client = this.serviceClientFor(idStr, POLL_TIMEOUT_MS);
        const r = await client.twoFactor.waitForResult(String(run.challengeId), { timeout: 2, interval: 2 });
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
    const idStr = String(id);
    run.calls = addCall(
      run.calls,
      id === 3 ? CALL_COMPLETE_ONE_TIME : id === 4 ? CALL_COMPLETE_CONNECT : CALL_COMPLETE_SIGNIN,
    );
    const oauth = this.oauthClientFor(idStr);
    const out = await oauth.completeSignIn(code, run.verifier ? String(run.verifier) : undefined);
    const result: Record<string, unknown> = {
      user: out.user ?? null,
      mode: out.mode ?? null,
      two_factor: out.two_factor ?? false,
      values: out.values ?? {},
      // The raw app-key ciphertext each decrypted value above came from — pairs with `values` by
      // claim name so the panel can show a decrypt actually ran on real bytes.
      values_cipher: out.values_cipher ?? {},
    };

    if (id === 4) {
      // Connect: read the person's LIVE values via the service data client.
      const shareCode = str(out.user?.share_code);
      run.calls = addCall(run.calls, CALL_SERVICE_BUILD);
      const client = this.serviceClientFor(idStr);
      run.calls = addCall(run.calls, CALL_CONNECTIONS_LIVE);
      let live: Record<string, unknown> = {};
      for await (const conn of client.connections()) {
        if (shareCode !== '' && conn.shareCode === shareCode) {
          live = this.plainValues(conn);
          break;
        }
      }
      result.live_values = live;
    }

    run.status = 'done';
    run.result = result;
  }

  /** Complete an OIDC sign-in (scenario 5) via the openid-client library — id_token verified. */
  private async completeOidc(run: RunRecord, currentUrl: URL, host: string): Promise<void> {
    const idStr = String(Number(run.scenario ?? 0));
    const config = await this.oidcConfigFor(idStr, host);
    run.calls = addCall(run.calls, CALL_OIDC_DISCOVERY);
    run.calls = addCall(run.calls, CALL_OIDC_COMPLETE);
    const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: String(run.verifier ?? ''),
      expectedNonce: String(run.nonce ?? ''),
      expectedState: String(run.state ?? ''),
    });
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
  private oauthClientFor(idStr: string, pollTimeoutMs?: number): OAuthClient {
    const path = this.rt.configPathFor(idStr);
    const opts: OAuthClientOptions = {};
    if (pollTimeoutMs !== undefined) opts.transport = new TimeoutTransport(pollTimeoutMs);
    if (this.usesDefaultAuthorizeBase(idStr)) {
      return OAuthClient.fromConfig(path, opts);
    }
    opts.authorizeUrl = str(this.rt.readConfigMeta(idStr).authorize_base);
    return new OAuthClient(Config.fromIdwFile(path), opts);
  }

  /**
   * Whether `oauthClientFor` takes the named-constructor branch. The SAME predicate decides the client AND
   * the trace entry, so the panel can never name a constructor that did not run — the local-stack
   * option really does build the client a different way.
   */
  private usesDefaultAuthorizeBase(idStr: string): boolean {
    const base = str(this.rt.readConfigMeta(idStr).authorize_base);
    return base === '' || base === DEFAULT_AUTHORIZE_URL;
  }

  /** The trace entry for the OAuth client `oauthClientFor` just built. */
  private idwBuildCall(idStr: string): string {
    return this.usesDefaultAuthorizeBase(idStr) ? CALL_IDW_BUILD : CALL_IDW_BUILD_LOCAL;
  }

  /** Build the service data client OFF the scenario's config file (service role). */
  private serviceClientFor(idStr: string, pollTimeoutMs?: number): Client {
    const path = this.rt.configPathFor(idStr);
    if (pollTimeoutMs === undefined) return Client.fromConfig(path);
    return Client.fromConfig(path, { httpOptions: { transport: new TimeoutTransport(pollTimeoutMs) } });
  }

  /**
   * Build the openid-client Configuration (the OIDC compliance surface) from the config file, sessionless.
   * Discovery is driven off the configured api base (issuer override); http bases enable insecure requests
   * for the local stack. Auth uses client_secret_post — the token endpoint's method.
   */
  private async oidcConfigFor(idStr: string, host: string): Promise<oidc.Configuration> {
    const cfg = this.rt.readConfig(idStr);
    const server = new URL(str(cfg.api_url) || DEFAULT_API_URL);
    const options: oidc.DiscoveryRequestOptions = {};
    if (server.protocol === 'http:') options.execute = [oidc.allowInsecureRequests];
    return oidc.discovery(
      server,
      str(cfg.oauth_client_id),
      { redirect_uris: [this.configRedirectUri(idStr, host)], response_types: ['code'] },
      oidc.ClientSecretPost(str(cfg.oauth_client_secret)),
      options,
    );
  }

  /**
   * The redirect URI recorded in the scenario's config file (used by the OIDC library) — the SAME value
   * the authorize URL carried, so the two legs of the exchange cannot diverge. An absent/empty record
   * re-derives from THIS request's origin; it never substitutes a host.
   */
  private configRedirectUri(idStr: string, host: string): string {
    return str(this.rt.readConfig(idStr).oauth_redirect_uri) || this.redirectUri(host);
  }

  // ── input / config plumbing ──────────────────────────────────────────────

  /**
   * The registered redirect URI: http://{host}/callback, host = the origin the browser actually used.
   * Never falls back to a hardcoded host — `127.0.0.1` and `localhost` are DIFFERENT origins for
   * redirect matching and for browser storage alike, so a substituted default drops the developer on an
   * origin whose localStorage never held the setup and whose URI the OAuth app never registered.
   */
  private redirectUri(host: string): string {
    if (host === '') throw new Error(NO_ORIGIN);
    return `http://${host}/callback`;
  }

  private claims(in_: Record<string, unknown>): string[] {
    const raw = in_.claims;
    if (Array.isArray(raw) && raw.length > 0) return raw.map((c) => String(c));
    return ['email', 'phone']; // a small default claim set (spec §4 scenario 3)
  }

  // A claim carries a mandatory, unique `name` — the key `values` and `attestations` come back
  // under. The demo's config lists claim TYPES, so the type doubles as the name here; a real
  // integration usually names them for its own domain ("billing_email").
  private claimObjects(types: string[]): Claim[] {
    return types.map((t) => ({ name: t, type: t }));
  }

  /** Map a Connection's typed values to a plain {slug: value} object for the result payload. */
  private plainValues(conn: Connection): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [slug, v] of Object.entries(conn.values)) out[slug] = v.value;
    return out;
  }
}
