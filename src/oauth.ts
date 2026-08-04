/**
 * "Sign in with allme" — the RP-side OAuth client.
 *
 * A third-party site embeds a *Sign in with allme* button, sends the person to the hosted
 * consent screen, and — once they approve — receives an authorization code at its redirect URI.
 * This module wraps the RP half: build the button URL, exchange the code, read the identity,
 * and (for one_time) decrypt the shared values. Config-only key handling still holds — the app
 * private key + passphrase come from {@link Config} (the idw role), never a method argument.
 */

import { readFileSync } from 'node:fs';
import type { KeyObject } from 'node:crypto';

import { Config } from './config.js';
import { decrypt as cryptoDecrypt, hashMatches, loadPrivateKey, type EncWrapper } from './crypto.js';
import { ApiError, AuthError, ConfigError } from './errors.js';
import { FetchTransport, type HttpTransport, type Sleep } from './http.js';

/** The hosted consent surface. Native apps claim this https link; web is the fallback. */
export const DEFAULT_AUTHORIZE_URL = 'https://web.allme.fyi/auth';

const NON_CLAIMABLE = new Set(['photo', 'document', 'legal_document']);
const MAX_CLAIMS = 15;
const MODES = new Set(['signin', 'one_time', 'connect', '2fa_enroll']);
const RESPONSE_MODES = new Set(['redirect', 'detached']);

/**
 * A claim the relying party asks for — a REQUEST FIELD.
 *
 * You describe what you need: a `name` (the claim's identity on the wire), a field `type`, an
 * advisory `suggest`ion, whether it is `required`, and whether only a `verified` answer will do.
 * You never name one of the person's fields — THEY decide which of theirs answers it.
 *
 * `name` is MANDATORY and must be unique within one request: everything downstream is keyed by it
 * (the stored mapping, the consent outcome, and the `values`/`attestations` maps this SDK returns).
 * Two claims sharing a name are rejected by the API rather than silently coalesced.
 *
 * `verified` is accepted only where it can be honoured (§3.1b): on the OIDC flow, and only for a
 * type that can be attested (v1: `email`). Sending it on a `one_time` request is refused with
 * `invalid_request` — that leg carries no source row id, so the server could neither enforce the
 * requirement nor attest it, and an unhonourable requirement is refused rather than quietly dropped.
 */
export interface Claim {
  /** REQUIRED — the claim's identity on the wire; `values`/`attestations` are keyed by it. */
  name: string;
  type: string;
  suggest?: string;
  required?: boolean;
  /** Only a verified answer satisfies this claim. OIDC flow + verifiable types only. */
  verified?: boolean;
  label?: string;
}

/**
 * §3.1a — proof that a delivered value is the verified one.
 *
 * Present only for a `verified` claim under ENCRYPTED delivery. The server builds and seals this
 * against your app key — a client-supplied attestation is never accepted — so it attests the server's
 * own record of the row the person chose, which is the only thing that makes it evidence.
 *
 * `verified` is computed BY THIS SDK, in constant time, over the plaintext it just decrypted; it is
 * never passed through from the server. **A `verified: false` entry means MISMATCH and you MUST
 * reject the value.** A slug ABSENT from `attestations` means "not attested" — never "wrong" — and you
 * must treat that value as unverified.
 *
 * `verifiedAt` carries the snapshot caveat: it attests the value as verified AT THAT MOMENT, not
 * verified today. A field loses its verification whenever the person re-saves it.
 */
export interface Attestation {
  /** Recomputed here: sha256(salt ‖ plaintext) === hash, constant-time. false = MISMATCH → reject. */
  verified: boolean;
  /** Lowercase hex. */
  hash: string;
  /** Lowercase hex. */
  salt: string;
  verifiedAt: string;
}

export type SignInMode = 'signin' | 'one_time' | 'connect' | '2fa_enroll';
export type ResponseMode = 'redirect' | 'detached';

export interface AuthorizeUrlOptions {
  claims?: Claim[];
  state?: string;
  responseMode?: ResponseMode;
  codeChallenge?: string;
  redirectUri?: string;
}

export interface OAuthClientOptions {
  transport?: HttpTransport;
  authorizeUrl?: string;
  sleep?: Sleep;
}

export interface SignInResult {
  /**
   * §5: `sub` IS the person's share code and is byte-identical to the id_token's `sub`.
   * `share_code` is retained beside it for compatibility and now simply equals it. `display_name` is
   * gone — it is a consented `name` claim now, or nothing: ask for `{name: 'name', type: 'text'}` and
   * read `values.name`.
   */
  user: { sub?: string; share_code?: string };
  mode?: string;
  two_factor: boolean;
  /** Claim name → plaintext. */
  values: Record<string, string>;
  /**
   * Claim name → the RAW app-key ciphertext wrapper `values` was decrypted from — an ADDITIVE
   * sibling of {@link values}, keyed the same way, exactly as delivered by userinfo. Lets a caller
   * demonstrate that a plaintext value really came from encrypted delivery. Empty for a mode/claim
   * that carries no ciphertext (signin mode, or plaintext delivery) — that absence is the honest
   * answer, never a placeholder.
   */
  values_cipher: Record<string, unknown>;
  /**
   * Claim name → {@link Attestation}, keyed by the SAME slug as {@link values} (§3.1a).
   * Additive: an integration that never reads it behaves exactly as before. ABSENT = not attested.
   */
  attestations: Record<string, Attestation>;
}

const defaultSleep: Sleep = (seconds) => new Promise((res) => setTimeout(res, Math.max(0, seconds) * 1000));

/** The RP-side "Sign in with allme" client. */
export class OAuthClient {
  private readonly config: Config;
  private readonly transport: HttpTransport;
  private readonly apiUrl: string;
  private readonly authorizeBase: string;
  private readonly sleep: Sleep;

  constructor(config: Config, opts: OAuthClientOptions = {}) {
    if (!config.oauthClientId || !config.oauthRedirectUri) {
      throw new ConfigError('OAuthClient requires oauth_client_id + oauth_redirect_uri (idw role)');
    }
    this.config = config;
    this.transport = opts.transport ?? new FetchTransport();
    this.apiUrl = config.apiUrl.replace(/\/+$/, '');
    this.authorizeBase = opts.authorizeUrl ?? DEFAULT_AUTHORIZE_URL;
    this.sleep = opts.sleep ?? defaultSleep;
  }

  /** Build from an idw-role JSON config file. */
  static fromConfig(path: string, opts?: OAuthClientOptions): OAuthClient {
    return new OAuthClient(Config.fromIdwFile(path), opts);
  }

  /** Build from `ALLUS_OAUTH_*` env vars. */
  static fromEnv(opts?: OAuthClientOptions): OAuthClient {
    return new OAuthClient(Config.fromIdwEnv(), opts);
  }

  /** Build the consent-screen URL — the "Sign in with allme" button target. */
  authorizeUrl(mode: SignInMode, opts: AuthorizeUrlOptions = {}): string {
    if (!MODES.has(mode)) {
      throw new ConfigError(`invalid mode '${mode}' (expected signin | one_time | connect | 2fa_enroll)`);
    }
    const responseMode = opts.responseMode ?? 'redirect';
    if (!RESPONSE_MODES.has(responseMode)) {
      throw new ConfigError(`invalid responseMode '${responseMode}' (expected redirect | detached)`);
    }
    const params = new URLSearchParams();
    params.set('client_id', this.config.oauthClientId!);
    params.set('redirect_uri', opts.redirectUri ?? this.config.oauthRedirectUri!);
    params.set('mode', mode);
    params.set('response_mode', responseMode);
    if (opts.state !== undefined) params.set('state', opts.state);
    if (opts.codeChallenge) {
      params.set('code_challenge', opts.codeChallenge);
      params.set('code_challenge_method', 'S256');
    }
    const cleaned = this.cleanClaims(opts.claims ?? []);
    if (cleaned.length > 0) params.set('claims', JSON.stringify(cleaned));
    return `${this.authorizeBase}?${params.toString()}`;
  }

  private cleanClaims(claims: Claim[]): Array<Record<string, unknown>> {
    const out: Array<Record<string, unknown>> = [];
    const seen = new Set<string>();
    for (const c of claims) {
      if (!c.type || NON_CLAIMABLE.has(c.type)) continue;
      // §2: `name` is the claim's identity and it is mandatory. Refused HERE rather than left to
      // the API, so the integration error surfaces at the call that made it.
      const name = (c.name ?? '').trim();
      if (!name) throw new ConfigError('every claim must carry a `name`');
      if (seen.has(name)) throw new ConfigError(`duplicate claim name '${name}'`);
      seen.add(name);
      const entry: Record<string, unknown> = { name, type: c.type };
      if (c.suggest) entry.suggest = c.suggest;
      if (c.required) entry.required = true;
      if (c.verified) entry.verified = true;
      if (c.label) entry.label = c.label;
      out.push(entry);
      if (out.length >= MAX_CLAIMS) break;
    }
    return out;
  }

  /** Swap the authorization `code` for a token (POST /oauth2/token). */
  async exchangeCode(code: string, codeVerifier?: string): Promise<Record<string, unknown>> {
    const form: Record<string, string> = {
      grant_type: 'authorization_code',
      client_id: this.config.oauthClientId!,
      code,
      redirect_uri: this.config.oauthRedirectUri!,
    };
    if (codeVerifier) form.code_verifier = codeVerifier;
    if (this.config.oauthClientSecret) form.client_secret = this.config.oauthClientSecret;
    const resp = await this.transport.post(`${this.apiUrl}/oauth2/token`, form, { Accept: 'application/json' });
    return this.parse(resp, 'token exchange');
  }

  /** Read the signed-in identity (GET /api/oauth/userinfo) with the RP token. */
  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const resp = await this.transport.get(`${this.apiUrl}/api/oauth/userinfo`, undefined, {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    });
    return this.parse(resp, 'userinfo');
  }

  /** Exchange + userinfo in one call, decrypting one_time values via the configured app key. */
  async completeSignIn(code: string, codeVerifier?: string): Promise<SignInResult> {
    const token = await this.exchangeCode(code, codeVerifier);
    const accessToken = token.access_token;
    if (!accessToken || typeof accessToken !== 'string') {
      throw new AuthError('token exchange returned no access_token');
    }
    return this.resolveUserinfo(accessToken, token.mode as string | undefined);
  }

  /**
   * Read + decrypt userinfo for an access token ALREADY held — the second half of
   * {@link completeSignIn}, split out so a caller that obtained its access token through its own
   * separate exchange can still resolve and decrypt the claim values. Config-only key handling
   * still holds — the caller passes no key/passphrase, only the token it already has; the private
   * key is read from `Config` exactly as {@link completeSignIn} does.
   *
   * Re-exchanging the code here would be wrong (a second exchange either mints a second grant or
   * fails outright), so this method never does the exchange — only the read + decrypt.
   */
  async resolveUserinfo(accessToken: string, fallbackMode?: string): Promise<SignInResult> {
    const info = await this.userinfo(accessToken);
    const result: SignInResult = {
      user: {
        sub: info.sub as string | undefined,
        share_code: info.share_code as string | undefined,
      },
      mode: (info.mode as string | undefined) ?? fallbackMode,
      two_factor: Boolean(info.two_factor),
      values: {},
      values_cipher: {},
      attestations: {},
    };
    const rawValues = info.values as Record<string, EncWrapper | string> | undefined;
    if (rawValues && Object.keys(rawValues).length > 0) {
      result.values = this.decryptValues(rawValues);
      result.values_cipher = rawValues;
      const rawAttest = info.values_attestation as Record<string, EncWrapper | string> | undefined;
      if (rawAttest && Object.keys(rawAttest).length > 0) {
        result.attestations = this.decryptAttestations(rawAttest, result.values);
      }
    }
    return result;
  }

  /**
   * §3.1a — open the app-key-sealed attestations and attest each value ourselves.
   *
   * A SECOND decrypt per verified claim: `values` is byte-identical to before, but each attestation is
   * its own `{"_enc":1,…}` object. A passthrough accessor that handed back an undecrypted blob would
   * not be an implementation of this.
   *
   * An attestation we cannot open or parse is DROPPED, not surfaced as `verified: false` — absence
   * means "not attested" and a mismatch means "reject the value", and conflating the two would turn a
   * key or transport problem into an accusation that the person's data was tampered with.
   */
  private decryptAttestations(
    raw: Record<string, EncWrapper | string>,
    values: Record<string, string>,
  ): Record<string, Attestation> {
    const pem = readFileSync(this.config.oauthPrivateKey!);
    const key: KeyObject = loadPrivateKey(pem, this.config.oauthKeyPassphrase!);
    const out: Record<string, Attestation> = {};
    for (const [slug, wrapper] of Object.entries(raw)) {
      const plaintext = values[slug];
      if (plaintext === undefined) continue;
      let parsed: { hash?: string; salt?: string; verified_at?: string };
      try {
        parsed = JSON.parse(cryptoDecrypt(wrapper, key));
      } catch {
        continue;
      }
      const hash = parsed.hash ?? '';
      const salt = parsed.salt ?? '';
      if (!hash || !salt) continue;
      out[slug] = {
        // Recomputed here, constant-time, over the plaintext we just decrypted — never trusted from
        // the server. false = the delivered value is NOT the verified one; reject it.
        verified: hashMatches(salt, hash, plaintext),
        hash,
        salt,
        verifiedAt: parsed.verified_at ?? '',
      };
    }
    return out;
  }

  private decryptValues(raw: Record<string, EncWrapper | string>): Record<string, string> {
    if (!this.config.oauthPrivateKey || !this.config.oauthKeyPassphrase) {
      throw new ConfigError('one_time values present but oauthPrivateKey / oauthKeyPassphrase not configured');
    }
    const pem = readFileSync(this.config.oauthPrivateKey);
    const key: KeyObject = loadPrivateKey(pem, this.config.oauthKeyPassphrase);
    const out: Record<string, string> = {};
    for (const [slug, wrapper] of Object.entries(raw)) {
      out[slug] = cryptoDecrypt(wrapper, key);
    }
    return out;
  }

  /**
   * Poll /oauth2/result for a detached sign-in or enrollment (single-delivery).
   *
   * A detached sign-in returns `{code, state}`; a detached `2fa_enroll` returns
   * `{enrolled: true, state}`. Returns on the first delivered shape (`code` OR
   * `enrolled`) and never polls past it, so a one-shot enrollment result is not consumed and lost.
   */
  async pollResult(state: string, opts: { timeout?: number; interval?: number } = {}): Promise<Record<string, unknown>> {
    const timeout = opts.timeout ?? 600;
    const interval = opts.interval ?? 2;
    const form: Record<string, string> = { client_id: this.config.oauthClientId!, state };
    if (this.config.oauthClientSecret) form.client_secret = this.config.oauthClientSecret;
    const deadline = Date.now() + timeout * 1000;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const resp = await this.transport.post(`${this.apiUrl}/oauth2/result`, form, { Accept: 'application/json' });
      if (resp.status === 200) {
        const body = await this.json(resp);
        // Return on the first delivered terminal shape — a sign-in `code` OR a
        // `2fa_enroll` `enrolled` sentinel ({enrolled: true, state}). Both are one-shot;
        // returning here (rather than looping) is what keeps an enrollment result from being
        // consumed and lost to a timeout.
        if (body.code || body.enrolled) return body;
      } else if (resp.status === 410) {
        throw new ApiError(410, 'oauth.result_expired', 'detached sign-in expired before completion');
      } else if (resp.status !== 202) {
        const { key, message } = await this.err(resp);
        throw new ApiError(resp.status, key, message ?? `result poll rejected (HTTP ${resp.status})`);
      }
      if (Date.now() >= deadline) {
        throw new ApiError(0, null, `detached sign-in not completed within ${timeout}s`);
      }
      await this.sleep(interval);
    }
  }

  private async parse(resp: { status: number; text(): Promise<string> }, what: string): Promise<Record<string, unknown>> {
    if (resp.status >= 200 && resp.status < 300) return this.json(resp);
    const { key, message } = await this.err(resp);
    if (resp.status === 401 || resp.status === 403) {
      throw new AuthError(`${what} rejected (HTTP ${resp.status})${key ? ` [${key}]` : ''}${message ? `: ${message}` : ''}`);
    }
    throw new ApiError(resp.status, key, message ?? `${what} rejected (HTTP ${resp.status})`);
  }

  private async json(resp: { text(): Promise<string> }): Promise<Record<string, unknown>> {
    const text = await resp.text();
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  }

  private async err(resp: { text(): Promise<string> }): Promise<{ key: string | null; message: string | null }> {
    try {
      const body = JSON.parse(await resp.text());
      if (body && typeof body === 'object') {
        return { key: (body.error_key as string) ?? null, message: (body.error as string) ?? null };
      }
    } catch {
      /* not JSON */
    }
    return { key: null, message: null };
  }
}
