/**
 * "Sign in with allme" — the RP-side OAuth client (#195).
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
import { decrypt as cryptoDecrypt, loadPrivateKey, type EncWrapper } from './crypto.js';
import { ApiError, AuthError, ConfigError } from './errors.js';
import { FetchTransport, type HttpTransport, type Sleep } from './http.js';

/** The hosted consent surface. Native apps claim this https link; web is the fallback. */
export const DEFAULT_AUTHORIZE_URL = 'https://web.allme.fyi/auth';

const NON_CLAIMABLE = new Set(['photo', 'document', 'legal_document']);
const MAX_CLAIMS = 15;
const MODES = new Set(['signin', 'one_time', 'connect']);
const RESPONSE_MODES = new Set(['redirect', 'detached']);

/** A one_time claim the RP asks for: a field TYPE + an advisory suggestion. */
export interface Claim {
  type: string;
  suggest?: string;
  required?: boolean;
  label?: string;
}

export type SignInMode = 'signin' | 'one_time' | 'connect';
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
  user: { sub?: string; share_code?: string; display_name?: string };
  mode?: string;
  two_factor: boolean;
  values: Record<string, string>;
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
      throw new ConfigError(`invalid mode '${mode}' (expected signin | one_time | connect)`);
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
    for (const c of claims) {
      if (!c.type || NON_CLAIMABLE.has(c.type)) continue;
      const entry: Record<string, unknown> = { type: c.type };
      if (c.suggest) entry.suggest = c.suggest;
      if (c.required) entry.required = true;
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
    const info = await this.userinfo(accessToken);
    const result: SignInResult = {
      user: {
        sub: info.sub as string | undefined,
        share_code: info.share_code as string | undefined,
        display_name: info.display_name as string | undefined,
      },
      mode: (info.mode as string | undefined) ?? (token.mode as string | undefined),
      two_factor: Boolean(info.two_factor),
      values: {},
    };
    const rawValues = info.values as Record<string, EncWrapper | string> | undefined;
    if (rawValues && Object.keys(rawValues).length > 0) {
      result.values = this.decryptValues(rawValues);
    }
    return result;
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

  /** Poll /oauth2/result for a detached sign-in (single-delivery). */
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
        if (body.code) return body;
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
