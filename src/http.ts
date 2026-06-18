/**
 * OAuth token + HTTP layer.
 *
 * The {@link HttpClient} is the thin transport every higher layer goes through. It
 * owns:
 *
 *   - **Auth** — `client_credentials` only. On the first call (or when the cached
 *     token is near expiry) it POSTs `client_id`/`client_secret` to
 *     `{api_url}/oauth2/token` and caches the bearer token + its expiry. Refresh is
 *     automatic and transparent; a 401 mid-flight triggers exactly one
 *     refresh-and-retry, then surfaces as {@link AuthError}.
 *   - **Format** — sets `Accept` per `config.format` (`application/json` or
 *     `application/xml`) and parses the body accordingly. The XML parser is the
 *     XXE-safe `parseXml` (mirrors the platform serializer).
 *   - **Errors** — maps non-2xx to the error taxonomy: a 401 → refresh+retry then
 *     {@link AuthError}; a 429 → read `Retry-After` and back off + retry a bounded
 *     number of times, then {@link RateLimitError}; any other non-2xx →
 *     {@link ApiError} carrying the body's `error_key` when present.
 *
 * Config-only key handling: the client id/secret come from the {@link Config} —
 * never a method argument.
 *
 * The transport is injectable (`HttpTransport`) so the whole client is testable
 * without the network; the default uses Node's global `fetch`.
 */

import { Config } from './config.js';
import { ApiError, AuthError, RateLimitError } from './errors.js';
import { parseXml } from './xml.js';

// Refresh the token a little before it actually expires so an in-flight call never
// races the expiry boundary.
const TOKEN_EXPIRY_SKEW_S = 30.0;

// 429 backoff policy: bounded retries with a Retry-After-driven (or default) sleep
// between attempts. Connections endpoints are heavily limited, so after the bounded
// retries we surface RateLimitError rather than hammering.
const DEFAULT_MAX_RETRIES_429 = 3;
const DEFAULT_BACKOFF_S = 1.0;
const MAX_BACKOFF_S = 60.0;

/** A minimal HTTP response shape (a subset of the Fetch API `Response`). */
export interface HttpResponse {
  status: number;
  text(): Promise<string>;
  /** Case-insensitive header lookup, returning `null` when absent (Fetch `Headers`). */
  headers: { get(name: string): string | null };
}

/** A pluggable transport (the default wraps Node's global `fetch`). */
export interface HttpTransport {
  post(url: string, form: Record<string, string>, headers: Record<string, string>): Promise<HttpResponse>;
  get(
    url: string,
    params: Record<string, string | number> | undefined,
    headers: Record<string, string>,
  ): Promise<HttpResponse>;
}

export type Sleep = (seconds: number) => Promise<void>;
export type Clock = () => number;

const defaultSleep: Sleep = (seconds) => new Promise((res) => setTimeout(res, Math.max(0, seconds) * 1000));
const defaultClock: Clock = () => Date.now() / 1000;

/** Default transport over Node's global `fetch`. */
export class FetchTransport implements HttpTransport {
  async post(url: string, form: Record<string, string>, headers: Record<string, string>): Promise<HttpResponse> {
    const body = new URLSearchParams(form).toString();
    const resp = await fetch(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    return resp;
  }

  async get(
    url: string,
    params: Record<string, string | number> | undefined,
    headers: Record<string, string>,
  ): Promise<HttpResponse> {
    let full = url;
    if (params && Object.keys(params).length > 0) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) qs.set(k, String(v));
      full += (url.includes('?') ? '&' : '?') + qs.toString();
    }
    const resp = await fetch(full, { method: 'GET', headers });
    return resp;
  }
}

export interface HttpClientOptions {
  transport?: HttpTransport;
  sleep?: Sleep;
  clock?: Clock;
  maxRetries429?: number;
}

/** Authenticated JSON/XML transport for the company-data API. */
export class HttpClient {
  private readonly config: Config;
  private readonly transport: HttpTransport;
  private readonly sleep: Sleep;
  private readonly clock: Clock;
  private readonly maxRetries429: number;

  private readonly apiUrl: string;
  private token: string | null = null;
  private tokenExpiry = 0; // clock deadline (seconds)

  constructor(config: Config, opts: HttpClientOptions = {}) {
    this.config = config;
    this.transport = opts.transport ?? new FetchTransport();
    this.sleep = opts.sleep ?? defaultSleep;
    this.clock = opts.clock ?? defaultClock;
    this.maxRetries429 = opts.maxRetries429 ?? DEFAULT_MAX_RETRIES_429;
    this.apiUrl = config.apiUrl.replace(/\/+$/, '');
  }

  // ── auth ────────────────────────────────────────────────────────────────

  private tokenValid(): boolean {
    return this.token !== null && this.clock() < this.tokenExpiry;
  }

  private async fetchToken(): Promise<string> {
    const url = `${this.apiUrl}/oauth2/token`;
    let resp: HttpResponse;
    try {
      resp = await this.transport.post(
        url,
        {
          grant_type: 'client_credentials',
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret,
        },
        { Accept: 'application/json' },
      );
    } catch (exc) {
      throw new AuthError(`token request failed: ${(exc as Error).message}`);
    }

    const status = resp.status;
    if (status < 200 || status >= 300) {
      const { errorKey, message } = await extractError(resp);
      throw new AuthError(
        `token request rejected (HTTP ${status})` +
          (errorKey ? ` [${errorKey}]` : '') +
          (message ? `: ${message}` : ''),
      );
    }

    let body: unknown;
    try {
      body = JSON.parse(await resp.text());
    } catch {
      throw new AuthError('token response was not valid JSON');
    }
    const accessToken =
      body !== null && typeof body === 'object' ? (body as Record<string, unknown>)['access_token'] : null;
    if (!accessToken) {
      throw new AuthError('token response missing access_token');
    }

    let expiresIn = 3600;
    const rawExpires = (body as Record<string, unknown>)['expires_in'];
    if (rawExpires !== undefined) {
      const n = Number(rawExpires);
      if (Number.isFinite(n)) expiresIn = n;
    }
    this.token = String(accessToken);
    this.tokenExpiry = this.clock() + Math.max(0, expiresIn - TOKEN_EXPIRY_SKEW_S);
    return this.token;
  }

  private async bearer(forceRefresh = false): Promise<string> {
    if (forceRefresh || !this.tokenValid()) {
      return this.fetchToken();
    }
    return this.token as string;
  }

  // ── requests ──────────────────────────────────────────────────────────

  /**
   * GET `path` (e.g. `/api/company-data/connections`) → parsed body.
   *
   * Adds the bearer token + an `Accept` header matching `config.format`, parses
   * JSON or XML, and maps non-2xx responses to the error taxonomy: 401 → one
   * refresh-and-retry then {@link AuthError}; 429 → bounded Retry-After backoff
   * then {@link RateLimitError}; other non-2xx → {@link ApiError} (carrying the
   * body's `error_key` when present).
   */
  async get(path: string, params?: Record<string, string | number>): Promise<unknown> {
    const url = this.url(path);
    const wantsXml = this.config.format === 'xml';
    const accept = wantsXml ? 'application/xml' : 'application/json';

    let retries429 = 0;
    let refreshed401 = false;

    for (;;) {
      const token = await this.bearer(false);
      let resp: HttpResponse;
      try {
        resp = await this.transport.get(url, params, {
          Authorization: `Bearer ${token}`,
          Accept: accept,
        });
      } catch (exc) {
        throw new ApiError(0, null, `request to ${path} failed: ${(exc as Error).message}`);
      }

      const status = resp.status;

      if (status >= 200 && status < 300) {
        return this.parseBody(resp, wantsXml);
      }

      if (status === 401) {
        // One refresh-and-retry, then give up as AuthError.
        if (!refreshed401) {
          refreshed401 = true;
          await this.bearer(true);
          continue;
        }
        const { errorKey, message } = await extractError(resp);
        throw new AuthError(
          'unauthorized after token refresh' +
            (errorKey ? ` [${errorKey}]` : '') +
            (message ? `: ${message}` : ''),
        );
      }

      if (status === 429) {
        const retryAfter = parseRetryAfter(resp);
        if (retries429 < this.maxRetries429) {
          retries429 += 1;
          await this.sleep(backoffDelay(retryAfter, retries429));
          continue;
        }
        const { errorKey, message } = await extractError(resp);
        throw new RateLimitError(retryAfter, errorKey, message);
      }

      // Any other non-2xx → ApiError with the body's error_key.
      const { errorKey, message } = await extractError(resp);
      throw new ApiError(status, errorKey, message);
    }
  }

  private url(path: string): string {
    if (path.startsWith('http://') || path.startsWith('https://')) {
      return path;
    }
    return this.apiUrl + (path.startsWith('/') ? '' : '/') + path;
  }

  private async parseBody(resp: HttpResponse, wantsXml: boolean): Promise<unknown> {
    const text = await resp.text();
    if (text === null || text.trim() === '') {
      return {};
    }
    if (wantsXml) {
      try {
        return parseXml(text);
      } catch (exc) {
        throw new ApiError(resp.status, null, `response was not valid XML: ${(exc as Error).message}`);
      }
    }
    try {
      return JSON.parse(text);
    } catch (exc) {
      throw new ApiError(resp.status, null, `response was not valid JSON: ${(exc as Error).message}`);
    }
  }
}

// ── module-level helpers ─────────────────────────────────────────────────────

/** Pull `error_key` + a message out of a non-2xx body (JSON or XML). */
async function extractError(resp: HttpResponse): Promise<{ errorKey: string | null; message: string | null }> {
  let text: string;
  try {
    text = await resp.text();
  } catch {
    return { errorKey: null, message: null };
  }
  let body: unknown = null;
  const trimmed = text.trim();
  if (trimmed.startsWith('<')) {
    try {
      body = parseXml(trimmed);
    } catch {
      return { errorKey: null, message: trimmed || null };
    }
  } else {
    try {
      body = JSON.parse(trimmed);
    } catch {
      return { errorKey: null, message: trimmed || null };
    }
  }
  if (body !== null && typeof body === 'object' && !Array.isArray(body)) {
    const rec = body as Record<string, unknown>;
    const errorKey = rec['error_key'];
    const message = rec['error'] ?? rec['message'];
    return {
      errorKey: errorKey != null ? String(errorKey) : null,
      message: message != null ? String(message) : null,
    };
  }
  return { errorKey: null, message: null };
}

/** Parse the `Retry-After` header (delta-seconds form) → number of seconds or null. */
function parseRetryAfter(resp: HttpResponse): number | null {
  const raw = resp.headers.get('Retry-After');
  if (raw === null) return null;
  const n = Number(raw.trim());
  // The platform sends delta-seconds; an HTTP-date form falls back to null
  // (default backoff). NaN guards the date case.
  return Number.isFinite(n) ? n : null;
}

/** Sleep duration before the next 429 retry: honor Retry-After, else exponential backoff. */
function backoffDelay(retryAfter: number | null, attempt: number): number {
  if (retryAfter !== null && retryAfter >= 0) {
    return Math.min(retryAfter, MAX_BACKOFF_S);
  }
  return Math.min(DEFAULT_BACKOFF_S * 2 ** (attempt - 1), MAX_BACKOFF_S);
}
