/**
 * Error taxonomy — the same names across all six SDKs.
 *
 * | Error                          | When                                              |
 * |--------------------------------|---------------------------------------------------|
 * | ConfigError                    | Missing/invalid config or key file at construction (fail fast). |
 * | AuthError                      | Token fetch/refresh failed (bad client_id/secret, revoked client). |
 * | ApiError(status, errorKey,…)   | Any non-2xx from the API; carries the HTTP status + the platform error_key + message. |
 * | DecryptError                   | Wrapper malformed, wrong key, or GCM tag mismatch. |
 * | WebhookError                   | Signature verification failed or an envelope couldn't be unwrapped. |
 * | RateLimitError(retryAfter)     | A 429 from a rate-limited endpoint (subclass of ApiError); carries Retry-After. |
 *
 * All errors extend a common {@link AllusError} base so a single `catch (e) { if (e
 * instanceof AllusError) … }` captures the whole taxonomy. `DecryptError` is raised
 * by the decryption core and re-exported here so the full taxonomy lives in one
 * place.
 */

/** Base class for every SDK error. */
export class AllusError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = new.target.name;
    // Restore the prototype chain for `instanceof` across the ES5 transpile target.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Missing or invalid configuration (or key file) at construction (fail fast).
 *
 * Canonical home for the error; the config + client layers throw it for a bad
 * config file, a missing required field, an unreadable PEM, or a wrong passphrase.
 */
export class ConfigError extends AllusError {}

/**
 * The `client_credentials` token fetch or refresh failed.
 *
 * Thrown when `/oauth2/token` rejects the credentials, or when a 401 mid-flight
 * survives the one automatic refresh-and-retry.
 */
export class AuthError extends AllusError {}

/**
 * Any non-2xx from the API.
 *
 * Carries the HTTP `status`, the platform `errorKey` (when the body provided one),
 * and a human-readable `message`. A transport failure (no HTTP response — e.g. a
 * connection error) surfaces as `new ApiError(0, null, …)`.
 */
export class ApiError extends AllusError {
  readonly status: number;
  readonly errorKey: string | null;
  /** The human-readable message (distinct from the formatted `Error.message`). */
  readonly apiMessage: string | null;

  constructor(status: number, errorKey: string | null = null, message: string | null = null) {
    const parts: string[] = [`HTTP ${status}`];
    if (errorKey) parts.push(`(${errorKey})`);
    if (message) parts.push(`: ${message}`);
    super(parts.join(' '));
    this.status = status;
    this.errorKey = errorKey;
    this.apiMessage = message;
  }
}

/** Signature verification failed, or a webhook envelope couldn't be unwrapped. */
export class WebhookError extends AllusError {}

/**
 * A 429 from a rate-limited endpoint.
 *
 * Subclass of {@link ApiError} with a fixed status of 429; carries the
 * `retryAfter` value parsed from the `Retry-After` response header (seconds, or
 * `null` when absent).
 */
export class RateLimitError extends ApiError {
  readonly retryAfter: number | null;

  constructor(
    retryAfter: number | null = null,
    errorKey: string | null = null,
    message: string | null = null,
  ) {
    super(429, errorKey, message);
    this.retryAfter = retryAfter;
  }
}

/**
 * Wrapper malformed, wrong key, or GCM tag mismatch.
 *
 * Defined here (rather than in `crypto.ts`) so the whole taxonomy is importable
 * from one module; the decryption core imports + throws it.
 */
export class DecryptError extends AllusError {}
