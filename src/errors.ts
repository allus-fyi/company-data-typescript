/**
 * Error taxonomy.
 *
 * | Error                          | When                                              |
 * |--------------------------------|---------------------------------------------------|
 * | ConfigError                    | Missing/invalid config or key file at construction (fail fast). |
 * | AuthError                      | Token fetch/refresh failed (bad client_id/secret, revoked client). |
 * | ApiError(status, errorKey,…)   | Any non-2xx from the API; carries the HTTP status + the platform error_key + message. |
 * | DecryptError                   | Wrapper malformed, wrong key, or GCM tag mismatch. |
 * | WebhookError                   | Signature verification failed or an envelope couldn't be unwrapped. |
 * | RateLimitError(retryAfter)     | A 429 from a rate-limited endpoint (subclass of ApiError); carries Retry-After. |
 * | ValidationError                | A value failed its field type, or a flow field's min/max (then `bound`/`boundValue`). |
 * | PluginInputUnavailable         | A required plugin input is unwired, unanswered, another party's private value, or not convertible. |
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
 *
 * A 503 `db.writes_paused` means saving is paused (the platform cannot complete a save in
 * every region). Nothing was written, so the call is safe to repeat; the response's
 * `Retry-After` is 30 seconds. Any call that is not a GET, the change-feed drains and
 * `OAuthClient.pollResult` can throw it; the token request cannot. The SDK does not retry it.
 *
 * A 503 `platform.out_of_order` means the region serving the call is being rebuilt. The
 * request was not processed, so the call is safe to repeat; the response's `Retry-After` is
 * 300 seconds. Any call can throw it, reads and the change-feed drains included, except the
 * `client_credentials` token request. The SDK does not retry it.
 */
export class ApiError extends AllusError {
  readonly status: number;
  readonly errorKey: string | null;
  /** The human-readable message (distinct from the formatted `Error.message`). */
  readonly apiMessage: string | null;
  /**
   * The error body's remaining fields, verbatim.
   *
   * Some responses carry actionable data BESIDE the key: a 410
   * `company_data.file_expired` returns the expired answer's `content_sha256` and `expired_at`, so a
   * consumer can record that its archived copy is now the only one and still prove what it holds.
   * Generic rather than a bespoke subclass — every error body's extra fields become reachable, and
   * no future one needs a new error type to be readable.
   */
  readonly details: Record<string, unknown>;

  constructor(
    status: number,
    errorKey: string | null = null,
    message: string | null = null,
    details: Record<string, unknown> = {},
  ) {
    const parts: string[] = [`HTTP ${status}`];
    if (errorKey) parts.push(`(${errorKey})`);
    if (message) parts.push(`: ${message}`);
    super(parts.join(' '));
    this.status = status;
    this.errorKey = errorKey;
    this.apiMessage = message;
    this.details = details;
  }
}

/** Signature verification failed, or a webhook envelope couldn't be unwrapped. */
export class WebhookError extends AllusError {}

/**
 * A submitted value failed field-type validation before encryption.
 *
 * Carries the offending field `slug` and its `fieldType` so the caller can point
 * at the bad answer without shipping malformed ciphertext.
 */
export class ValidationError extends AllusError {
  readonly slug: string | null;
  readonly fieldType: string | null;
  /**
   * Set when a flow field's minimum or maximum refused the value: which bound (`min` | `max`) and
   * the bound's value as the field's expression computed it. Null on a type failure.
   */
  readonly bound: 'min' | 'max' | null;
  readonly boundValue: unknown;

  constructor(
    slug: string | null,
    fieldType: string | null,
    bound: { bound: 'min' | 'max'; value: unknown } | null = null,
  ) {
    super(
      bound === null
        ? `invalid ${fieldType} value for '${slug ?? 'value'}'`
        : `value for '${slug ?? 'value'}' is ${bound.bound === 'min' ? 'below its minimum' : 'above its maximum'} ${String(bound.value)}`,
    );
    this.slug = slug;
    this.fieldType = fieldType;
    this.bound = bound === null ? null : bound.bound;
    this.boundValue = bound === null ? null : bound.value;
  }
}

/** Why a plugin input could not be sent. */
export type PluginInputReason = 'unwired' | 'unanswered' | 'other_party_private' | 'not_convertible';

/**
 * A plugin call could not be made because a REQUIRED input is unavailable.
 *
 * `input` is the plugin's input key, `source` the flow key it is wired to, and `reason` why it is
 * unavailable: `unwired` (no source), `unanswered` (the source has no value yet),
 * `other_party_private` (the source is another party's private value — never sent to a plugin) or
 * `not_convertible` (the value does not convert to the input's declared type). An OPTIONAL input
 * that is unavailable is left out of the call instead.
 */
export class PluginInputUnavailable extends AllusError {
  readonly input: string;
  readonly source: string | null;
  readonly reason: PluginInputReason;

  constructor(input: string, source: string | null, reason: PluginInputReason) {
    super(`plugin input '${input}' is unavailable (${reason}${source ? `: ${source}` : ''})`);
    this.input = input;
    this.source = source;
    this.reason = reason;
  }
}

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
