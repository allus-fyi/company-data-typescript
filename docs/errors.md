# Error model

Same taxonomy + names across all six SDKs. All importable from
`@allus-fyi/company-data`. Every error extends a common `AllusError` base.

```ts
import {
  AllusError, ConfigError, AuthError, ApiError, DecryptError, WebhookError, RateLimitError,
} from '@allus-fyi/company-data';
```

| Error | Thrown when |
|-------|-------------|
| `ConfigError` | Missing/invalid config, an unreadable key file, or a wrong passphrase — at construction (fail fast). |
| `AuthError` | The `client_credentials` token fetch/refresh failed (bad `client_id`/`secret`, revoked client); or a mid-flight 401 survived the one automatic refresh-and-retry. |
| `ApiError` | Any non-2xx from the API. |
| `DecryptError` | A ciphertext wrapper is malformed, the key is wrong, or the GCM tag mismatches. |
| `WebhookError` | Signature verification failed, or a webhook envelope couldn't be unwrapped/parsed. |
| `RateLimitError` | A 429 from a rate-limited endpoint. Subclass of `ApiError`. |

## `AllusError`

The base class. `catch (e) { if (e instanceof AllusError) … }` captures the whole
taxonomy. `instanceof` works correctly across the transpile target (the prototype
chain is restored in the constructor).

## `ApiError`

```ts
class ApiError extends AllusError {
  status: number;             // the HTTP status
  errorKey: string | null;    // the platform error_key, when the body provided one
  apiMessage: string | null;  // a human-readable message
}
```

`err.message` is formatted as `"HTTP <status> (<errorKey>): <apiMessage>"`. A
transport failure (no HTTP response — e.g. a connection error) surfaces as
`new ApiError(0, null, …)`.

## `RateLimitError`

```ts
class RateLimitError extends ApiError {   // status is always 429
  retryAfter: number | null;              // seconds from the Retry-After header, or null
}
```

The SDK already retries a 429 with backoff before surfacing this:

* the transport (`HttpClient`) retries a bounded number of times honoring `Retry-After`;
* the `connections(...)` generator additionally backs off + retries a page a bounded number of times.

For the heavily-limited connections endpoints it surfaces after that backoff so you
don't accidentally hammer them; on the changes feed it auto-backs-off within reason.
If you catch it, wait `err.retryAfter` (or a default) before retrying.

## Where each surfaces

| Layer | Common errors |
|-------|---------------|
| `Client.fromConfig` / `fromEnv` | `ConfigError` |
| Token / any call (auth) | `AuthError` |
| `connections`, `connection`, `requestFields`, `logs`, pump drains | `ApiError`, `RateLimitError` |
| Value access / `BinaryHandle.bytes()` / pump delivery | `DecryptError` |
| `verifyWebhook` / `parseWebhook` / `handleWebhook` | `WebhookError` (`verifyWebhook` returns `false` rather than throwing on a bad signature) |

## Example

```ts
import {
  Client, ConfigError, AuthError, ApiError,
  DecryptError, WebhookError, RateLimitError,
} from '@allus-fyi/company-data';

try {
  const client = Client.fromConfig('allus.json');
  for await (const conn of client.connections()) process(conn);
} catch (e) {
  if (e instanceof ConfigError) { /* fix the config / key file */ }
  else if (e instanceof AuthError) { /* bad/revoked credentials */ }
  else if (e instanceof RateLimitError) { await sleep((e.retryAfter ?? 60) * 1000); }
  else if (e instanceof DecryptError) { /* wrong service key or corrupt data */ }
  else if (e instanceof ApiError) { log(e.status, e.errorKey, e.apiMessage); }
  else throw e;
}
```
