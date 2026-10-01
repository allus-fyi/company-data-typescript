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
  status: number;                       // the HTTP status
  errorKey: string | null;              // the platform error_key, when the body provided one
  apiMessage: string | null;            // a human-readable message
  details: Record<string, unknown>;     // the error body's remaining fields, verbatim
}
```

`err.message` is formatted as `"HTTP <status> (<errorKey>): <apiMessage>"`. A
transport failure (no HTTP response — e.g. a connection error) surfaces as
`new ApiError(0, null, …)`.

`details` carries everything the error body sent BESIDE the key and the message, so a
response with actionable data is readable without a bespoke error type. The current
example is the expired binary answer:

```ts
catch (e) {
  if (e instanceof ApiError && e.errorKey === 'company_data.file_expired') {
    // the frozen answer's 90-day retention elapsed — your copy is now the only one
    record(e.details['content_sha256'], e.details['expired_at']);
  }
}
```

A **421 `region.rebase_required`** never reaches you when the platform is reachable: it is the global front door telling the SDK to send the call to the caller's home region, which the SDK does automatically (README, **How it's wired** → Regions). It surfaces as `ApiError` only when the base the refusal names is absent or empty — in which case no base was stored and no retry was made.

## 503 `db.writes_paused` — saving is paused, retry

While the platform cannot complete a save in every region, a call can answer
**503** with `error_key` **`db.writes_paused`** (`"Saving data is not possible
right now"`) and the header `Retry-After: 30`. **Nothing was written**, so the call
is safe to repeat exactly as it was. Reads keep working.

It surfaces as a plain `ApiError` (`status === 503`, `errorKey ===
'db.writes_paused'`); the SDK does not retry it. `ApiError` does not carry the
`Retry-After` header: wait 30 seconds, then repeat the same call.

Where it can come from:

* every company-data and customer call that is not a GET — creating, updating or
  deleting documents, flow-run starts, answers, uploads and generation, consent
  answers, connect requests, messages, 2FA challenges, `/api/keys/batch`;
* the change-feed drains `GET /api/company-data/changes` and
  `GET /api/customer/changes` (`processChanges`, `drainBatch`): nothing was
  drained, the events stay queued on the server and arrive on a later run, and the
  local buffer is untouched;
* `OAuthClient.pollResult` (`POST /oauth2/result`): the result is not consumed;
  poll again.

The token request (`POST /oauth2/token`) does not answer it: token grants keep
working while saving is paused.

```ts
catch (e) {
  if (e instanceof ApiError && e.status === 503 && e.errorKey === 'db.writes_paused') {
    await sleep(30_000);
    // repeat the same call
  }
}
```

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
| Value access / `BinaryHandle.bytes()` / pump delivery | `DecryptError`; `BinaryHandle.bytes()` also `ApiError` (a 410 `company_data.file_expired` on an expired frozen answer) |
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
