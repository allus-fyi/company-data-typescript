# @allus-fyi/company-data (TypeScript / Node)

The TypeScript/Node SDK for the **allus company-data API**. Point it at a JSON
config file and it hands back typed, plaintext, **your-slug-keyed conclusions**:
for each connected person, a map of *your request-field slug → plaintext value*
(plus whether the value is live and when it last changed).

The SDK hides everything else — the OAuth token, the field catalog, the id
plumbing, the hybrid decryption, binary fetching, the changes-queue mechanics,
JSON-vs-XML. The platform is **zero-knowledge**: the API only ever holds
ciphertext, so all decryption happens inside the SDK with your service private
key. **The person's own field choices are never exposed** — you only ever see
the request slots you configured.

> This SDK is one of six language ports that share an identical API surface.
> This manual is the TypeScript view of it.

**Contents:** [TL;DR — fetch new updates](#tldr--fetch-new-updates) ·
[Quickstart](#quickstart) · [Every call](#every-call) ·
[The typed value model](#the-typed-value-model) ·
[The changes pump](#the-changes-pump) · [Webhooks](#webhooks) ·
[Rate limits](#rate-limits) · [Errors](#errors) ·
[How it's wired](#how-its-wired)

---

## TL;DR — fetch new updates

```bash
npm install @allus-fyi/company-data
```

Point a config.json at your service keys:

```json
{
  "api_url": "https://api.allme.fyi",
  "client_id": "svc_xxx",
  "client_secret": "xxx",
  "service_private_key": "/path/to/service.pem",
  "key_passphrase": "xxx",
  "cache_dir": "./allus-cache"
}
```

Drain everything new, handled one update at a time:

```ts
import { Client } from '@allus-fyi/company-data';

const client = Client.fromConfig('config.json');

await client.processChanges((change) => {
  // event, person, slug, value, live, at
  console.log(change.event, change.personId, change.slug, change.value, change.live, change.at);
});
```

`processChanges` pulls every pending change, decrypts it, and hands them to your
callback ONE BY ONE, acking each only after your code returns. Crash mid-batch? The
next run replays exactly what wasn't acked — nothing is lost, and the API keeps no
backlog of its own. Run it on a schedule (cron / systemd timer); there is no
daemon/follow mode by design. Connections, binary values, and webhooks are
documented below.

Deeper reference pages live in [`docs/`](docs/):
[config](docs/config.md) · [model](docs/model.md) · [pump](docs/pump.md) ·
[webhooks](docs/webhooks.md) · [errors](docs/errors.md).

---

## Quickstart

Requires **Node ≥ 18** (it uses the built-in global `fetch` and `node:crypto`).
The package ships **dual ESM + CommonJS** with bundled `.d.ts` types.

```bash
npm install @allus-fyi/company-data
# or, working from this repo:  npm install && npm run build   # from sdks/typescript/
```

```ts
// ESM
import { Client } from '@allus-fyi/company-data';
```
```js
// CommonJS
const { Client } = require('@allus-fyi/company-data');
```

### 1. Write a config file

A single JSON file holds everything. Any field can be overridden by an `ALLUS_*`
env var, so secrets needn't live in the file. **No SDK method ever takes a key,
passphrase, or secret as an argument** — they all come from here.

`allus.json`:

```json
{
  "api_url": "https://api.allme.fyi",
  "client_id": "svc_1a2b3c…",
  "client_secret": "…",
  "service_private_key": "./service-CRM.pem",
  "key_passphrase": "…",

  "account_private_key": "./account.pem",
  "account_passphrase": "…",

  "webhooks": {
    "wh_abc123": "hmac_secret_for_that_webhook"
  },

  "cache_dir": "./allus-cache",
  "format": "json"
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `api_url` | yes | API base, e.g. `https://api.allme.fyi`. |
| `client_id` / `client_secret` | yes | The registered `client_credentials` credentials for **one** service. |
| `service_private_key` | yes | Path to the OpenSSL-encrypted PKCS#8 PEM you downloaded from the portal. |
| `key_passphrase` | yes | Decrypts that PEM in memory at startup. |
| `account_private_key` / `account_passphrase` | only for `encrypt_payload` webhooks | The company **account** key, used to unwrap an encrypted webhook envelope. |
| `webhooks` / `webhook_secret` | webhook auth — HMAC (default) | Per-webhook HMAC secrets keyed by webhook id (matched via the `X-Allus-Webhook-Id` header). A single-webhook service can use a flat `"webhook_secret": "…"` instead of the map. |
| `webhook_bearer_token` | webhook auth — bearer | Verify `Authorization: Bearer <token>` deliveries. |
| `webhook_basic` | webhook auth — basic | `{"username","password"}` — verify HTTP Basic deliveries. |
| `webhook_header` | webhook auth — header | `{"name","value"}` — verify a custom-header delivery. |
| `webhook_auth_none` | webhook auth — none | `true` — explicit opt-out; `verifyWebhook` always passes (use only behind your own gateway). **Configure at most one** webhook auth method (two+ → `ConfigError`). |
| `cache_dir` | no (default `./allus-cache`) | Durable local buffer for the changes pump. Must be writable + durable. |
| `format` | no (default `json`) | Wire format `json` or `xml`. Invisible in the output. |

The config-file keys are **snake_case** (`api_url`, `client_secret`, …); the SDK
exposes them as camelCase (`config.apiUrl`, …). Env overrides use the `ALLUS_`
prefix, e.g. `ALLUS_CLIENT_SECRET`, `ALLUS_KEY_PASSPHRASE`,
`ALLUS_ACCOUNT_PASSPHRASE`, `ALLUS_WEBHOOK_SECRET`. A missing/invalid config (or an
unreadable PEM / wrong passphrase) throws `ConfigError` at construction — fail
fast.

### 2. First call — list a connection's values

```ts
import { Client } from '@allus-fyi/company-data';

const client = Client.fromConfig('allus.json');

// Iterate every connected person (lazy, auto-paged).
for await (const conn of client.connections()) {
  console.log(conn.displayName, conn.personId);
  for (const [slug, val] of Object.entries(conn.values)) {
    console.log(`  ${slug} = ${JSON.stringify(val.value)}  (live=${val.live}, updated=${val.updatedAt})`);
  }
  break; // just the first one for the demo
}
```

Or fetch one connection by id:

```ts
const conn = await client.connection('019xxxxxxxxxxxxxxxxxxxxxxxxx');
const email = conn.values['work_email'].value;        // "alice@acme.com"  (a string)
```

`Client.fromEnv()` builds the same client entirely from `ALLUS_*` env vars (no
file).

---

## Every call

`Client` is the only object you construct. Build it from config, then:

```ts
Client.fromConfig(path, opts?): Client     // from a JSON file (env overrides secrets)
Client.fromEnv(opts?):          Client      // entirely from ALLUS_* env vars
```

`opts` are advanced/optional: `http` (an injected `HttpClient`), `httpOptions`
(passed to the default `HttpClient`: `transport`, `clock`, `maxRetries429`),
`logger` (a console-compatible sink for the pump), `sleep` (a
`(seconds) => Promise<void>`, for tests).

### `requestFields()`

```ts
requestFields(): Promise<RequestField[]>
```

Your request-field **definitions** — fetched once from
`GET /api/company-data/request-fields` and cached for the life of the client (it
types every value). Returns *your* request config, never the person's fields.

* **Params:** none.
* **Returns:** `Promise<RequestField[]>` — each `RequestField { slug, label, type, oneTime, mandatory, raw }`. `mandatory` is true when the field is mandatory-to-provide **or** mandatory-to-stay-connected.
* **Throws:** `AuthError`, `ApiError`, `RateLimitError`.

```ts
for (const f of await client.requestFields()) {
  const flag = f.mandatory ? 'mandatory' : 'optional';
  console.log(`${f.slug}  ${f.type}  ${flag}${f.oneTime ? ' (one-time)' : ''}`);
}
```

### `connections(limit?, offset?)`

```ts
connections(limit?: number, offset?: number): AsyncGenerator<Connection>
```

A **lazy async generator** that auto-pages
`GET /api/company-data/connections?limit&offset` and yields one typed `Connection`
at a time (bounded memory for a large book). Each `conn.values[slug]` is already
decrypted (or a lazy binary handle). It honors the response's `total` so it never
over-fetches a page past the end (and also stops on a short page).

* **Params:** `limit` — page size (default 100); `offset` — starting offset.
* **Returns:** `AsyncGenerator<Connection>` — consume with `for await`.
* **Throws:** `AuthError`, `ApiError`, `DecryptError` (per value, on access), `RateLimitError` (after the iterator's bounded internal backoff — see [Rate limits](#rate-limits)).

> **Heavily rate-limited.** Use for the initial full sync + occasional
> reconciliation only — never as a poll substitute for the changes feed. The
> generator paces itself within the limit (backs off on `Retry-After`).

```ts
// Initial full sync, streaming so a 100k-connection book never lands in memory.
for await (const conn of client.connections(200)) {
  await upsertLocalRecord(conn);
}
```

### `connection(id)`

```ts
connection(id: string): Promise<Connection>
```

Fetch one connection by its connection id
(`GET /api/company-data/connections/{id}`).

* **Params:** `id` — the connection id (`Connection.id`).
* **Returns:** `Promise<Connection>`. Note: this endpoint returns `{connection_id, user_id, values}` and **no** `displayName`/`connectedAt`, so those identity fields are `null` here (the list endpoint carries them).
* **Throws:** `AuthError`, `ApiError` (404 if unknown), `DecryptError`, `RateLimitError`.

```ts
const conn = await client.connection(connId);
const phone = conn.values['mobile'];
if (phone) console.log(phone.value, phone.live ? 'live' : 'snapshot');
```

### `logs(limit?, offset?)`

```ts
logs(limit?: number, offset?: number): Promise<LogEntry[]>
```

The service's activity log (`GET /api/company-data/logs?limit&offset`) — **ops
events only** (email / purge / webhook), never person field data.

* **Params:** `limit` (default 50), `offset` (default 0).
* **Returns:** `Promise<LogEntry[]>` — each `LogEntry { type, message, metadata, at, raw }`.
* **Throws:** `AuthError`, `ApiError`, `RateLimitError`.

```ts
for (const entry of await client.logs(20)) {
  console.log(entry.at, entry.type, entry.message);
}
```

### `processChanges(handler, options?)`

```ts
processChanges(handler: (change: Change) => void | Promise<void>, options?): Promise<void>
```

The crash-safe changes pump: drains the feed through `handler` **one `Change` at a
time**, durably buffering each batch before delivery, with per-item ack and
retry → dead-letter → continue. Runs **until the feed is empty, then resolves** —
there is **no follow/daemon mode** (you schedule re-runs yourself). Delivery is
**at-least-once**, so your handler **must be idempotent** (dedup on `Change.id`).
See [The changes pump](#the-changes-pump) for the full model.

* **Params:** `handler` — your callback; called with one `Change`. Resolving/returning is an ack; throwing triggers retry. May be sync or async.
* **Options:** `batchSize` (clamped to ≤ 500, default 100), `maxRetries` (default 3), `onError` (`"deadletter"` — default — or `"halt"`), `backoff` (`(attempt) => seconds`).
* **Returns:** `Promise<void>` (resolves when the feed is empty + the buffer is drained).
* **Throws:** `AuthError`, `ApiError`, `RateLimitError` (during a drain); `TypeError` (bad `onError`); whatever the handler throws if `onError="halt"` and retries are exhausted.

```ts
async function handle(change) {
  if (await alreadyProcessed(change.id)) return;   // idempotency — dedup on the stable id
  if (change.event === 'field_updated') {
    await store(change.personId, change.slug, change.value);
  } else if (change.event === 'connection_deleted' || change.event === 'field_deleted') {
    await remove(change.personId, change.slug);
  }
  await markProcessed(change.id);
}

await client.processChanges(handle);            // resolves when the feed is empty
```

> `logger` is **not** a `processChanges` option — pass it once to the `Client`
> constructor (`Client.fromConfig('allus.json', { logger: myLogger })`).

### Advanced changes primitives

```ts
drainBatch(max?: number)                            : Promise<Change[]>     // raw, UNBUFFERED — you own durability
deadLetters()                                       : DeadLetterRecord[]    // the local dead-letter store
retryDeadLetters(handler, options?)                 : Promise<number>       // re-drive dead-lettered events; resolves to count re-driven
```

* `drainBatch(max)` — fetches one batch (clamped ≤ 500) and returns the decrypted `Change`s directly. It does **not** persist anything, so a crash loses what the API already deleted. Prefer `processChanges` for safe consumption.
* `deadLetters()` — each record is the stored (ciphertext) event plus a flattened `error` and `attempts`.
* `retryDeadLetters(handler, options?)` — same `maxRetries` / `onError` / `backoff` options as `processChanges`; on success a record is removed, on repeated failure it stays dead-lettered (or re-throws under `"halt"`). Dead letters are never re-fetched from the API — the local store is their only home.

```ts
for (const dl of client.deadLetters()) {
  console.log('stuck:', dl.id, dl.error, 'after', dl.attempts, 'attempts');
}
const n = await client.retryDeadLetters(handle);     // after you've fixed the bug
console.log(`re-drove ${n} dead letters`);
```

### Webhook helpers (on the client)

The webhook receiver helpers are also exposed as `Client` methods (they delegate
to the module functions, fully config-driven — no key/secret arguments):

```ts
client.verifyWebhook(rawBody: Buffer | Uint8Array | string, headers): boolean
client.parseWebhook(rawBody, headers):  Change
client.handleWebhook(rawBody, headers): Change   // verify + parse
```

* `verifyWebhook` — recomputes `HMAC-SHA256(rawBody, secret)` and constant-time-compares it to `X-Allus-Signature`. Returns `true`/`false`; **never throws** for a bad signature.
* `parseWebhook` — body → a typed `Change`. Does **not** verify. Handles JSON, XML, and the `encrypt_payload` account-key envelope. Throws `WebhookError` on a malformed/unparseable body.
* `handleWebhook` — verify **then** parse; throws `WebhookError` on a bad/unknown signature, otherwise returns the `Change`. The typical one-liner inside a route.

> The client webhook methods are **synchronous** and require the request-fields
> catalog (for value typing). Call `await client.requestFields()` once at startup
> so the catalog is cached before you handle webhooks (the catalog fetch is the
> only network call these methods would need, and it must be done up front since
> they are sync).

The same three are importable as standalone functions
(`import { verifyWebhook, parseWebhook, handleWebhook } from '@allus-fyi/company-data'`),
which take the `config` and the decrypt/type closures explicitly — but inside an
app you'll almost always use the client methods. See [Webhooks](#webhooks).

---

## The typed value model

You work with these objects and nothing else (`import { … } from '@allus-fyi/company-data'`):

```text
RequestField { slug, label, type, oneTime, mandatory }     // YOUR request config
Connection   { id, personId, displayName, connectedAt, values: {<slug>: Value} }
Value        { value, live, updatedAt }
Change       { id, event, personId, slug?, value?, live?, at }
LogEntry     { type, message, metadata, at }
```

### Keyed by *your* slug

`conn.values['work_email'].value` → `"alice@acme.com"`. The key is the stable,
explicit slug you set per request field in the portal — rename the label freely,
the slug is the contract. **The person's source field is never exposed**: no
source slug, no `field_id`, not even via `.raw`.

### `Value { value, live, updatedAt }`

| Property | Meaning |
|----------|---------|
| `value` | The typed plaintext (see the table below). |
| `live` | `true` if the person chose "keep connected" (auto-updates); `false` for a one-time snapshot. |
| `updatedAt` | `Date` of when this answer last changed (per-answer, rides on the `Value`), or `null`. |

### Value types (from the field's `type`)

| Field type | JS `value` |
|------------|------------|
| `email`, `phone`, `url`, `text` | `string` |
| `address`, `bank`, `creditcard` | a parsed `object` — the decrypted plaintext is a JSON object, parsed for you |
| `date`, `date_of_birth` | a `Date` (UTC midnight; falls back to the raw string if it can't be parsed) |
| `photo`, `document`, `legal_document` | a lazy `BinaryHandle` — see below |
| unanswered / no value | `null` |

```ts
const addr = conn.values['home_address'].value as Record<string, unknown>; // {street, city, …}
const dob  = conn.values['birthday'].value as Date;                          // Date(1990-05-17)
```

### Binary fields — the lazy `BinaryHandle`

A photo/document value is a `BinaryHandle`. Nothing is fetched or decrypted until
you call `.bytes()` or `.save()`:

```ts
const handle = conn.values['passport_scan'].value as BinaryHandle;  // no network yet

const data = await handle.bytes();                  // GET the slot file → decrypt → Buffer
const n    = await handle.save('/tmp/passport.jpg'); // same, written to disk; returns bytes written
console.log(handle.valueUrl);                         // the opaque slot-keyed URL it fetches from
```

`.bytes()` GETs the slot-keyed file endpoint, unwraps the API's
`{"encrypted": true, "value": <wrapper>}` envelope, decrypts with your service key,
parses the inner JSON envelope (`{"full": "data:…"}` for photos, `{"file": "data:…"}`
for documents) and base64-decodes the data URI into a `Buffer`. The result is cached
on the handle, so repeated calls don't re-fetch. `.save()` is crash-safe (temp file →
fsync → atomic rename).

### `Change { id, event, personId, slug?, value?, live?, at }`

A change-feed / webhook event.

| Property | Meaning |
|----------|---------|
| `id` | **The stable server change-row id — your dedup key** (captured before the server delete). |
| `event` | `connection_created`, `connection_deleted`, `field_updated`, `field_deleted`, `consent_accepted`, `consent_declined`. |
| `personId` | The person the change is about (may be `null`). |
| `slug`, `value`, `live` | Present only on `field_updated`; `value` is typed exactly like `Value.value` (incl. a lazy `BinaryHandle` for binaries). Connection/consent events carry no slot/value. |
| `at` | `Date` of the change. (There is no separate `updatedAt` on a change.) |

### `.raw`

Every model carries `.raw` — the underlying *hardened* API object — for debugging
or an edge case the SDK didn't model. It still never contains the person's source
field.

See [`docs/model.md`](docs/model.md) for the full reference.

---

## The changes pump

The changes feed is a server-side **drain-on-fetch queue**:
`GET /api/company-data/changes?limit=N` returns up to N events (default 100, max
500) **and deletes exactly those rows in the same transaction** — no
offset/cursor, and the API keeps no copy afterward. So consumption can't be a
plain list: a consumer crash mid-batch would lose events the API already deleted,
and a huge backlog must not materialize in memory. `processChanges` solves both.

**Per run, repeating until the feed is empty then resolving:**

1. **Replay first.** Deliver any un-acked events already in the local buffer (from a previous crashed run), oldest-first.
2. **Drain.** When the buffer is empty, fetch one batch and **persist it to the durable file buffer (fsync) BEFORE handing anything out.** This is the backup the API no longer has.
3. **Deliver one-by-one.** For each buffered event, oldest-first: decrypt its value *at delivery* (never on disk), build the typed `Change`, call `handler`.
4. **Ack / retry / dead-letter.** On success, remove the event from the buffer (ack). On a handler error, retry with backoff up to `maxRetries`; then either move it to the dead-letter store and continue (`onError="deadletter"`, default — one poison event never wedges the stream) or stop and re-throw (`onError="halt"`). A `DecryptError` on a buffered event (corrupt/truncated ciphertext, rotated key) is **dead-lettered immediately** — re-decrypting can't fix it, so it does *not* burn retries (under `onError="halt"` it re-throws). Either way it never propagates out and wedges replay.
5. Repeat until a drain returns empty **and** the buffer is drained → resolve.

### The durable buffer

* Plain files under `cacheDir` (zero extra dependencies): `pending/` for un-acked events, `deadletter/` for ones that exhausted retries.
* Stored events keep their **ciphertext** value — **no plaintext PII is ever written to disk**. Decryption happens only at delivery.
* Writes are crash-safe (temp file → `fsyncSync` → atomic rename → dir fsync). Files are named with a monotonic, zero-padded sequence so they replay oldest-first.

### Crash safety, at-least-once, and idempotency

A batch is durably buffered *before* any delivery, and acked per-item only *after*
the handler succeeds. The ack can't be atomic with your side-effects — a crash
between your handler's success and its ack re-delivers that event on the next run.
That makes delivery **at-least-once**, so:

> **Your handler must be idempotent. Dedup on `Change.id`.**

`Change.id` is the stable server change-row id, captured before the server delete,
so it survives crash + replay unchanged.

### No follow mode

`processChanges` resolves when the feed empties. **You** schedule re-runs — a cron
job, a `while (true) { await client.processChanges(handle); await sleep(5000); }`
loop, a worker queue, whatever fits. The feed is cheap to poll (see
[Rate limits](#rate-limits)).

### Worked example

```ts
import { Client } from '@allus-fyi/company-data';

const client = Client.fromConfig('allus.json');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function handle(change) {
  if (await seen(change.id)) return;            // idempotent: skip what we've applied
  switch (change.event) {
    case 'field_updated':
      await storeValue(change.personId, change.slug, change.value, change.live);
      break;
    case 'field_deleted':
      await clearValue(change.personId, change.slug);
      break;
    case 'connection_deleted':
      await dropPerson(change.personId);
      break;
    case 'connection_created':
    case 'consent_accepted':
    case 'consent_declined':
      await noteEvent(change.personId, change.event, change.at);
      break;
  }
  await recordSeen(change.id);
}

// Schedule your own re-runs; processChanges itself resolves when empty.
for (;;) {
  await client.processChanges(handle, { batchSize: 200, maxRetries: 5 });
  await sleep(5000);
}
```

If a handler keeps failing, the event lands in the dead-letter store instead of
blocking the stream; inspect with `client.deadLetters()` and re-drive with
`client.retryDeadLetters(handle)` after fixing the cause. See
[`docs/pump.md`](docs/pump.md).

---

## Webhooks

Webhooks are the lower-latency push alternative to polling the changes feed. The
platform POSTs each change event to your configured webhook URL with:

* `X-Allus-Webhook-Id` — which webhook this is (selects the HMAC secret from config).
* `X-Allus-Signature` — `HMAC-SHA256(rawBody, secret)` as lowercase hex.
* the body — the same slug-keyed `Change` shape as the pull feed (JSON or XML).

All secrets/keys come from config; the helpers take **no key or secret
arguments**. Use the raw request body **bytes** (`Buffer`) — do not re-serialize a
parsed body, the HMAC is over the exact bytes the platform sent.

### In a web route (Express)

```ts
import express from 'express';
import { Client, WebhookError } from '@allus-fyi/company-data';

const app = express();
const client = Client.fromConfig('allus.json');
await client.requestFields();   // warm the catalog once (the webhook methods are sync)

// IMPORTANT: capture the RAW body bytes — do not let a JSON body-parser replace them.
app.post('/allus/webhook', express.raw({ type: '*/*' }), (req, res) => {
  let change;
  try {
    change = client.handleWebhook(req.body /* Buffer */, req.headers);
  } catch (e) {
    if (e instanceof WebhookError) return res.sendStatus(401); // bad/unknown signature
    throw e;
  }
  // Same idempotency rule as the pump: dedup on change.id.
  if (!seen(change.id)) {
    applyChange(change);
    recordSeen(change.id);
  }
  res.sendStatus(204);
});
```

`verifyWebhook` / `parseWebhook` let you split the steps if you prefer:

```ts
if (!client.verifyWebhook(rawBody, headers)) return res.sendStatus(401);
const change = client.parseWebhook(rawBody, headers);
```

### Config-driven secrets

Per-webhook HMAC secrets live in the config `webhooks` map, keyed by webhook id;
the SDK reads `X-Allus-Webhook-Id` off the request and looks up the matching
secret. A single-webhook service can use the flat `"webhook_secret": "…"`
shortcut (or `ALLUS_WEBHOOK_SECRET`). An unknown/unconfigured id ⇒ verification
returns `false` (and `handleWebhook` throws `WebhookError`).

### The `encrypt_payload` account-key envelope

If a webhook has `encrypt_payload` enabled, the body is **replaced** by a
`{"_enc":1,…}` envelope encrypted to your company **account** key (and the HMAC is
over that envelope — the final bytes sent). `parseWebhook`/`handleWebhook` unwrap
it transparently using the configured `account_private_key` + `account_passphrase`,
then decrypt the inner field value with the service key — so an encrypted-payload
`Change` is identical to a plain one. If you receive such a webhook without an
`account_private_key` configured, you get a `WebhookError`.

> The account-key envelope uses OAEP-**SHA1** (OpenSSL's default), distinct from
> the OAEP-SHA256 used for person field values — the SDK handles this difference
> internally; you only supply the account key in config.

See [`docs/webhooks.md`](docs/webhooks.md).

---

## Rate limits

| Endpoint | Limit | Use it for |
|----------|-------|-----------|
| `changes` (the pump) | **generous** | Poll **as often as you like** — it's a cheap drain-on-fetch queue. |
| `request-fields`, `logs` | moderate | Occasional reads. |
| `connections`, `connection(id)`, binary `/file` | **heavily limited** | Initial full sync + occasional reconciliation **only** — never as a poll substitute. |

A 429 carries `Retry-After`. The SDK backs off and retries automatically:

* The transport (`HttpClient`) retries a 429 a bounded number of times honoring `Retry-After`, then surfaces `RateLimitError`.
* The `connections(...)` generator additionally backs off per `Retry-After` on a surfaced `RateLimitError` and retries the page a bounded number of times before re-throwing — so it paces itself within the limit instead of hammering.

If you catch a `RateLimitError`, its `.retryAfter` is the seconds to wait (or
`null` when the header was absent).

---

## Errors

All from `@allus-fyi/company-data`. Same taxonomy + names across all six SDKs.
Every error extends `AllusError`, so `catch (e) { if (e instanceof AllusError) … }`
captures the whole taxonomy.

| Error | When |
|-------|------|
| `ConfigError` | Missing/invalid config, unreadable key file, or wrong passphrase — at construction (fail fast). |
| `AuthError` | Token fetch/refresh failed (bad `client_id`/`secret`, revoked client); or a 401 survives the one automatic refresh-and-retry. |
| `ApiError` | Any non-2xx from the API; carries `status`, `errorKey` (the platform `error_key`, when present), and `apiMessage`. |
| `DecryptError` | A ciphertext wrapper is malformed, the key is wrong, or the GCM tag mismatches. Surfaces when a value is accessed/decrypted. |
| `WebhookError` | Signature verification failed, or an envelope couldn't be unwrapped/parsed. |
| `RateLimitError` | A 429 from a rate-limited endpoint. Subclass of `ApiError` (status fixed at 429); carries `retryAfter` (seconds, or `null`). |

```ts
import {
  Client, AllusError, ConfigError, AuthError, ApiError,
  DecryptError, WebhookError, RateLimitError,
} from '@allus-fyi/company-data';

try {
  const client = Client.fromConfig('allus.json');
  for await (const conn of client.connections()) { /* … */ }
} catch (e) {
  if (e instanceof ConfigError) { /* fix the config / key file */ }
  else if (e instanceof RateLimitError) { await wait((e.retryAfter ?? 60) * 1000); }
  else if (e instanceof ApiError) { log(e.status, e.errorKey, e.apiMessage); }
  else throw e;
}
```

See [`docs/errors.md`](docs/errors.md).

---

## How it's wired

Everything below is what the SDK hides so your code only ever sees conclusions.

**Auth / token.** An `HttpClient` owns a `client_credentials`-only token. On the
first call (or when the cached token nears expiry) it POSTs
`client_id`/`client_secret` to `{api_url}/oauth2/token` and caches the bearer
token + its expiry; refresh is automatic. A mid-flight 401 triggers exactly one
refresh-and-retry, then `AuthError`. The token is scoped server-side to **one**
service, so every call is implicitly that service's data. The transport is over
Node's global `fetch` by default, but injectable (`HttpTransport`) for tests.

**Slug resolution.** `requestFields()` is fetched once and cached; its slug→type
map types every value (so `address` parses to an object, `photo` becomes a lazy
binary handle, etc.). The connection/changes endpoints return values keyed by
**your** request slug — the person's source field is dropped server-side and never
reaches the SDK.

**Decryption (zero-knowledge).** The service private key is loaded **once** at
construction from the configured encrypted PEM + passphrase
(`crypto.createPrivateKey({ key, passphrase })` — PBES2 handled by OpenSSL). A
`decryptValue` closure over it is handed to every model factory and the pump — the
key never appears in a method signature. Each value is a hybrid wrapper
(`{"_enc":1,"k":rsa_oaep_sha256(aesKey),"iv":…,"d":aes256gcm(…)}`); the SDK
RSA-OAEP-SHA256 unwraps the AES key (`privateDecrypt({ …, oaepHash: 'sha256' })` —
Node defaults to SHA-1, so the SHA-256 pin is essential), then AES-256-GCM decrypts
the payload (the 16-byte tag is the last 16 bytes of `d`). **The platform only ever
holds ciphertext — it never sees your plaintext.**

**Binary fetch.** A binary value is a lazy `BinaryHandle` over a slot-keyed
`value_url`. On `.bytes()`/`.save()` it GETs that file endpoint, unwraps the
`{"encrypted":true,"value":<wrapper>}` envelope, runs the same service-key decrypt
to a JSON file-envelope, and base64-decodes its data URI to the file bytes.
(Slot-keyed, never source-field-keyed.)

**XML, safely.** When `format: "xml"`, responses (and webhook bodies) are parsed by
a small, **XXE-safe** hand-written parser: no DOCTYPE/DTD processing, no custom or
external entities — those vectors are simply absent, and a DOCTYPE / unknown entity
is rejected. HMAC verification is always over the raw bytes, never the parsed tree.

**The drain-on-fetch feed.** `processChanges` delegates to a `Pump` wired to a
`fetchChanges` closure (`GET /changes?limit=`, returning raw ciphertext events) and
a `decrypt` closure (builds a typed `Change`). Because the fetch deletes the rows it
returns, the pump persists each batch to the durable file buffer (ciphertext at
rest) before delivery, acks per-item after your handler succeeds, and replays the
buffer on restart — see [The changes pump](#the-changes-pump).

---

## Status

**Crypto parity gate:** the decryption core is verified against the shared
cross-language decryption vector — PEM-load (PBES2 / PBKDF2-SHA256 / AES-256-CBC,
100k iters), text decrypt, and the binary decrypt → envelope → inner-bytes hash —
plus an independent OpenSSL cross-check (anti-circularity). The full test suite
(config, crypto, http/auth, models, the crash-safe pump, webhooks, and the XXE-safe
XML parser) is green under `npm test`.
