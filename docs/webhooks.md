# Webhook receiver helpers

The lower-latency push alternative to polling the changes feed. The platform POSTs
each change event to your configured webhook URL with:

* `X-Allus-Webhook-Id` — which webhook this is (selects the HMAC secret from config).
* `X-Allus-Signature` — `HMAC-SHA256(rawBody, secret)` as lowercase hex.
* the body — the same slug-keyed `Change` shape as the pull feed (JSON or XML). If `encrypt_payload` is on, the body is replaced by a `{"_enc":1,…}` envelope encrypted to the company **account** key (and the HMAC is over that envelope).

**All secrets/keys come from config — these helpers take NO key or secret
arguments.** Always pass the **raw request body bytes** (a `Buffer`); don't
re-serialize a parsed body — the HMAC is over the exact bytes sent.

## Client methods (the usual form)

```ts
client.verifyWebhook(rawBody: Buffer | Uint8Array | string, headers): boolean
client.parseWebhook(rawBody, headers):  Change
client.handleWebhook(rawBody, headers): Change   // verify + parse
```

| Method | Returns | Errors |
|--------|---------|--------|
| `verifyWebhook` | `boolean` — recomputes `HMAC-SHA256(rawBody, secret)` and constant-time-compares to `X-Allus-Signature`. `false` on missing signature / unknown id / mismatch. | **Never throws** for a bad signature. |
| `parseWebhook` | a typed `Change`. Does **not** verify. Handles JSON, XML, and the `encrypt_payload` account-key envelope. | `WebhookError` on a malformed/unparseable body or envelope. |
| `handleWebhook` | a typed `Change` — verify **then** parse. | `WebhookError` on a bad/unknown signature, or any `parseWebhook` error. |

> The client webhook methods are **synchronous** but need the request-fields catalog
> (to type the value). Call `await client.requestFields()` once at startup so the
> catalog is cached — the methods then make no network calls. `headers` may be a
> plain object or a Node `IncomingHttpHeaders` (case-insensitive lookup; array
> header values use the first element).

## Standalone functions

The same three are importable as module functions. They take the `config` and the
decrypt/type closures explicitly — used by `Client` internally; you'll normally use
the client methods inside an app.

```ts
import { verifyWebhook, parseWebhook, handleWebhook } from '@allus-fyi/company-data';

verifyWebhook(rawBody, headers, config): boolean
parseWebhook(rawBody, headers, config, { typeForSlug, decryptValue, binaryFetch?, accountKey? }): Change
handleWebhook(rawBody, headers, config, { typeForSlug, decryptValue, binaryFetch?, accountKey? }): Change
```

## In a web route

### Express

```ts
import express from 'express';
import { Client, WebhookError } from '@allus-fyi/company-data';

const app = express();
const client = Client.fromConfig('allus.json');
await client.requestFields();   // warm the catalog (the webhook methods are sync)

// Capture the RAW body bytes — do NOT let a JSON parser replace them.
app.post('/allus/webhook', express.raw({ type: '*/*' }), (req, res) => {
  let change;
  try {
    change = client.handleWebhook(req.body, req.headers);
  } catch (e) {
    if (e instanceof WebhookError) return res.sendStatus(401);
    throw e;
  }
  applyChange(change);             // see "Delivery contract" below before adding dedup
  res.sendStatus(200);   // 200 — the ONLY status allus counts as delivered
});
```

### Fastify

```ts
import Fastify from 'fastify';
import { Client, WebhookError } from '@allus-fyi/company-data';

const app = Fastify();
const client = Client.fromConfig('allus.json');
await client.requestFields();

// Keep the raw body: a contentTypeParser that returns the Buffer untouched.
app.addContentTypeParser('*', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));

app.post('/allus/webhook', (req, reply) => {
  let change;
  try {
    change = client.handleWebhook(req.body as Buffer, req.headers);
  } catch (e) {
    if (e instanceof WebhookError) return reply.code(401).send();
    throw e;
  }
  applyChange(change);
  return reply.code(200).send();
});
```

Split the steps if you prefer:

```ts
if (!client.verifyWebhook(rawBody, headers)) return res.sendStatus(401);
const change = client.parseWebhook(rawBody, headers);
```

## Delivery contract — effectively unique, rarely replayed

Each queued event is POSTed **once**, and **only HTTP `200` counts as delivered** — a
`202`, a `204`, a 3xx redirect and every 4xx/5xx are all treated as a failure. On anything
other than `200` (or a timeout or connection error) the event is **not retried in place**:
it and the rest of the webhook's queue move to a durable server-side backlog and the
webhook is marked bad. The backlog is delivered later, either automatically when
the webhook next probes healthy, or when you drain it yourself with
`GET /api/company-data/changes?webhook_id=…` (delete-on-read).

So deliveries are **effectively unique** — with one rare exception. If your endpoint
processed an event but the platform never saw your `200` (your response timed out, or
you crashed after committing but before responding), the event is treated as failed
and replayed on recovery, so you receive it **again**. Nothing caps that at two: a
failed probe leaves its backlog row in place, so every later recovery attempt whose
`200` is likewise lost replays the same event once more. Inside that window the
contract is **at-least-once** — plan for one or more repeats, not for exactly one.

> **Do not use `change.id` as an idempotency key here.** On the webhook path the id is
> neither reliably stable nor reliably fresh, and a receiver cannot tell which one it is
> holding. A **live** delivery is built with no change row behind it, so its id is minted
> for that single POST — the later replay of the same event is rebuilt from a durable
> backlog row and therefore carries a **different** id. But a replayed delivery carries
> **that row's** id, and the row stays in place until it is delivered successfully, so a
> re-attempted replay arrives with the **same** id — which changes again if the event is
> re-backlogged after a further failure. An id check therefore misses the duplicate you
> are most likely to see and matches only a rarer one; it is not a contract. If you need
> strict idempotency, key on the **content** — event + person + slug/document + payload —
> never on the id.

**Webhooks and the pull feed are alternative integrations — consume one, never both.**
The id-dedup guidance in [pump.md](pump.md) applies to the pump only, where `Change.id`
is the real server change-row id.

## Config-driven secrets

Per-webhook HMAC secrets live in the config `webhooks` map, keyed by webhook id;
the SDK reads `X-Allus-Webhook-Id` and looks up the matching secret. A
single-webhook service can use the flat `"webhook_secret": "…"` shortcut (or
`ALLUS_WEBHOOK_SECRET`). An unknown/unconfigured id ⇒ `verifyWebhook` returns
`false` (and `handleWebhook` throws `WebhookError`).

## The `encrypt_payload` account-key envelope

If a webhook has `encrypt_payload` enabled, the whole body is a `{"_enc":1,…}`
envelope encrypted to your company **account** key, and the HMAC is over that
envelope. `parseWebhook`/`handleWebhook`:

1. Unwrap the envelope with the configured `account_private_key` + `account_passphrase` (loaded once at `Client` construction — no per-webhook PBKDF2).
2. Parse the inner payload (JSON or XML per `format`).
3. Decrypt the inner field `value` (a service-key wrapper) with the service key.

So an `encrypt_payload` `Change` is identical to a plain one. Receiving such a
webhook without an `account_private_key` configured throws `WebhookError`.

> The envelope uses RSA-OAEP-**SHA1** (OpenSSL's default), distinct from the
> OAEP-SHA256 used for person field values. The SDK has two OAEP code paths and
> handles this difference internally — you only supply the account key in config.

## XXE safety

XML webhook bodies (and the inner payload after an envelope unwrap) are parsed by
the same **XXE-safe** parser the HTTP layer uses: no DOCTYPE/DTD processing, no
custom or external entities. The HMAC is always computed over the **raw bytes**,
never the parsed tree.
