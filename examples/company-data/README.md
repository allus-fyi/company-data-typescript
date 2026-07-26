# Company-data example (TypeScript)

A thin, runnable localhost backend that serves the shared allme SDK example frontend and implements the
**demo-backend contract v3, company-data family** through the TypeScript SDK's **service-role** data
`Client`. Five scenarios, disposable state.

This is its own npm sub-project — it is **not** part of the published `@allus-fyi/company-data` package.
It depends on the SDK via a local path (`file:../..`).

## Run

```bash
git clone https://github.com/allus-fyi/company-data-typescript
cd company-data-typescript/examples/company-data
npm install       # once — installs tsx/typescript + links the local SDK
npm start         # wipes .runtime/, fetches + verifies the pinned frontend, serves on :8091
```

Then open <http://localhost:8091>. Override the port with `PORT=<n> npm start` (one browser origin is
shared across the SDK examples, so only one runs at a time).

`npm start` fetches the pinned frontend release (`frontend.lock` → tag `v0.3.0`), verifies its sha256,
unpacks it under `.frontend/<tag>/`, and refuses to serve on a checksum or `contract.json` mismatch.

## The five scenarios

Every scenario uses the SERVICE-role `Client`, built from the config file the setup panel writes
(`Client.fromConfig(...)` → `Config.fromFile`). There is **no** OAuth/OIDC leg — no `/callback`, no
`/enroll`. Open `src/server.ts` and each handler shows the exact SDK call implementing the card.

| Scenario | SDK call(s) | Result |
|---|---|---|
| `companydata:read` | `Client.connections()` | `{connections:[{connectionId, personId, displayName, customerType, shareCode, values:[{slug,value,live,at}]}]}` — grouped by connection |
| `companydata:definitions` | `Client.requestFields()` | `{fields:[{slug,label,type,mandatory,one_time}]}` |
| `companydata:changes` | `Client.processChanges()` | `{events:[…], drained:true}` — crash-safe pump drain, idempotent on `Change.id` |
| `companydata:webhook` | `Client.verifyWebhook()` + `Client.parseWebhook()` (public `POST /webhook`) + `Client.drainBatch()` (feed fallback) | `{webhookId, events:[{source,…}], unparseable?}` — accumulating |
| `companydata:documents` | `Client.createDocument()` ×6 | `{docs:[{index,label,document_id,status}]}` |

The four data scenarios run synchronously on `/start` (`action {type:"data"}`; the run is `done` with the
pinned `result`). A start-time failure surfaces as a `failed` run, never a 200 without the success shape.

## The webhook scenario

`companydata:webhook` is **accumulating**, not long-poll (a held-open request would wedge the single
worker). `/start` persists a routing record `webhookId → runId` (superseding any prior active webhook run)
and returns `{action:{type:"none"}}`. Events arrive two ways:

1. **`POST /webhook`** (public inbound delivery). The exact sequence — never the combined
   `handleWebhook()`, which can't split 401-vs-200:
   - read `X-Allus-Webhook-Id`; unknown/stale id or no active run → **200** acknowledge-and-discard.
   - `Client.verifyWebhook()` false → **401** (a genuine signature failure; loud).
   - `Client.parseWebhook()` ok → append `{source:"webhook",…}` + **200**; a `WebhookError` here is a
     verified-but-unparseable delivery → **200** acknowledge-and-note (`unparseable`).
   - Every accepted-and-dropped case is **200** — the platform worker counts exactly 200 as success.
2. **Feed fallback** (always-works default). Each `GET /api/runs` poll does ONE `Client.drainBatch()` raw
   feed fetch, appending `{source:"feed",…}` events deduped on `Change.id`. The run stays `pending` while
   collecting; the frontend keeps polling and renders `run.result`.

The scenario is **setup-first**: register a webhook on your service in the portal, then paste its
**webhook id** and one-time **HMAC secret** into the scenario before starting it — **the run refuses to
start without them** (`/start` answers `409 not_configured`). Set `encrypt_payload` OFF; this example
holds no account private key. Once it is started, the webhook tunnel is the optional advanced (deployed)
path; the feed fallback works locally without it.

## Backend state (single worker, disposable)

Node's built-in `http` = one process = one worker, so requests serialize — no locks, no burn-on-read.
State lives under `.runtime/` (git-ignored, wiped at every startup):

- `config/{sid}.json` — the canonical SDK config file each scenario runs off, written by
  `POST /api/scenarios/{id}/config` from the browser settings (`api_url`, `client_id`, `client_secret`,
  `service_private_key` path, `key_passphrase`; `cache_dir` for the pump scenarios;
  `webhooks:{id:secret}` for the webhook scenario). Any PEM is written to `config/keys/<sha1>.pem` (0600).
- `config/{sid}.meta.json` — demo-only values that are not SDK config fields (the documents `share_code`,
  the webhook id).
- `runs/{runId}.json` — one run's accumulated result + `calls`, 30-minute TTL.
- `webhook-route.json` — the single active webhook run. `cache/` — the pump's buffer/dead-letters.

Config files are configuration, not runs: removed only by Clear or the startup wipe. This reverses the
"no config files while testing" rule for the examples on purpose — seeing the real SDK config file makes
the demo clearer (sdk.html §2).

## Files

```
bin/start.ts            launcher (wipe → fetch+verify bundle → contract guard → serve)
src/server.ts           HTTP dispatch → one handler per scenario → the SDK call
src/runtime.ts          .runtime/ state: config files, runs, webhook route, pump cache
src/timeoutTransport.ts a short-timeout HttpTransport for the per-poll drainBatch() feed fetch
frontend.lock           the pinned frontend release {tag, sha256}
```
