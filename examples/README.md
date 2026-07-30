# Example test suite — allus company-data TypeScript SDK

A runnable demo of **everything the SDK does**, across three scenario families:

- **Identity** — "Sign in with allme" (redirect + detached), one-time claims, stay-connected,
  standard **OIDC** login (via the `openid-client` library), 2FA-at-consent
  (a guide card), and standalone **service-2FA** with enrollment.
- **Flow** — run a **contract flow** end-to-end: trigger it, drive the company party through it with
  type-checked step filling, hand a turn to the person's phone, then read the decrypted answers and
  (for the contract fixture) download the generated signed document.
- **Company-data** — connections read, request-field catalog, the change feed, **webhooks**, and
  creating document/contract types (six offered, pick which to create).

It is a thin backend implementing the shared **demo-backend contract (v3)**; most of the UI is the
shared frontend bundle fetched from
[`allme-sdk/example-test-suite`](https://github.com/allme-sdk/example-test-suite). The point is
teaching: each scenario's handler calls the SDK's intended top-level surface, so a reader opens a
family's handler file and sees exactly which SDK call implements each flow.

> This is its **own npm sub-project** — not separately published, though its source ships inside the SDK's npm package (#493). It is a local developer
> demo, not a production service.

## Prerequisites

- **Node.js 18+** and **npm** on your PATH.
- **`tar`** on your PATH (used once to unpack the fetched frontend bundle).
- The **SDK built to `dist/`.** The example consumes the SDK through its published `exports` map, so
  the SDK must be built first. An installed package already is — from a clone, run
  `npm install && npm run build` in the SDK repo root.

## Get it and run it

The shortest path is the package manager: this suite ships **inside** the published
`@allus-fyi/company-data` package, so installing the SDK also gets you the example.

```bash
npm install @allus-fyi/company-data
cd node_modules/@allus-fyi/company-data/examples
npm install                           # installs tsx + the OIDC library, links the SDK from ..
npm start                             # -> serves http://localhost:8091
```

Or from a clone of the SDK repository:

```bash
git clone https://github.com/allus-fyi/company-data-typescript
cd company-data-typescript
npm install && npm run build          # build the SDK to dist/ (what the example imports)

cd examples
npm install                           # installs tsx + the OIDC library, links the SDK from ..
npm start                             # -> serves http://localhost:8091
```

`npm start` runs `bin/start.ts` (via [`tsx`](https://github.com/privatenumber/tsx) — no build step for
the example), which wipes `.runtime/` (fresh state every boot), fetches and **sha256-verifies** the
pinned frontend release named in `frontend.lock` into `.frontend/` (a present, verified bundle is a
cache hit), checks the bundle's `contract.json` version against the backend's, refuses a busy port with
a clear message, then serves **the whole example test suite — all three scenario families — on port
8091, bound to all interfaces**, printing every URL it is reachable on.

Then open <http://localhost:8091> and pick a scenario.

**From a phone or another machine on the same network.** The server binds **all
interfaces**, so any device on your network can reach it — startup prints the exact
`http://<your-lan-ip>:8091` URL to type, alongside the localhost one. Open that URL on
the phone and press **Save** there: the redirect URI written into the config file
follows the origin you used, so register the same `http://<your-lan-ip>:8091/callback`
on your OAuth app. Binding all interfaces also means **anyone on your network can reach
this demo**, and its setup panels accept and store real credentials under
`.runtime/config/` — OAuth and data-client secrets, private-key PEMs and their
passphrases, and webhook signing secrets. It is a local developer example, not a
hardened service: run it only on a network you trust, and only with sandbox
credentials.

**Moving a whole setup to that phone — Save all / Restore all.** Typing every
scenario's setup again on the second device is the tedious part, so the sidebar
carries two buttons above **Clear all**: **Save all** stores this browser's whole
setup on the backend, and **Restore all** loads it into another browser pointed at
the same backend. The backend keeps it as an opaque blob and never runs anything
off it; it lives with the rest of `.runtime/`, so a restart or **Clear all** drops
it. After restoring, press **Save** in each scenario you want to run — that is what
writes its config file here, with this device's own redirect URI.

**`localhost` and `127.0.0.1` are different origins.** Whichever address you open the
example on is the one the backend registers as the redirect URI — it never substitutes
a default — so open the example on the address you registered and stay on it for the
whole round-trip. Registering both spellings on the OAuth app makes either one work,
but that is a convenience, not a remedy for switching mid-flow: the browser also keeps
your saved setup per origin, so a flow that returns to the other spelling lands on a
page whose stored settings are simply not there.

**Port.** `8091` is the default, overridable with `PORT=<n> npm start`. The default is deliberately the
same across all SDK examples (one browser origin ⇒ your localStorage setup carries across SDKs), so
only one example runs at a time.

## Where the SDK calls live

Open the handler for a family and every SDK call is right there:

- `src/handlers/identity.ts` — the identity scenarios (ids 1–5, 7–8)
- `src/handlers/flow.ts` — the contract-flow scenario (`flow:run`)
- `src/handlers/companyData.ts` — the company-data scenarios (`companydata:*`)

Everything else in `src/` is shared scaffolding (routing, config-file state, the run store, the static
bundle server) — not the SDK example.

### Identity — what each scenario calls

| # | Scenario | SDK / library calls |
|---|----------|---------------------|
| 1 | Sign in — redirect | `OAuthClient.fromConfig` → `authorizeUrl('signin', …)` → (`/callback`) `completeSignIn` |
| 2 | Sign in — detached | `authorizeUrl('signin', {responseMode:'detached'})` → (`/api/runs`) `pollResult` → `completeSignIn` |
| 3 | One-time claims | `authorizeUrl('one_time', {claims})` → `completeSignIn` (decrypts values with the config'd app key) |
| 4 | Connect (stay-connected) | `authorizeUrl('connect', …)` → `completeSignIn`, then `Client.connections()` for LIVE values |
| 5 | OIDC login | `openid-client`: `discovery` → `buildAuthorizationUrl` (PKCE) → `authorizationCodeGrant` (id_token verified) |
| 7 | 2FA at consent — **GUIDE** | no `/start`; a checklist + links to scenarios 1 & 5 where the 2FA prompt is observed |
| 8 | Standalone service-2FA + enroll | `Client.twoFactor.challenge` → `waitForResult`; `/enroll` runs `authorizeUrl('2fa_enroll', …)` (redirect & detached) |

### Flow — what the scenario calls

| Step | SDK calls |
|------|-----------|
| **Trigger** (`/start`) | `Client.fromConfig` → `requestFields()` (resolve flow name + version → flow id) → `identity()` (company party) → `connections()` (resolve share code → person party) → `triggerFlowRun(flowId, {connectionId, bindings})` |
| **Drive** (`/api/runs` poll, company turn) | `flowRun()` → `processFlowRun(flowRunId, fillNode)` — the `email` field is filled invalid once (`ValidationError` → ✗), then valid (→ ✓) |
| **Wait** (person's turn) | `flowRun()` reports `awaiting_<person party>` → the run sits in `waiting_person`; the next poll resumes automatically |
| **Complete** (run `completed`) | `flowRunAnswers()` (decrypted `{slug: value}`), plus `flowRunDocument()` for the `document` fixture |

The flow ships **two importable fixtures** in `fixtures/` — `info-gathering.zip` (`data_only`: a few
company steps incl. an email validation-demo step, then a person turn) and `contract.zip` (`document`:
a company step then a signature leaf that generates a document). Import the one you pick into the
portal (service settings → Flows → Import) and publish it.

### Company-data — what each scenario calls

| Scenario | SDK call(s) | Result |
|---|---|---|
| `companydata:read` | `Client.connections()` | `{connections:[{connectionId, personId, displayName, customerType, shareCode, values:[{slug,value,live,at}]}]}` — grouped by connection |
| `companydata:definitions` | `Client.requestFields()` | `{fields:[{slug,label,type,mandatory,one_time}]}` |
| `companydata:changes` | `Client.processChanges()` | `{events:[…], drained:true}` — crash-safe pump drain, idempotent on `Change.id` |
| `companydata:webhook` | `Client.verifyWebhook()` + `Client.parseWebhook()` (public `POST /webhook`) + `Client.drainBatch()` (feed fallback) | `{webhookId, events:[{source,…}], unparseable?}` — accumulating |
| `companydata:documents` | `Client.createDocument()` per selected type (six offered, all ticked by default) | `{docs:[{index,label,document_id,status}]}` |

## Setting up a scenario (the portal)

Every scenario's setup checklist names the exact portal steps, and a table beneath it gives
**the intended value for every control on each portal form it sends you to** — including the ones
to leave alone. Do them at **<https://portal.allus.fyi>**.
In short: register a **data client** (client_credentials) for the service (its whitelist auto-grants
`/api/company-data/*`), create/reuse the **service** and download its **private key (PEM)** (it
decrypts values, answers, and documents), then in the browser fill the scenario's setup panel and
**Save**. The advanced **API url** defaults to the deployed platform (`https://api.allme.fyi`) — no
environment setup. A physical phone with the allme app, signed in as the connected demo person, is
needed for the person-side steps (sign-in prompts, the flow's person turn + signature).

### The webhook scenario — set up first, tunnel optional

`companydata:webhook` needs its setup done **before you run it**: register the webhook in the portal so
you have a **webhook id** and its **HMAC secret**, enter both in the setup panel and **Save** (the id
is the routing key; the secret verifies deliveries). Then **Run** it — it starts an **accumulating**
run and collects events two ways:

1. **Feed fallback (always works locally).** Each `GET /api/runs` poll does ONE `Client.drainBatch()`
   raw feed fetch, appending `{source:"feed",…}` events deduped on `Change.id`. No tunnel required.
2. **`POST /webhook`** (public inbound delivery — the **optional** live path). To receive real-time
   deliveries on your laptop you expose this server's `/webhook` through a tunnel and point the portal
   webhook at it. `verifyWebhook()` false → **401**; a verified delivery is parsed and appended → **200**
   (a verified-but-unparseable one is acknowledged **200** and counted in `unparseable`).

## How it works (contract v3)

- **One server, one port, all three families.** A single Node `http` process serves the static bundle,
  the whole contract API, the identity OAuth `/callback`, and the public company-data `POST /webhook`.
  `GET /api/meta` lists all 13 scenarios (7 identity + 1 flow + 5 company-data) at `contractVersion 3`.
  A scenario request is dispatched to its family by id (integers → identity, `flow:*` → flow,
  `companydata:*` → company-data).
- **Config-file model.** `POST /api/scenarios/{id}/config` writes the browser's settings to a canonical
  SDK config file at `.runtime/config/{id}.json` (any PEM → `.runtime/config/keys/` at `0600`,
  referenced by path; demo-only params → `{id}.meta.json`). `POST …/start` (and identity's `…/enroll`)
  **ignore their body** and build the SDK OFF that file via the role-appropriate file constructor
  (`OAuthClient.fromConfig`/`Config.fromIdwFile`, `Client.fromConfig`/`Config.fromFile`) — exactly as a
  real integrator wires the SDK. No saved config → `409 {"error":"not_configured"}`. Config files are
  keyed per scenario id, so the three families share ONE `.runtime/` without colliding.
- **Idempotent, poll-driven runs.** `GET /api/runs/{runId}` returns `{status, result?, error?, calls}`.
  Detached/challenge (identity) and the flow drive loop advance ONE short-cycled SDK step per poll;
  outcomes are returned on every poll until a 30-minute TTL or a Clear (no burn-on-read).
- **Single worker.** Node's built-in `http` server is one process — requests serialize, so there are
  no locks/tombstones. State lives under `.runtime/` (git-ignored, wiped at startup). Config files are
  configuration, not runs: removed only by Clear or the startup wipe.
- **Pinned frontend.** `frontend.lock` pins the release `tag` + `sha256`; the launcher fetches that
  asset cache-first, verifies the checksum, unpacks to `.frontend/<tag>/`, and refuses on a checksum or
  `contract.json` version mismatch.

## Layout

```
examples/
├── package.json          # one manifest (the SDK via file:.., openid-client); npm start
├── tsconfig.json         # one strict tsconfig (tsc --noEmit typechecks the whole example)
├── frontend.lock         # ONE pinned {tag, sha256} of the shared frontend bundle (contract v3)
├── fixtures/             # the two importable flow packages (portal-export zips)
├── bin/start.ts          # launcher (wipe → fetch+verify bundle → contract guard → serve)
└── src/
    ├── server.ts         # the router: /api/meta, config/start/enroll/clear/runs, /api/state, /callback, /webhook, static
    ├── runtime.ts        # .runtime/ file state (config files, runs, key PEMs, webhook route, pump cache, TTL)
    ├── http.ts           # shared HTTP plumbing (static bundle server, JSON/text responders, body readers)
    ├── pkce.ts           # PKCE verifier/challenge for the SDK OAuth scenarios
    ├── timeoutTransport.ts # short-timeout HttpTransport for the short-cycled polls / feed fetch
    └── handlers/
        ├── identity.ts   # the identity scenarios (calls the SDK OAuth / OIDC / 2FA surface)
        ├── flow.ts       # the contract-flow scenario (calls the SDK flow surface)
        └── companyData.ts # the company-data scenarios (calls the service-role data Client)
```

`npm run typecheck` runs `tsc --noEmit`.

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the ONE pin lives in `frontend.lock` (`{tag,
sha256}`). To move to a newer release: note the release **tag** and its `dist.tar.gz` checksum
(`shasum -a 256 dist.tar.gz`) from `github.com/allme-sdk/example-test-suite`, set `tag` + `sha256` in
`frontend.lock`, `rm -rf .frontend/`, then `npm start` — it re-fetches, verifies the checksum, and
checks the bundle's `contract.json` version against the backend (a mismatch refuses loudly).

## Troubleshooting

| Symptom | Fix |
|---|---|
| **`port 8091 is busy`** at startup | Another example holds the port — one origin is shared across SDK examples, so only one runs at a time. Stop it, or `PORT=<n> npm start`. |
| **`contract mismatch: bundle contractVersion=… backend implements …`** | The pinned bundle's `contract.json` version differs from this backend (v3). Bump `frontend.lock` to a matching release (and re-fetch), or update the backend. |
| **`frontend checksum MISMATCH`** | The downloaded `dist.tar.gz` doesn't match `frontend.lock`'s `sha256`. Fix the `sha256` (from `shasum -a 256 dist.tar.gz` on the real release) or re-download. |
| **`could not download the pinned frontend release`** | The release isn't published yet, or no network. If unpublished, seed the bundle into `.frontend/<tag>/` manually (build `example-test-suite`, `tar -xzf dist.tar.gz -C .frontend/<tag>`, `printf %s <sha> > .frontend/<tag>/.sha`). |
| **Cannot find module `@allus-fyi/company-data`** | Build the SDK first (`npm run build` in the SDK repo root) — the example imports it through `dist/`. |
| **`start_failed`** naming a missing flow (flow) | The flow name or published version doesn't match a flow on this service — check the spelling against the portal's flow list and the "Published vN" it shows next to it. |
| **`start_failed`** naming more than one matching flow (flow) | Two flows on this service share the same name AND published version — rename one of them (the flow builder's name field) so the pair is unique, then try again. |
| **`connection_error`** naming a missing connection (flow) | The share code is wrong, or the person isn't connected to this service yet. |
