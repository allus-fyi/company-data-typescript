# Flow example — run a contract flow (TypeScript SDK)

A runnable website that demonstrates a **contract flow** end-to-end through the
`@allus-fyi/company-data` **TypeScript SDK**: trigger a flow run, drive the company
party through it with type-checked step filling, hand a turn to the person's phone,
and on completion read the decrypted answers and — for the contract fixture —
download the generated signed document. Like the
[identity example](../identity/), ~90 % of the UI is a shared frontend fetched from a
pinned release; this directory is the thin TypeScript backend that implements the
[demo-backend contract](https://github.com/allme-sdk/example-test-suite)
(`CONTRACT.md`, flow family — contract v2).

Everything the handler does goes through the SDK's **intended top-level flow
functions** — `identity()`, `triggerFlowRun()`, `flowRun()`, `processFlowRun()`,
`flowRunAnswers()`, `flowRunDocument()` — never internals, never raw platform HTTP.

> This is its **own npm sub-project**, excluded from the published SDK package. It is a
> local developer demo, not a production service.

---

## Run it — one command

```bash
npm install     # links the SDK from ../.. (file: dependency)
npm start       # fetches + verifies the pinned frontend, then serves http://localhost:8091
```

`npm start` runs `bin/start.ts` (via [`tsx`](https://github.com/privatenumber/tsx) —
no build step for the example), which wipes `.runtime/` (fresh state every boot),
fetches + **sha256-verifies** the pinned frontend release named in `frontend.lock`
into `.frontend/` (a present, verified bundle is a cache hit), checks the bundle's
`contract.json` version against the backend's, refuses a busy port with a clear
message, then serves `http://localhost:8091` — a **single-worker** Node `http`
server.

The SDK is consumed through its published `exports` map (`dist/`), so the SDK must be
**built** first (`npm run build` in the SDK repo root) — the normal state of an
installed package.

Open **http://localhost:8091** and pick the **Run a contract flow** scenario. From
there the browser and the allus portal are the only surfaces you touch. The
scenario's **Save** button POSTs your settings to the backend, which writes them to a
canonical SDK **config file** (`.runtime/config/1.json`, the service PEM under
`.runtime/config/keys/`) — the same shape a real integrator wires by hand. The panel
shows the written path so you can open and read the real config; **Trigger** then
builds the SDK from that file (`Client.fromConfig`) and runs off it. You still never
hand-create or edit the file — the backend writes it from your browser inputs; it is
there to be read.

**Port.** `8091` is the default, overridable with `PORT` (e.g. `PORT=8092 npm
start`). The default is deliberately the **same across all six SDK examples** (one
browser origin ⇒ your localStorage setup carries across SDKs) — the documented
consequence is that only one example runs at a time.

**Requirements:** Node ≥ 18, and `tar` on `PATH` (used to unpack the fetched frontend
bundle).

---

## The scenario — set up, then run

A contract flow is a company-authored graph of steps. The demo ships **two fixtures**
you import into the portal (`fixtures/`):

| Fixture zip | Shape |
|---|---|
| `fixtures/info-gathering.zip` | `data_only` — a few company steps (text, an **email** validation-demo step, an address composite) then one person turn. |
| `fixtures/contract.zip` | `document` — a company step, then a signature leaf that generates a document. |

The scenario's setup checklist names the exact portal steps. In short:

1. In the **allus portal**, register a **data client** (client_credentials) for the
   service — its whitelist auto-grants `/api/company-data/*`. Create/reuse the
   **service** and download its **private key (PEM)** (it decrypts the answers +
   document).
2. **Import** the chosen fixture zip (service settings → Flows → Import) and
   **publish** the imported flow.
3. In the browser, enter the data-client id/secret, pick the service PEM + its
   passphrase, enter the **published flow id** and the target **connection id**, and
   pick the same **fixture** you imported. **Save**, then **Trigger the flow run**.

What you then observe:

- The **flow-run log** accumulates one row per company step as the SDK drives it: the
  `email` step is submitted once with a bad value → rejected (the SDK's
  `ValidationError`, shown ✗), then re-submitted valid → accepted ✓. The other steps
  submit valid and advance.
- When the flow reaches the person's turn it shows **"waiting — answer on your
  phone"**; polling resumes automatically once the person answers (and, for the
  contract fixture, **signs**) in the allme app.
- On completion the **decrypted answers** appear, and for the contract fixture the
  **document** is downloaded via `flowRunDocument()`.
- **"What just happened"** lists the exact SDK methods the run called.

> **Phone required.** The person's turn — and the contract fixture's signature — are
> completed on a **physical phone** with the allme app, signed in as the connected
> demo person (project practice: physical devices).

---

## What the scenario calls (contract v2)

| Step | SDK calls |
|------|-----------|
| **Trigger** (`/start`) | `Client.fromConfig` → `identity()` (company party) → `connection()` (person party) → `triggerFlowRun(flowId, {connectionId, bindings})` |
| **Drive** (`/api/runs` poll, company turn) | `flowRun()` → `processFlowRun(flowRunId, fillNode)` — the `email` field is filled invalid once (`ValidationError` → ✗), then valid (→ ✓) |
| **Wait** (person's turn) | `flowRun()` reports `awaiting_<person party>` → the run sits in `waiting_person`; the next poll resumes automatically |
| **Complete** (run `completed`) | `flowRunAnswers()` (decrypted `{slug: value}`), plus `flowRunDocument()` for the `document` fixture |

- **Config-file model.** `POST /api/scenarios/flow:run/config` writes the browser's
  settings to a canonical SDK config file at `.runtime/config/1.json` (the service PEM
  → `.runtime/config/keys/` at `0600`, referenced by path; demo-only params —
  `flow_id`, `connection_id`, `fixture` — → `1.meta.json`). `POST …/start` **ignores
  its body** and builds the SDK OFF that file via `Client.fromConfig` — exactly as a
  real integrator wires the SDK. No saved config → `409 {"error":"not_configured"}`.
- **The platform run lives inside the demo run.** `/start` stores the platform
  `flowRunId` inside the demo run file and returns `{runId, action:{type:"none"}}`;
  there is no separate flow-run-id browser input.
- **Idempotent, poll-driven runs.** `GET /api/runs/{runId}` returns the shared
  envelope `{status:"pending"|"done"|"failed", result, calls, error?}` with the flow
  shape nested under `result` (`{status, steps, answers?, document?}`). Each poll is
  the drive loop and the resume — it drives exactly ONE company step or reports
  waiting. Outcomes are returned on every poll until a 30-minute TTL or a Clear (no
  burn-on-read).
- **Single worker.** Node's built-in `http` server is one process — requests
  serialize, so there are no locks/tombstones. State lives under `.runtime/`
  (git-ignored, wiped at startup).
- **Pinned frontend.** `frontend.lock` pins the flow-family bundle's release `tag` +
  `sha256`; the launcher fetches that asset cache-first, verifies the checksum,
  unpacks to `.frontend/<tag>/`, and refuses on a checksum or `contract.json` version
  mismatch.

---

## Default target — the deployed AWS platform

The scenario's advanced input (**API url**) defaults to the deployed platform
(`https://api.allme.fyi`) — **no environment setup**. You register the data client,
create the service, and import + publish the flow in the **allus portal at
`portal.allus.fyi`**.

> **Portal prerequisite / interim (2026-07-24).** `portal.allus.fyi` is **not deployed
> yet**. Until it lands, the documented interim is to run the **local portal UI
> against the cluster API**: set `VITE_API_URL=https://api.allme.fyi` in `allus/.env`
> and start the portal locally (it proxies `/api` to that URL), so every portal step
> still lands on the same deployed platform the run executes against. A physical phone
> with the allme app reaches the deployed platform naturally.

---

## Secondary target — a local stack

Running against a **local stack** is a documented secondary option (see
`docs/reference/software.html`). In the browser, switch the advanced **API url** to
`http://localhost:8070`; no file in **this** example changes. The phone must be able
to reach the local API (project practice: `adb reverse tcp:8070 tcp:8070` on Android,
or the machine's LAN address).

---

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the pin lives in `frontend.lock`
(`{tag, sha256}`). This example pins the **flow family bundle (contract v2)**. To move
to a newer release: note the release **tag** and its `dist.tar.gz` checksum
(`shasum -a 256 dist.tar.gz`) from `github.com/allme-sdk/example-test-suite`, set
`tag` + `sha256` in `frontend.lock`, `rm -rf .frontend/`, then `npm start` — it
re-fetches, verifies the checksum, and checks the bundle's `contract.json` version
against the backend (a mismatch refuses loudly). A pin bump is a **per-example
commit**.

---

## Layout

```
examples/flow/
├── package.json          # own manifest (the SDK via file:../..); npm start
├── tsconfig.json         # own strict tsconfig (tsc --noEmit typechecks the example)
├── frontend.lock         # pinned {tag, sha256} of the flow-family frontend bundle
├── bin/start.ts          # one-command launcher (wipe → fetch+verify bundle → contract guard → serve)
├── fixtures/             # the two importable flow packages (portal-export zips)
└── src/
    ├── server.ts         # the contract v2 flow:run dispatch + handlers (calls the SDK flow surface)
    └── runtime.ts        # .runtime/ file state (config file, run stash, key PEM, TTL sweep, clear)
```

`npm run typecheck` runs `tsc --noEmit`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **`port 8091 is busy`** at startup | Another example holds the port — one origin is shared across SDK examples, so only one runs at a time. Stop it, or `PORT=<n> npm start`. |
| **`contract mismatch: bundle contractVersion=… backend implements …`** | The pinned bundle's `contract.json` version differs from this backend (flow = v2). Bump `frontend.lock` to a matching release (and re-fetch), or update the backend. |
| **`frontend checksum MISMATCH`** | The downloaded `dist.tar.gz` doesn't match `frontend.lock`'s `sha256`. Fix the `sha256` (from `shasum -a 256 dist.tar.gz` on the real release) or re-download. |
| **`could not download the pinned frontend release`** | The `v0.2.0` release isn't published yet, or no network. If unpublished, seed the bundle into `.frontend/<tag>/` manually (build `example-test-suite`, `tar -xzf dist.tar.gz -C .frontend/<tag>`, `printf %s <sha> > .frontend/<tag>/.sha`). |
| **`start_failed`** naming a missing connection / person | The connection id is wrong or the person isn't connected to the service — check the connection in the portal. |
