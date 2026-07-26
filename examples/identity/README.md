# Identity example — allus company-data TypeScript SDK

A runnable demo of every **identity** scenario the SDK supports —
"Sign in with allme" (redirect + detached), one-time claims, stay-connected,
standard **OIDC** login (the #314 compliance surface, via the `openid-client`
library), OIDC-continue-on-phone, and standalone **service-2FA** with enrollment.

It is a thin backend implementing the shared **demo-backend contract v1**; ~90 % of
the UI is the shared frontend bundle fetched from
[`allme-sdk/example-test-suite`](https://github.com/allme-sdk/example-test-suite).
The point of the example is teaching: each scenario's handler calls the SDK's
intended top-level surface, so a reader sees exactly which SDK call implements each flow.

> This is its **own npm sub-project**, excluded from the published SDK package. It is a
> local developer demo, not a production service.

## Run it

```bash
git clone https://github.com/allus-fyi/company-data-typescript
cd company-data-typescript/examples/identity
npm install     # installs the OIDC library + links the SDK from ../.. (file: dependency)
npm start       # fetches + verifies the pinned frontend, then serves on http://localhost:8091
```

`PORT=<n> npm start` uses another port. The default `8091` is shared across every SDK
example on purpose (one browser origin → the localStorage setup carries across SDKs), so
only one example runs at a time.

The SDK is consumed through its published `exports` map (`dist/`), so the SDK must be
**built** first (`npm run build` in the SDK repo root) — the normal state of an installed
package.

## What each scenario calls

| # | Scenario | SDK / library calls |
|---|----------|---------------------|
| 1 | Sign in — redirect | `OAuthClient.fromConfig` → `authorizeUrl('signin', …)` → (`/callback`) `completeSignIn` |
| 2 | Sign in — detached | `authorizeUrl('signin', {responseMode:'detached'})` → (`/api/runs`) `pollResult` → `completeSignIn` |
| 3 | One-time claims | `authorizeUrl('one_time', {claims})` → `completeSignIn` (decrypts values with the config'd app key) |
| 4 | Connect (stay-connected) | `authorizeUrl('connect', …)` → `completeSignIn`, then `Client.connections()` for LIVE values |
| 5 | OIDC login | `openid-client`: `discovery` → `buildAuthorizationUrl` (PKCE) → `authorizationCodeGrant` (id_token verified) |
| 6 | OIDC — continue on phone | same as 5; completion via the phone's redirect leg |
| 7 | 2FA at consent — **GUIDE** | no `/start`; a checklist + links to scenarios 1 & 5 where the 2FA prompt is observed |
| 8 | Standalone service-2FA + enroll | `Client.twoFactor.challenge` → `waitForResult`; `/enroll` runs `authorizeUrl('2fa_enroll', …)` (redirect & detached) |

## How it works (contract v1)

- **Config-file model.** `POST /api/scenarios/{id}/config` writes the browser's settings to a
  canonical SDK config file at `.runtime/config/{id}.json` (any PEM → `.runtime/config/keys/`
  at `0600`, referenced by path; demo-only params → `{id}.meta.json`). `POST …/start` and
  `POST …/enroll` **ignore their body** and build the SDK OFF that file via the role-appropriate
  file constructor (`OAuthClient.fromConfig`/`Config.fromIdwFile`, `Client.fromConfig`/`Config.fromFile`)
  — exactly as a real integrator wires the SDK. No saved config → `409 {"error":"not_configured"}`.
- **`state == runId`.** The OAuth `state` is the run id; `GET /callback` (handles both
  `?code=&state=` and `?enrolled=true&state=`) finds the run, records the outcome, and 302s back
  to the card.
- **Idempotent, poll-driven runs.** `GET /api/runs/{runId}` returns `{status, result?, error?, calls}`.
  A pending detached/challenge run does ONE short-cycled SDK wait (`timeout=2` + a 2 s abort transport);
  the SDK's logical "not completed within Ns" → still pending, a real transport failure → failed.
  Outcomes are returned on every poll until a 30-minute TTL or a Clear (no burn-on-read).
- **Single worker.** Node's built-in `http` server is one process — requests serialize, so there are
  no locks/tombstones. State lives under `.runtime/` (git-ignored, wiped at startup).
- **Pinned frontend.** `frontend.lock` pins the release `tag` + `sha256`; the launcher fetches that
  asset cache-first, verifies the checksum, unpacks to `.frontend/<tag>/`, and refuses on a checksum
  or `contract.json` version mismatch.

## Layout

```
examples/identity/
├── package.json          # own manifest (openid-client + the SDK via file:../..); npm start
├── tsconfig.json         # own strict tsconfig (tsc --noEmit typechecks the example)
├── frontend.lock         # pinned {tag, sha256} of the shared frontend bundle
├── bin/start.ts          # launcher (wipe → fetch+verify bundle → contract guard → serve)
└── src/
    ├── server.ts         # the contract v1 dispatch + handlers (calls the SDK surface)
    ├── runtime.ts        # .runtime/ file state (config files, runs, key PEMs, TTL sweep, clear)
    ├── pkce.ts           # PKCE verifier/challenge for the SDK OAuth scenarios
    └── timeoutTransport.ts # short-timeout HttpTransport for the short-cycled polls
```

Run via [`tsx`](https://github.com/privatenumber/tsx) (no build step for the example);
`npm run typecheck` runs `tsc --noEmit`.
