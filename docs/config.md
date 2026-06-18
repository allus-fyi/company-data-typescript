# Config reference

`Config` (`import { Config } from '@allus/company-data'`).

A single JSON file holds the whole SDK configuration. **Config-only key handling is
a hard rule:** no SDK method ever takes a key, passphrase, or secret as an argument
— everything cryptographic (decrypting the service PEM, decrypting field values,
verifying the webhook HMAC, unwrapping the account-key envelope) is driven entirely
by this config. Your only key responsibility is putting the right values here.

The config-file keys are **snake_case**; the SDK exposes them as **camelCase**
properties.

## Fields

| File key | Property | Type | Required | Default | Meaning |
|----------|----------|------|----------|---------|---------|
| `api_url` | `apiUrl` | string | yes | — | API base, e.g. `https://api.allme.fyi`. |
| `client_id` | `clientId` | string | yes | — | The `client_credentials` client id (scoped to one service). |
| `client_secret` | `clientSecret` | string | yes | — | The client secret. |
| `service_private_key` | `servicePrivateKey` | string | yes | — | Path to the OpenSSL-encrypted PKCS#8 PEM (downloaded from the portal). |
| `key_passphrase` | `keyPassphrase` | string | yes | — | Decrypts the service PEM in memory at startup. |
| `account_private_key` | `accountPrivateKey` | string \| null | no | `null` | Path to the company **account** key PEM — only needed to receive `encrypt_payload` webhooks. |
| `account_passphrase` | `accountPassphrase` | string \| null | no | `null` | Decrypts the account PEM. |
| `webhooks` | `webhooks` | object | no | `{}` | Per-webhook HMAC secrets, keyed by webhook id (matched via the `X-Allus-Webhook-Id` header). |
| `cache_dir` | `cacheDir` | string | no | `"./allus-cache"` | Durable local buffer dir for the changes pump. Must be writable + durable. |
| `format` | `format` | `"json"` \| `"xml"` | no | `"json"` | Wire format. Invisible in the output. |

The PEM is PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC, 100k iters); it is decrypted in
memory at construction (`crypto.createPrivateKey({ key, passphrase })`) and never
written back to disk in plaintext.

## Constructors

```ts
Config.fromFile(path: string): Config     // load JSON; ALLUS_* env vars override file values
Config.fromEnv():              Config      // build entirely from ALLUS_* env vars
```

In practice you build the client directly:

```ts
import { Client } from '@allus/company-data';
const client = Client.fromConfig('allus.json');   // == new Client(Config.fromFile('allus.json'))
const client2 = Client.fromEnv();                  // == new Client(Config.fromEnv())
```

## Env overrides

Every scalar field can be overridden by its `ALLUS_*` env var (so secrets needn't
live in the file). An env value, when set, wins over the file value.

| Property | Env var |
|----------|---------|
| `apiUrl` | `ALLUS_API_URL` |
| `clientId` | `ALLUS_CLIENT_ID` |
| `clientSecret` | `ALLUS_CLIENT_SECRET` |
| `servicePrivateKey` | `ALLUS_SERVICE_PRIVATE_KEY` |
| `keyPassphrase` | `ALLUS_KEY_PASSPHRASE` |
| `accountPrivateKey` | `ALLUS_ACCOUNT_PRIVATE_KEY` |
| `accountPassphrase` | `ALLUS_ACCOUNT_PASSPHRASE` |
| `cacheDir` | `ALLUS_CACHE_DIR` |
| `format` | `ALLUS_FORMAT` |
| flat single-webhook secret | `ALLUS_WEBHOOK_SECRET` |

## Webhook secrets

```json
"webhooks": { "wh_abc123": "secret_a", "wh_def456": "secret_b" }
```

Keyed by webhook id; the SDK reads `X-Allus-Webhook-Id` off the incoming request
and looks up the matching secret. A service with a single webhook can use the flat
shortcut instead of the map:

```json
"webhook_secret": "the_one_secret"
```

(stored internally under a reserved key `Config.SINGLE_WEBHOOK_KEY` and used as the
fallback when there is no id-specific match). `ALLUS_WEBHOOK_SECRET` overrides the
flat shortcut.

`config.webhookSecret(webhookId?)` resolves the secret for an id (falling back to
the single-webhook shortcut). The webhook helpers call this for you — you never
pass a secret in. **The method takes a webhook *id*, never a secret.**

## Validation

* A missing required field (`api_url`, `client_id`, `client_secret`, `service_private_key`, `key_passphrase`) throws `ConfigError` listing the missing **config-file keys**.
* A `format` other than `json`/`xml` throws `ConfigError`.
* A malformed/missing config file throws `ConfigError`.
* An unreadable `service_private_key` PEM, or a wrong `key_passphrase`, throws `ConfigError` at `Client` construction (fail fast — a bad key is a config problem, not a runtime decrypt error).
