# Output model reference

The conclusions — the only objects you work with. Importable from
`@allus/company-data`. Each carries `.raw` (the underlying hardened API object;
never contains the person's source field).

## `RequestField`

Your request-field **definition** — your config, never the person's fields.
Returned by `client.requestFields()`.

```ts
class RequestField {
  slug: string;        // the stable, company-set key — the contract for value access
  label: string;       // the human label (rename freely; the slug stays)
  type: string;        // email|phone|url|text|address|bank|creditcard|date|date_of_birth|photo|document|legal_document
  oneTime: boolean;    // a one-time snapshot vs a live (auto-updating) answer
  mandatory: boolean;  // mandatory-to-provide OR mandatory-to-stay-connected (the API's two flags, folded)
  raw: Record<string, unknown>;
}
```

## `Connection`

A connected person — identity + the slug-keyed value map. No source field
anywhere; `values` is keyed by **your** request slug.

```ts
class Connection {
  id: string;
  personId: string;
  displayName: string | null;      // null on connection(id) (the list endpoint carries it)
  connectedAt: Date | null;        // likewise null on connection(id)
  values: Record<string, Value>;   // {<your_slug>: Value}
  raw: Record<string, unknown>;
}
```

```ts
conn.values['work_email'].value     // "alice@acme.com"
conn.values['mobile']                // undefined if the person didn't answer that slot
```

## `Value`

One answer for one of your request slots.

```ts
class Value {
  value: unknown;            // typed plaintext (see below)
  live: boolean;             // true = "keep connected" (auto-updates); false = one-time snapshot
  updatedAt: Date | null;    // when this answer last changed
  raw: Record<string, unknown>;
}
```

### `value` types (resolved from the field's `type`)

| Field type | JS `value` | Notes |
|------------|------------|-------|
| `email`, `phone`, `url`, `text` | `string` | The decrypted plaintext. |
| `address`, `bank`, `creditcard` | `object` | The decrypted plaintext is a JSON object → parsed. A non-JSON structured value throws `DecryptError`. |
| `date`, `date_of_birth` | `Date` | Parsed from ISO `YYYY-MM-DD` (UTC midnight, the leading 10 chars); falls back to the raw string if unparseable. |
| `photo`, `document`, `legal_document` | `BinaryHandle` | Lazy — nothing fetched/decrypted until `.bytes()`/`.save()`. |
| unanswered / no value | `null` | The slot has no answer. |

## `BinaryHandle`

A lazy handle for a binary value. No network or decryption happens at construction.

```ts
class BinaryHandle {
  get valueUrl(): string | null;        // the opaque slot-keyed file URL (read-only)
  bytes(): Promise<Buffer>;             // fetch (if needed) → decrypt → decoded primary file bytes
  save(path: string): Promise<number>;  // write bytes() to path; resolves to bytes written
  static parseEnvelopeBytes(envelopeJson: string): Buffer;  // envelope string → file bytes
}
```

On first `.bytes()`/`.save()`:

1. GET the slot-keyed file endpoint → the API serves `{"encrypted": true, "value": <wrapper>}`.
2. Decrypt the inner `{"_enc":1,…}` wrapper with the service key → a JSON file-envelope string (`{"full": "data:…", "thumb": …}` for photos, `{"file": "data:…", …}` for documents).
3. Base64-decode the primary data URI (`full` for photos, `file` for documents) → a `Buffer`. Cached on the handle (repeated calls don't re-fetch).

`.save()` is crash-safe (temp file → fsync → atomic rename — never a truncated
output). An unanswered binary slot yields an empty handle; calling `.bytes()` on it
throws `DecryptError`.

## `Change`

A change-feed / webhook event. Returned by the pump (`processChanges`, `drainBatch`)
and the webhook helpers.

```ts
class Change {
  id: string;                 // the stable server change-row id — YOUR dedup key
  event: string;              // see the event table
  personId: string | null;
  slug: string | null;        // field_updated/field_deleted/consent_* only
  value: unknown;             // field_updated only; typed exactly like Value.value
  live: boolean | null;       // field_updated only
  at: Date | null;            // the change time (no separate updatedAt on a change)
  raw: Record<string, unknown>;
}
```

### Events

| `event` | Carries |
|---------|---------|
| `connection_created` | identity only (no slot/value) |
| `connection_deleted` | identity only (no slot/value) |
| `field_updated` | `slug` + decrypted `value` (+ `live`); binary → a lazy `BinaryHandle` |
| `field_deleted` | `slug`, no value |
| `consent_accepted` / `consent_declined` | `slug` |

`Change.id` is captured before the server's drain-delete, so it survives a crash +
replay unchanged — dedup on it.

## `LogEntry`

A service activity-log entry — ops events only (email / purge / webhook), never
person field data.

```ts
class LogEntry {
  type: string;
  message: string | null;
  metadata: unknown;
  at: Date | null;
  raw: Record<string, unknown>;
}
```

## `.raw`

Every model has a `.raw` property: the underlying (hardened) API object, for
debugging or an edge case the SDK didn't model. It never contains the person's
source field — the hardened API doesn't return it.
