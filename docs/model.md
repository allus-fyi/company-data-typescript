# Output model reference

The conclusions — the only objects you work with. Importable from
`@allus-fyi/company-data`. Each carries `.raw` (the underlying hardened API object;
never contains the person's source field).

## `RequestField`

Your request-field **definition** — your config, never the person's fields.
Returned by `client.requestFields()`.

```ts
class RequestField {
  slug: string;        // the stable, company-set key — the contract for value access
  label: string;       // the human label (rename freely; the slug stays)
  type: string;        // the field type — a row in the served registry, never a fixed list
  oneTime: boolean;    // a one-time snapshot vs a live (auto-updating) answer
  mandatory: boolean;  // mandatory-to-provide OR mandatory-to-stay-connected (the API's two flags, folded)
  verified: boolean;   // this row DEMANDS a verified answer (mutually exclusive with oneTime)
  verifiedMaxAgeDays: number | null;  // oldest verification accepted; null = no age limit
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
  verified: boolean;         // the hash recomputes over the plaintext AND the verification has not lapsed
  verifiedAt: Date | null;        // when the answering field was verified
  verifiedExpiresAt: Date | null; // when that verification lapses; null = it does not
  verifiedMethod: string | null;  // HOW allme bound it: email_code|sms_code|sumsub_id|sumsub_address
  verifiedProvider: string | null; // WHO established the proof: allme|sumsub
  verificationId: string | null;  // the proof id to quote back to allme in a dispute
  raw: Record<string, unknown>;
}
```

### `value` types — from the type's RESOLVED definition

A contact-field TYPE is a ROW in the served field-type registry (`GET /api/contact-field-types`),
which the client fetches beside the request-field catalog and holds for its life. A value's shape
follows the type's resolved storage LANE and PRIMITIVE, so a type added as a row types itself with
no SDK release.

| The type's resolved… | JS `value` | Notes |
|----------------------|------------|-------|
| storage lane `photo` / `document` | `BinaryHandle` | Lazy — nothing fetched/decrypted until `.bytes()`/`.save()`. |
| primitive `composite` | `object` | The decrypted plaintext is a JSON object → parsed. A non-JSON value throws `DecryptError`. |
| primitive `date` | `Date` | Parsed from ISO `YYYY-MM-DD` (UTC midnight, the leading 10 chars); falls back to the raw string if unparseable. |
| primitive `multilist` | `Array` | The chosen option strings, parsed from the JSON array. |
| anything else, and a type the registry does not carry | `string` | The decrypted plaintext. |
| unanswered / no value | `null` | The slot has no answer. |
For the seeded types that is, unchanged: `email`/`phone`/`url`/`text` and the three numeric types →
a string; `country`/`nationality` → an ISO 3166-1 alpha-2 code string; `address`/`bank`/`creditcard`
→ the parsed object; `date`/`date_of_birth` → the date type; `photo`, `document`,
`legal_document`, `passport`, `photo_id` and `drivers_license` → the lazy binary handle. A request
row of a PARENT type MAY be answered by a field of any DESCENDANT, but that matching happens in
the API: the answer still arrives keyed by YOUR slug and shaped by the SLOT's own type, because
the person's source field — and therefore its type — is never exposed. A binary slot's
slot → source → file resolution is likewise the API's.


## `BinaryHandle`

A lazy handle for a binary value. No network or decryption happens at construction.

```ts
class BinaryHandle {
  get valueUrl(): string | null;        // the opaque slot-keyed file URL (read-only)
  get contentType(): string | null;     // the Content-Type the bytes arrived with (after a fetch)
  get contentSha256(): string | null;   // the X-Allus-Content-Sha256 digest of those bytes
  bytes(): Promise<Buffer>;             // fetch (if needed) → the primary file bytes
  save(path: string): Promise<number>;  // write bytes() to path; resolves to bytes written
  static parseEnvelopeBytes(envelopeJson: string): Buffer;  // envelope string → file bytes
}
```

The file endpoint has **two 200 shapes**, decided by whether the person's source field
is private — the company cannot predict or control which arrives. On first
`.bytes()`/`.save()` the handle GETs the slot-keyed file endpoint and classifies the
response on its `Content-Type` (never by sniffing the body):

* **`application/json`, or no `Content-Type` at all** → the encrypted shape,
  `{"encrypted": true, "value": <wrapper>}`. Decrypt the inner `{"_enc":1,…}` wrapper with
  the service key → a JSON file-envelope string (`{"full": "data:…", "thumb": …}` for photos,
  `{"file": "data:…", …}` for documents), then base64-decode the primary data URI (`full`
  for photos, `file` for documents) → a `Buffer`.
* **any other `Content-Type`** (`image/jpeg`, `application/pdf`, …) → the plaintext shape:
  the body already IS the file. Nothing is decrypted, and a handle built without decrypt
  wiring still works.

A missing `Content-Type` deliberately falls through to the JSON path: mistaking a wrapper
for file bytes writes ciphertext to disk as if it were the document and nothing complains,
while mistaking bytes for a wrapper fails loudly at the parse.

Either way the result is cached on the handle (repeated calls don't re-fetch), and
`contentSha256` exposes the `X-Allus-Content-Sha256` digest of exactly the bytes returned.
There is no variant selection: one slot has one byte sequence and one digest.

`.save()` is crash-safe (temp file → fsync → atomic rename — never a truncated
output). An unanswered binary slot yields an empty handle; calling `.bytes()` on it
throws `DecryptError`. A frozen answer whose 90-day retention has elapsed answers **410**
`company_data.file_expired` — an `ApiError` whose `details` carry `content_sha256` and
`expired_at`.

## `Change`

A change-feed / webhook event. Returned by the pump (`processChanges`, `drainBatch`)
and the webhook helpers.

```ts
class Change {
  id: string;                 // the pull feed's server change-row id — your dedup key THERE only
  event: string;              // see the event table
  personId: string | null;
  shareCode: string | null;   // the person's profile share code (every event; may be null)
  slug: string | null;        // field_updated/field_deleted/consent_* only
  value: unknown;             // field_updated only; typed exactly like Value.value
  live: boolean | null;       // field_updated only
  connectionId: string | null;      // message_received only
  messageId: string | null;         // message_received only — the ack boundary
  personPublicKey: string | null;   // message_received only — base64 SPKI for the reply
  messageBody: string | null;       // message_received only — the DECRYPTED text
  verified: boolean;          // field_updated only; hash recomputes AND the verification has not lapsed
  verifiedAt: Date | null;        // when the answering field was verified
  verifiedExpiresAt: Date | null; // when that verification lapses; null = it does not
  verifiedMethod: string | null;  // HOW allme bound it: email_code|sms_code|sumsub_id|sumsub_address
  verifiedProvider: string | null; // WHO established the proof: allme|sumsub
  verificationId: string | null;  // the proof id to quote back to allme in a dispute
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
| `message_received` | `connectionId`, `messageId`, `personPublicKey` + `messageBody` (the DECRYPTED message text); no slot. Person→company only — a broadcast raises no event |

The event's ciphertext is carried under `body`. It is never `value`: on every other
event `value` means field ciphertext, and a message body is not one.

**Answering one.** `sendMessage` answers **201** with the created message carrying
`message_id`, which is what it returns — hand that id, or the inbound event's `messageId`,
to `markMessagesRead` as the acknowledgement boundary.

`Change.id` is captured before the server's drain-delete, so it survives a crash +
replay unchanged — dedup on it.

> **On the webhook path this id is NOT a dedup key.** A live webhook delivery has no change row behind it, so its id is minted for that single POST; a delivery replayed from the server-side backlog is rebuilt from a durable row and carries that row's id instead — the same id on every re-attempt of that row. The id is therefore sometimes stable across a duplicate and sometimes not, with no way for the receiver to tell, which is what makes it unusable as an idempotency key. Webhooks and the pull feed are alternative integrations; see `webhooks.md` for the webhook delivery contract and what to key on instead (change.id is not it).

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

## Share codes — what you may send, what you always receive

A profile can carry a second, human-readable **custom share code** assigned by an
allme operator, beside the generated code the person's app displays. Both resolve
to the same person.

- **Both places this SDK takes a share code as input accept either**:
  `client.sendConnectRequest(shareCode)` (`POST /api/company-data/connect-requests`)
  and `client.twoFactor.challenge(shareCode, opts)`
  (`POST /api/service-2fa/challenges`). Same parameter, same type, same shape —
  nothing in the SDK changes, and a customer who gives you `ACME` instead of
  `2I6UF3` simply works.
- **Every `share_code` the API emits is the GENERATED code** — `Connection.shareCode`,
  `Change.shareCode` and every webhook body. So a code handed to you by a customer
  may differ from the one you read back for that same person, and anything you key
  on the emitted value (a public-key cache, your own customer record) stays
  internally consistent.
