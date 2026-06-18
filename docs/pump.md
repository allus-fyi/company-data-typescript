# The changes pump

The changes feed is a server-side **drain-on-fetch queue**:
`GET /api/company-data/changes?limit=N` returns up to N events (default 100, max
500) **and deletes exactly those rows in the same transaction**. There is no
offset/cursor/page, and the API keeps no copy after a fetch. So a consumer must:

* not lose a drained batch if it crashes mid-batch (the API already deleted it), and
* not materialize a huge backlog in memory.

`client.processChanges(handler)` (delegating to the `Pump`) does both.

## `processChanges(handler, options?)`

```ts
processChanges(
  handler: (change: Change) => void | Promise<void>,
  options?: {
    batchSize?: number;                       // clamped to [1, 500]; default 100
    maxRetries?: number;                      // default 3
    onError?: 'deadletter' | 'halt';          // default 'deadletter'
    backoff?: (attempt: number) => number;    // attempt(1-based) -> seconds
  },
): Promise<void>
```

Drains the feed through `handler` one `Change` at a time, **until the feed is empty,
then resolves**. No follow/daemon mode — schedule re-runs yourself. The handler may
be sync or async.

## The cycle

1. **Replay first** — deliver any un-acked events already in the local buffer (a previous crashed run), oldest-first.
2. **Drain** — when the buffer is empty, fetch one batch (≤ `batchSize`, ≤ 500) and **persist it to the durable buffer (fsync) BEFORE handing anything out**.
3. **Deliver one-by-one** — for each buffered event, oldest-first: decrypt its value *at delivery* (never on disk), build the typed `Change`, call `handler(change)`.
4. **Ack / retry / dead-letter** — on handler success, remove the event from the buffer (ack). On a handler error, retry with `backoff` up to `maxRetries`; then:
   * `onError="deadletter"` (default) → move it to the dead-letter store, log it, and continue (one poison event never wedges the stream);
   * `onError="halt"` → re-throw the handler's error (the event stays un-acked in the buffer for the next run).
   A **`DecryptError`** (corrupt/truncated ciphertext, rotated key) is special: the decrypt runs *inside* the delivery attempt, and an undecryptable event is **dead-lettered immediately** — re-decrypting can't fix it, so it does **not** burn `maxRetries`. Under `onError="halt"` it re-throws like a handler error. Either way it never propagates out of `processChanges` and wedges step-1 replay.
5. Repeat until a drain returns empty **and** the buffer is drained → resolve.

## Crash safety · at-least-once · idempotency

A batch is durably buffered *before* any delivery, and acked per-item only *after*
the handler succeeds. A crash between a handler's success and its ack re-delivers
that event on the next run. Delivery is therefore **at-least-once**:

> **Your handler must be idempotent. Dedup on `Change.id`** (the stable server
> change-row id, captured before the server delete).

## The durable buffer (on disk)

Under `cacheDir`:

```
<cacheDir>/pending/<seq>_<change_id>.json      # un-acked events, oldest-first
<cacheDir>/deadletter/<seq>_<change_id>.json   # events that exhausted retries
```

* Stored events keep their **ciphertext** `value`/`value_url` — **no plaintext PII is ever written to disk**. Decryption happens only at delivery.
* `<seq>` is a zero-padded, monotonically increasing sequence, so lexicographic filename order == oldest-first (stable even if `at` timestamps are equal/missing).
* Writes are crash-safe: temp file → `fsyncSync` → atomic rename → dir fsync. A crash never leaves a half-written file.
* Re-instantiating the buffer on the same `cacheDir` recovers whatever is on disk — that recovery **is** the replay-on-restart.

## Options

| Option | Default | Meaning |
|--------|---------|---------|
| `batchSize` | 100 | Events per drain; clamped to `[1, 500]`. |
| `maxRetries` | 3 | Handler retries before dead-letter/halt. |
| `onError` | `"deadletter"` | `"deadletter"` (continue) or `"halt"` (re-throw). Any other value throws `TypeError`. |
| `backoff` | exponential, capped 30s | `attempt -> seconds` between retries. |

> `logger` is **not** a `processChanges` option — pass it to the `Client`
> constructor (`Client.fromConfig('allus.json', { logger: myLogger })`). Every
> drain, deliver, ack, retry, dead-letter, and replay is logged (any
> console-compatible sink with `debug`/`info`/`warn`/`error`).

## Durability guarantees

Held by the pump across all six SDKs, validated by the test suite:

1. **Decrypt inside the delivery attempt** — a poison/undecryptable event is dead-lettered immediately, never wedges replay, and does not burn retries.
2. **A re-failing dead-letter is updated in place** within `deadletter/` (atomic temp+fsync+rename) — never routed back through `pending/` (which has a crash window that could resurrect a dead-letter as a live event).
3. **Stored attempt count is monotonic** across separate retry runs (`max(existing, new)`).
4. **At-least-once dead-lettering** — the new dead-letter copy is written *before* the pending copy is unlinked, so a crash between leaves the event in both dirs (harmless re-delivery, absorbed by the id-dedup handler). This is intentional — do not "fix" it by deleting-first.

## No follow mode — schedule re-runs

```ts
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
for (;;) {
  await client.processChanges(handle);   // resolves when the feed empties
  await sleep(5000);                      // the feed is cheap to poll (see rate limits)
}
```

A cron job, a worker loop, or any scheduler works equally well.

## Dead-letter inspect / re-drive

```ts
client.deadLetters(): DeadLetterRecord[]
client.retryDeadLetters(handler, options?): Promise<number>
```

* `deadLetters()` — each record is the stored (ciphertext) event with a flattened `error` and `attempts`, plus its `id`.
* `retryDeadLetters(handler)` — re-drives every dead-lettered event through `handler`. On success the record is removed. On repeated failure (or a `DecryptError`) the dead-letter record is **updated in place** with the new error + attempt count and stays in `deadletter/` (`"deadletter"`), or the error re-throws (`"halt"`). Resolves to the count successfully re-driven.

A re-failing dead-letter never re-enters `pending/` — it is rewritten in place
within `deadletter/`, so a crash mid-re-drive can't resurrect it as a live event on
the next run. Dead letters are **never silently dropped** and **never re-fetched
from the API** (it already deleted them) — the local store is their only home,
which is exactly why it's durable.

```ts
for (const dl of client.deadLetters()) console.log(dl.id, dl.error, dl.attempts);
const fixed = await client.retryDeadLetters(handle);   // after fixing the handler bug
```

## Advanced: `drainBatch(max?)`

```ts
client.drainBatch(max?: number): Promise<Change[]>
```

A raw, **UNBUFFERED** drain: fetches one batch (clamped ≤ 500) and returns the
decrypted `Change`s directly — it does **not** persist anything to the buffer, so
**you own durability** if you use it (a crash loses what the API already deleted).
Prefer `processChanges` for safe consumption.
