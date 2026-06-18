/**
 * Crash-safe streaming changes pump.
 *
 * The changes feed is a server-side **drain-on-fetch queue**: a fetch returns up to
 * N events (default 100, max 500) and deletes those rows in the same transaction —
 * the API keeps no copy. So consumption cannot be a plain list: a consumer crash
 * mid-batch would lose events the API already deleted, and a huge backlog must not
 * materialize in memory. The pump solves both:
 *
 *     processChanges(handler) — one Change at a time, until the feed is empty, then
 *                               RETURNS. No follow/daemon mode (you schedule re-runs
 *                               yourself).
 *
 * Per cycle:
 *
 *   1. **Replay first** — deliver any un-acked events already in the local buffer
 *      (from a previous crashed run), oldest-first.
 *   2. **Drain** — when the buffer is empty, fetch ONE batch (≤ batchSize, ≤500) and
 *      **persist it to the durable buffer (fsync) BEFORE handing anything out**.
 *   3. **Deliver one-by-one** — for each buffered event oldest-first: decrypt its
 *      value (at delivery — never on disk), build the typed Change, call the handler.
 *   4. **Ack / retry / dead-letter** — on success remove the event from the buffer;
 *      on error retry with backoff up to maxRetries, then (onError "deadletter")
 *      move it to the dead-letter store and continue (one poison event never wedges
 *      the stream), or (onError "halt") stop and re-throw.
 *   5. Repeat until a drain returns empty AND the buffer is drained → return.
 *
 * Durability invariants (every port preserves these):
 *   (1) Decrypt INSIDE the delivery attempt — a DecryptError on a persisted poison
 *       event is dead-lettered IMMEDIATELY (re-decrypt can't help → it does NOT burn
 *       the retry budget); it never propagates out and wedges replay.
 *   (2) A re-failing dead-letter is updated IN PLACE within deadletter/ (never routed
 *       back through pending/).
 *   (3) Stored attempt count is monotonic = max(existing, new) (handled by the buffer).
 *   (4) dead_letter writes the new copy BEFORE unlinking pending (at-least-once safe).
 *
 * Injection (so tests + the real Client share one pump): the pump takes a
 * `fetchChanges(limit) -> Promise<event[]>` source (the raw drain-on-fetch call,
 * returning ciphertext event objects) and a `decrypt(event) -> Change` callable
 * (closes over the loaded service private key — config-only key handling). No
 * key/secret is ever a method argument.
 */

import { FileBuffer, type BufferedEvent, type DeadLetterRecord } from './buffer.js';
import { Config } from './config.js';
import { DecryptError } from './errors.js';
import { Change } from './models.js';

// The drain-on-fetch queue caps a fetch at 500. The pump clamps any requested
// batch size to this.
export const MAX_BATCH = 500;
const DEFAULT_BATCH = 100;

// Default retry/backoff for a failing handler.
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_BACKOFF_S = 0.5;
const MAX_BACKOFF_S = 30.0;

/** A fetch source: given a limit, drain-and-return up to that many raw event objects. */
export type FetchChanges = (limit: number) => Promise<BufferedEvent[]> | BufferedEvent[];
/** A decrypt callable: raw event object -> typed Change (value decrypted at delivery). */
export type DecryptChange = (event: BufferedEvent) => Change;
/** The consumer handler: it does the side-effect; success acks, a throw retries. */
export type Handler = (change: Change) => void | Promise<void>;

/** A minimal logger sink (console-compatible). */
export interface Logger {
  debug?(message: string, ...args: unknown[]): void;
  info?(message: string, ...args: unknown[]): void;
  warn?(message: string, ...args: unknown[]): void;
  error?(message: string, ...args: unknown[]): void;
}

export type OnError = 'deadletter' | 'halt';

export interface ProcessOptions {
  batchSize?: number;
  maxRetries?: number;
  onError?: OnError;
  backoff?: (attempt: number) => number;
}

export interface PumpOptions {
  fetchChanges: FetchChanges;
  decrypt: DecryptChange;
  logger?: Logger;
  sleep?: (seconds: number) => Promise<void>;
}

const defaultSleep = (seconds: number): Promise<void> =>
  new Promise((res) => setTimeout(res, Math.max(0, seconds) * 1000));

function defaultBackoff(attempt: number): number {
  return Math.min(DEFAULT_BACKOFF_S * 2 ** (attempt - 1), MAX_BACKOFF_S);
}

function clampBatch(value: number): number {
  let v = Math.trunc(Number(value));
  if (!Number.isFinite(v)) v = DEFAULT_BATCH;
  if (v < 1) v = 1;
  if (v > MAX_BATCH) v = MAX_BATCH;
  return v;
}

/**
 * The crash-safe changes pump.
 *
 * Wires a durable {@link FileBuffer} (under `config.cacheDir`) to an injected drain
 * source + decrypt callable.
 */
export class Pump {
  private readonly fetchChanges: FetchChanges;
  private readonly decryptChange: DecryptChange;
  private readonly log: Logger;
  private readonly sleep: (seconds: number) => Promise<void>;
  private readonly _buffer: FileBuffer;

  constructor(config: Config, opts: PumpOptions) {
    this.fetchChanges = opts.fetchChanges;
    this.decryptChange = opts.decrypt;
    this.log = opts.logger ?? {};
    this.sleep = opts.sleep ?? defaultSleep;
    // The buffer recovers whatever is already on disk — that recovery IS the
    // replay-on-restart in step 1.
    this._buffer = new FileBuffer(config.cacheDir);
  }

  get buffer(): FileBuffer {
    return this._buffer;
  }

  // ── the pump ──────────────────────────────────────────────────────────────

  /**
   * Stream events through `handler` until the feed is empty, then return.
   *
   * `handler` is called with one typed {@link Change} at a time and must be
   * idempotent (at-least-once delivery; dedup on `Change.id`).
   *
   * Options: `batchSize` (clamped ≤500), `maxRetries`, `onError`
   * (`"deadletter"` — default — or `"halt"`), `backoff` (attempt → seconds).
   */
  async processChanges(handler: Handler, options: ProcessOptions = {}): Promise<void> {
    const onError = options.onError ?? 'deadletter';
    if (onError !== 'deadletter' && onError !== 'halt') {
      throw new TypeError("onError must be 'deadletter' or 'halt'");
    }
    const size = clampBatch(options.batchSize ?? DEFAULT_BATCH);
    const maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    const backoff = options.backoff ?? defaultBackoff;

    for (;;) {
      // 1. Replay anything already buffered (a previous crashed run), then deliver
      //    it. If the buffer is empty, drain ONE batch first.
      let pending = this._buffer.pending();
      if (pending.length > 0) {
        this.log.info?.(`pump replay: ${pending.length} buffered event(s)`);
      } else {
        const drained = await this.drainIntoBuffer(size);
        if (drained === 0) {
          // A drain returned empty AND the buffer is drained → done.
          return;
        }
        pending = this._buffer.pending();
      }

      // 3+4. Deliver each buffered event oldest-first; ack/retry/dead-letter.
      for (const event of pending) {
        await this.deliverOne(event, handler, { maxRetries, onError, backoff });
      }
      // Loop: re-check the buffer (now drained) and try another drain.
    }
  }

  private async drainIntoBuffer(size: number): Promise<number> {
    const batch = (await this.fetchChanges(size)) || [];
    this.log.info?.(`pump drain: fetched ${batch.length} event(s) (limit=${size})`);
    if (batch.length === 0) {
      return 0;
    }
    // Persist-before-deliver: the durable backup the API no longer has.
    this._buffer.append(batch);
    return batch.length;
  }

  private async deliverOne(
    event: BufferedEvent,
    handler: Handler,
    opts: { maxRetries: number; onError: OnError; backoff: (attempt: number) => number },
  ): Promise<void> {
    const changeId = event['id'];
    let attempts = 0;

    for (;;) {
      attempts += 1;
      try {
        // Decrypt only now — never on disk (ciphertext at rest).
        // Inside the try so a poison-ciphertext DecryptError is contained.
        const change = this.decryptChange(event);
        this.log.debug?.(`pump deliver: id=${String(changeId)} attempt=${attempts}`);
        await handler(change);
      } catch (exc) {
        if (exc instanceof DecryptError) {
          // A poison event: re-decrypting won't help, so don't burn retries.
          if (opts.onError === 'halt') {
            this.log.error?.(`pump halt: id=${String(changeId)} undecryptable (${exc.message})`);
            throw exc;
          }
          this._buffer.deadLetter(changeId, `DecryptError: ${exc.message}`, attempts);
          this.log.error?.(`pump dead-letter (undecryptable): id=${String(changeId)}: ${exc.message}`);
          return;
        }
        // A handler error.
        const err = exc as Error;
        if (attempts <= opts.maxRetries) {
          const delay = Math.max(0, opts.backoff(attempts));
          this.log.warn?.(
            `pump retry: id=${String(changeId)} attempt=${attempts} failed (${err.message}); backoff ${delay}s`,
          );
          if (delay) await this.sleep(delay);
          continue;
        }
        // Retries exhausted.
        if (opts.onError === 'halt') {
          this.log.error?.(`pump halt: id=${String(changeId)} failed after ${attempts} attempt(s)`);
          throw err;
        }
        this._buffer.deadLetter(changeId, String(err.message ?? err), attempts);
        this.log.error?.(`pump dead-letter: id=${String(changeId)} after ${attempts} attempt(s): ${err.message}`);
        return;
      }
      // Success → per-item ack (remove from the buffer).
      this._buffer.ack(changeId);
      this.log.debug?.(`pump ack: id=${String(changeId)}`);
      return;
    }
  }

  // ── advanced primitive ─────────────────────────────────────────────────────

  /**
   * Raw, UNBUFFERED drain → a list of typed Changes (advanced).
   *
   * Fetches one batch (clamped ≤500) and returns the decrypted Changes directly — it
   * does NOT persist anything to the buffer, so **you own durability** if you use it.
   * Prefer {@link processChanges} for safe consumption.
   */
  async drainBatch(max: number = DEFAULT_BATCH): Promise<Change[]> {
    const size = clampBatch(max);
    const batch = (await this.fetchChanges(size)) || [];
    this.log.info?.(`drainBatch: fetched ${batch.length} event(s) (limit=${size})`);
    return batch.map((event) => this.decryptChange(event));
  }

  // ── dead-letter inspect / re-drive ─────────────────────────────────────────

  /** The local dead-letter store (ciphertext + error + attempt count). */
  deadLetters(): DeadLetterRecord[] {
    return this._buffer.deadLetters();
  }

  /**
   * Re-drive every dead-lettered event through `handler`.
   *
   * On success the dead-letter record is removed; on repeated failure it is
   * re-dead-lettered IN PLACE (`"deadletter"`) or the error is re-thrown (`"halt"`).
   * They are never re-fetched from the API (it already deleted them) — the local
   * store is their only home. Returns the count successfully re-driven.
   */
  async retryDeadLetters(handler: Handler, options: ProcessOptions = {}): Promise<number> {
    const onError = options.onError ?? 'deadletter';
    if (onError !== 'deadletter' && onError !== 'halt') {
      throw new TypeError("onError must be 'deadletter' or 'halt'");
    }
    const maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    const backoff = options.backoff ?? defaultBackoff;

    let redriven = 0;
    for (const record of this._buffer.deadLetters()) {
      const changeId = record['id'];
      // Strip the reserved failure block before re-decrypting the event.
      const event: BufferedEvent = {};
      for (const [k, v] of Object.entries(record)) {
        if (k === '_deadletter' || k === 'error' || k === 'attempts') continue;
        event[k] = v;
      }
      let attempts = 0;
      for (;;) {
        attempts += 1;
        try {
          // Decrypt inside the loop so an undecryptable dead-letter (the poison
          // case) is contained here too — it updates its own record in place
          // instead of crashing the re-drive.
          const change = this.decryptChange(event);
          await handler(change);
        } catch (exc) {
          if (exc instanceof DecryptError) {
            if (onError === 'halt') {
              this.log.error?.(
                `retryDeadLetters halt: id=${String(changeId)} undecryptable (${exc.message})`,
              );
              throw exc;
            }
            this._buffer.updateDeadLetter(changeId, `DecryptError: ${exc.message}`, attempts);
            this.log.warn?.(`retryDeadLetters: id=${String(changeId)} still undecryptable (${exc.message})`);
            break;
          }
          const err = exc as Error;
          if (attempts <= maxRetries) {
            const delay = Math.max(0, backoff(attempts));
            if (delay) await this.sleep(delay);
            continue;
          }
          if (onError === 'halt') {
            this.log.error?.(`retryDeadLetters halt: id=${String(changeId)} failed again`);
            throw err;
          }
          // Refresh the stored attempt count + error IN PLACE — the record stays in
          // deadletter/ and never re-enters pending/, so there is no crash window
          // (between an append and a re-dead-letter) where it could resurrect as a
          // live pending event.
          this._buffer.updateDeadLetter(changeId, String(err.message ?? err), attempts);
          this.log.warn?.(`retryDeadLetters: id=${String(changeId)} still failing (${err.message})`);
          break;
        }
        // Success.
        this._buffer.removeDeadLetter(changeId);
        this.log.info?.(`retryDeadLetters: id=${String(changeId)} re-driven OK`);
        redriven += 1;
        break;
      }
    }
    return redriven;
  }
}
