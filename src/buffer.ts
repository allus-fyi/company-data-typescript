/**
 * Durable plain-file buffer for the crash-safe changes pump.
 *
 * The changes feed is a server-side **drain-on-fetch queue**: a fetch returns up to
 * N events and deletes those rows in the same transaction — the API keeps no copy.
 * So a drained batch MUST be persisted locally BEFORE any delivery, or a consumer
 * crash mid-batch loses events the API already deleted. This module is that
 * persistence: a zero-dependency, plain-file buffer under `cacheDir`.
 *
 * Layout:
 *
 *     <cacheDir>/pending/<seq>_<change_id>.json      # one un-acked event, oldest-first
 *     <cacheDir>/deadletter/<seq>_<change_id>.json   # events that exhausted retries
 *
 *   - The stored event is the **raw hardened API event object** — its `value` /
 *     `value_url` is **CIPHERTEXT**, never the decrypted plaintext. No PII is ever
 *     written to disk ("ciphertext at rest").
 *   - `<seq>` is a zero-padded, monotonically increasing sequence number persisted
 *     in `<cacheDir>/.seq`. Because {@link FileBuffer.append} is called in drain
 *     order (oldest-first), sorting filenames lexicographically yields oldest-first
 *     — a stable order even if event `at` timestamps are missing or equal.
 *   - Writes are **crash-safe**: each file is written to a temp name, fsync'd,
 *     atomically renamed into place, and the containing directory is fsync'd — so a
 *     crash never leaves a half-written pending file.
 *   - `ack(id)` deletes the pending file; `deadLetter(id, error, attempts)` moves it
 *     to `deadletter/` with the error + attempt count appended. Neither re-fetches
 *     from the API (it already deleted the row) — the buffer is the only home.
 *
 * All operations are SYNCHRONOUS (Node `fs` + `fsyncSync`) so the fsync discipline
 * is exact. The pump calls them between awaits.
 */

import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

const PENDING_DIR = 'pending';
const DEADLETTER_DIR = 'deadletter';
const SEQ_FILE = '.seq';

// Width of the zero-padded sequence prefix. 16 digits keeps filenames sorting
// lexicographically up to ~10^16 appends — vastly beyond any real backlog.
const SEQ_WIDTH = 16;

/** A buffered event (the raw hardened API object; ciphertext value intact). */
export type BufferedEvent = Record<string, unknown>;

/** A dead-letter record: the stored event + flattened error/attempts/id. */
export interface DeadLetterRecord extends BufferedEvent {
  error: string | null;
  attempts: number | null;
}

function sanitizeId(changeId: unknown): string {
  const s = changeId != null ? String(changeId) : 'noid';
  const cleaned = Array.from(s)
    .map((c) => (/[A-Za-z0-9_-]/.test(c) ? c : '_'))
    .join('');
  return cleaned.length > 0 ? cleaned : 'noid';
}

function fsyncDir(path: string): void {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    // Platform without dir fds — ignore.
    return;
  }
  try {
    fsyncSync(fd);
  } catch {
    // fs without dir fsync — ignore.
  } finally {
    closeSync(fd);
  }
}

function uniqueTempName(prefix: string): string {
  return `${prefix}${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2)}`;
}

function atomicWriteJson(path: string, obj: unknown): void {
  const directory = join(path, '..');
  const tmp = join(directory, uniqueTempName('.tmp_') + '.json');
  try {
    writeFileSync(tmp, JSON.stringify(obj));
    const fd = openSync(tmp, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path); // atomic rename over any existing file
  } catch (exc) {
    try {
      unlinkSync(tmp);
    } catch {
      // ignore — never leak partials
    }
    throw exc;
  }
  // Durably record the rename in the directory entry.
  fsyncDir(directory);
}

function atomicWriteInt(path: string, value: number): void {
  const directory = join(path, '..');
  const tmp = join(directory, uniqueTempName('.tmp_seq_'));
  try {
    writeFileSync(tmp, String(value));
    const fd = openSync(tmp, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
  } catch (exc) {
    try {
      unlinkSync(tmp);
    } catch {
      // ignore
    }
    throw exc;
  }
  fsyncDir(directory);
}

function seqOf(name: string): number | null {
  const head = name.split('_', 1)[0];
  const n = Number(head);
  return Number.isInteger(n) ? n : null;
}

/**
 * A durable, ordered, ciphertext-at-rest event buffer under `cacheDir`.
 *
 * Re-instantiating a `FileBuffer` on the same `cacheDir` recovers whatever is on
 * disk — that recovery is exactly the pump's replay-on-restart.
 */
export class FileBuffer {
  private readonly pendingDir: string;
  private readonly deadletterDir: string;
  private readonly seqPath: string;

  constructor(cacheDir: string) {
    this.pendingDir = join(cacheDir, PENDING_DIR);
    this.deadletterDir = join(cacheDir, DEADLETTER_DIR);
    this.seqPath = join(cacheDir, SEQ_FILE);
    mkdirSync(this.pendingDir, { recursive: true });
    mkdirSync(this.deadletterDir, { recursive: true });
  }

  // ── sequence ─────────────────────────────────────────────────────────────

  // Single-threaded JS — no lock needed around the seq counter.
  private nextSeq(): number {
    let current = this.readSeq();
    if (current === null) {
      current = this.maxOnDiskSeq();
    }
    const next = current + 1;
    this.writeSeq(next);
    return next;
  }

  private readSeq(): number | null {
    try {
      const raw = readFileSync(this.seqPath, 'utf8').trim();
      const n = Number(raw);
      return Number.isInteger(n) ? n : null;
    } catch {
      return null;
    }
  }

  private writeSeq(value: number): void {
    atomicWriteInt(this.seqPath, value);
  }

  private maxOnDiskSeq(): number {
    let best = 0;
    for (const d of [this.pendingDir, this.deadletterDir]) {
      for (const name of readdirSync(d)) {
        const seq = seqOf(name);
        if (seq !== null && seq > best) best = seq;
      }
    }
    return best;
  }

  // ── append / list / ack ──────────────────────────────────────────────────

  /**
   * Persist a drained batch (oldest-first), each in its own fsync'd file.
   *
   * Each event is stored verbatim (ciphertext value intact). Returns the list of
   * pending filenames written. This is the backup the API no longer holds — it
   * MUST complete before the pump delivers anything.
   */
  append(events: BufferedEvent[]): string[] {
    const written: string[] = [];
    for (const event of events) {
      const seq = this.nextSeq();
      const changeId = event && typeof event === 'object' ? event['id'] : undefined;
      const name = `${String(seq).padStart(SEQ_WIDTH, '0')}_${sanitizeId(changeId)}.json`;
      atomicWriteJson(join(this.pendingDir, name), event);
      written.push(name);
    }
    return written;
  }

  /** All un-acked events, oldest-first (by the sortable filename). */
  pending(): BufferedEvent[] {
    return this.pendingFiles().map((n) => this.readEvent(this.pendingDir, n));
  }

  private pendingFiles(): string[] {
    const names = readdirSync(this.pendingDir).filter(
      (n) => n.endsWith('.json') && !n.startsWith('.tmp_'),
    );
    names.sort(); // zero-padded seq prefix → lexicographic == oldest-first
    return names;
  }

  private readEvent(directory: string, name: string): BufferedEvent {
    return JSON.parse(readFileSync(join(directory, name), 'utf8')) as BufferedEvent;
  }

  private findPendingFile(changeId: unknown): string | null {
    const target = sanitizeId(changeId);
    for (const name of this.pendingFiles()) {
      const rest = name.slice(name.indexOf('_') + 1);
      if (rest === `${target}.json`) return name;
    }
    return null;
  }

  /** Delete the pending file for `changeId` (the per-item ack). Idempotent. */
  ack(changeId: unknown): boolean {
    const name = this.findPendingFile(changeId);
    if (name === null) return false;
    try {
      unlinkSync(join(this.pendingDir, name));
    } catch {
      return false; // already gone (idempotent)
    }
    fsyncDir(this.pendingDir);
    return true;
  }

  // ── dead-letter ────────────────────────────────────────────────────────────

  /**
   * Move a poison event from pending → deadletter with error + attempts.
   *
   * Crash safety: the new dead-letter copy is written BEFORE the pending copy is
   * unlinked — never lose. A crash between the two leaves the event in BOTH dirs,
   * which is harmless: replay re-delivers it (the id-dedup handler absorbs the
   * duplicate). Do NOT "fix" this by deleting-first.
   *
   * The event keeps its ciphertext value; the failure context is appended under a
   * reserved key so it is never silently dropped.
   */
  deadLetter(changeId: unknown, error: string, attempts: number): boolean {
    const name = this.findPendingFile(changeId);
    if (name === null) return false;
    const event = this.readEvent(this.pendingDir, name);
    const record: BufferedEvent = { ...event, _deadletter: { error: String(error), attempts: Math.trunc(attempts) } };
    // Write the dead-letter copy FIRST (at-least-once safe).
    atomicWriteJson(join(this.deadletterDir, name), record);
    try {
      unlinkSync(join(this.pendingDir, name));
    } catch {
      // already gone — harmless
    }
    fsyncDir(this.pendingDir);
    return true;
  }

  private deadletterFiles(): string[] {
    const names = readdirSync(this.deadletterDir).filter(
      (n) => n.endsWith('.json') && !n.startsWith('.tmp_'),
    );
    names.sort();
    return names;
  }

  /**
   * All dead-lettered events, oldest-first.
   *
   * Each item is the stored (ciphertext) event with a flattened `error` and
   * `attempts` lifted out of the reserved `_deadletter` block, plus the event's own
   * `id` for convenience.
   */
  deadLetters(): DeadLetterRecord[] {
    const out: DeadLetterRecord[] = [];
    for (const name of this.deadletterFiles()) {
      const event = this.readEvent(this.deadletterDir, name);
      const meta = (event['_deadletter'] as { error?: unknown; attempts?: unknown } | undefined) ?? {};
      out.push({
        ...event,
        error: meta.error != null ? String(meta.error) : null,
        attempts: meta.attempts != null ? Number(meta.attempts) : null,
      });
    }
    return out;
  }

  private findDeadletterFile(changeId: unknown): string | null {
    const target = sanitizeId(changeId);
    for (const name of this.deadletterFiles()) {
      const rest = name.slice(name.indexOf('_') + 1);
      if (rest === `${target}.json`) return name;
    }
    return null;
  }

  /**
   * Rewrite a dead-letter record IN PLACE with a refreshed error + attempts.
   *
   * Used by a still-failing re-drive (`retryDeadLetters`): the record stays in
   * `deadletter/` and its failure context is updated atomically (temp file inside
   * `deadletter/` → fsync → rename over the same path). It is NEVER routed back
   * through `pending/`, so a crash anywhere in this method leaves the record either
   * as the old dead-letter or the new one — it can never resurrect as a live
   * pending event. Idempotent (returns false if the record is gone).
   * Preserves the file's seq prefix so its oldest-first ordering is unchanged.
   *
   * The stored attempt count is monotonic across separate re-drive runs — a later
   * run with a smaller `maxRetries` must never lower the recorded total — so we
   * clamp to `max(existing, new)`.
   */
  updateDeadLetter(changeId: unknown, error: string, attempts: number): boolean {
    const name = this.findDeadletterFile(changeId);
    if (name === null) return false;
    const path = join(this.deadletterDir, name);
    let event: BufferedEvent;
    try {
      event = this.readEvent(this.deadletterDir, name);
    } catch {
      return false; // already gone (idempotent)
    }
    const priorMeta = event['_deadletter'] as { attempts?: unknown } | undefined;
    let priorAttempts = 0;
    if (priorMeta && priorMeta.attempts != null) {
      const n = Number(priorMeta.attempts);
      priorAttempts = Number.isFinite(n) ? n : 0;
    }
    const record: BufferedEvent = {};
    for (const [k, v] of Object.entries(event)) {
      if (k === '_deadletter' || k === 'error' || k === 'attempts') continue;
      record[k] = v;
    }
    record['_deadletter'] = { error: String(error), attempts: Math.max(priorAttempts, Math.trunc(attempts)) };
    atomicWriteJson(path, record); // temp+fsync+rename, all within deadletter/
    return true;
  }

  /** Delete a dead-letter record (after a successful re-drive). Idempotent. */
  removeDeadLetter(changeId: unknown): boolean {
    const name = this.findDeadletterFile(changeId);
    if (name === null) return false;
    try {
      unlinkSync(join(this.deadletterDir, name));
    } catch {
      return false;
    }
    fsyncDir(this.deadletterDir);
    return true;
  }
}
