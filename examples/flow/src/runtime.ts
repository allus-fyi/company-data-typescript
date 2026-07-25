import {
  chmodSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';

/**
 * Cross-request state for the demo backend (contract §"Backend state", config-file model).
 *
 * SINGLE-worker server (Node's built-in http = one process) → requests serialize; there is NO
 * concurrency to guard, so there are NO locks, NO tombstones and NO burn-on-read. Everything lives
 * under {@link runtimeDir} (git-ignored, wiped at startup):
 *   - config/{id}.json       — the canonical SDK config file the scenario runs OFF (written by
 *                              POST /api/scenarios/{id}/config from the browser settings; NOT TTL-swept)
 *   - config/{id}.meta.json  — demo-only run parameters that are not SDK Config fields
 *                              (flow_id, connection_id, fixture)
 *   - config/keys/<sha1>.pem — the service private-key file a config references by path (mode 0600)
 *   - runs/{runId}.json      — the platform flowRunId / step log / outcome for one demo run
 *
 * The single public scenario id ("flow:run") is not filesystem-shaped, so the server maps it to the
 * internal numeric store id 1 before touching these files. Config files persist across runs — they are
 * configuration, not runs, so they are removed ONLY by a Clear or the startup wipe, never by the TTL.
 * Run files are written via write-temp + atomic rename (crash hygiene only) and removed by their
 * 30-minute TTL (lazy sweep on any request, which also collects orphaned *.tmp files), by Clear, or by
 * the startup wipe.
 */
export const TTL_MS = 30 * 60 * 1000; // 30-minute run TTL. Config files are exempt.

export type RunRecord = Record<string, unknown> & {
  scenario?: number;
  status?: string;
  calls?: string[];
};

export class Runtime {
  readonly runtimeDir: string;
  readonly runsDir: string;
  readonly configDir: string;
  readonly configKeysDir: string;

  constructor(baseDir: string) {
    this.runtimeDir = join(baseDir, '.runtime');
    this.runsDir = join(this.runtimeDir, 'runs');
    this.configDir = join(this.runtimeDir, 'config');
    this.configKeysDir = join(this.configDir, 'keys');
  }

  /** Ensure the runtime directories exist (idempotent). */
  ensureDirs(): void {
    for (const d of [this.runtimeDir, this.runsDir, this.configDir, this.configKeysDir]) {
      if (!existsSync(d)) mkdirSync(d, { recursive: true, mode: 0o700 });
    }
  }

  /** Startup wipe: remove ALL runtime state (configs + keys + runs), then recreate the empty tree. */
  wipeAll(): void {
    rmSync(this.runtimeDir, { recursive: true, force: true });
    this.ensureDirs();
  }

  // ── lazy TTL sweep ──────────────────────────────────────────────────────

  /**
   * Remove expired run files and orphaned *.tmp files. Called on every request (contract §backend state).
   * Config files carry NO TTL — they are wiped only at startup or by Clear.
   */
  sweep(): void {
    const now = Date.now();
    for (const name of this.list(this.runsDir)) {
      const path = join(this.runsDir, name);
      if (name.endsWith('.tmp')) {
        this.tryUnlink(path); // orphaned temp from an interrupted write
        continue;
      }
      if (name.endsWith('.json') && now - this.mtime(path) > TTL_MS) {
        this.tryUnlink(path);
      }
    }
  }

  // ── config files ────────────────────────────────────────────────────────

  configPathFor(id: number): string {
    return join(this.configDir, `${id}.json`);
  }

  metaPathFor(id: number): string {
    return join(this.configDir, `${id}.meta.json`);
  }

  hasConfig(id: number): boolean {
    return existsSync(this.configPathFor(id));
  }

  /**
   * Write a scenario's canonical SDK config file (config endpoint). Atomic write-temp + rename.
   * Returns the RELATIVE path (for display/inspection in the setup panel).
   */
  writeConfig(id: number, config: Record<string, unknown>): string {
    this.ensureDirs();
    this.atomicWrite(this.configPathFor(id), JSON.stringify(config, null, 2));
    return `.runtime/config/${id}.json`;
  }

  /** Write a scenario's demo-only meta sidecar (flow_id, connection_id, fixture). */
  writeConfigMeta(id: number, meta: Record<string, unknown>): void {
    this.ensureDirs();
    this.atomicWrite(this.metaPathFor(id), JSON.stringify(meta, null, 2));
  }

  /** Read a scenario's meta sidecar; {} when absent. */
  readConfigMeta(id: number): Record<string, unknown> {
    return this.readJson(this.metaPathFor(id)) ?? {};
  }

  /** The decoded canonical config file for a scenario ({} if none). */
  readConfig(id: number): Record<string, unknown> {
    return this.readJson(this.configPathFor(id)) ?? {};
  }

  /**
   * Materialize a browser-sent PEM to config/keys/<sha1>.pem (0600) and return its ABSOLUTE path —
   * the value recorded in the config file (the SDK reads keys by path). Content-addressed: identical
   * PEM reuses the same file. Removed only by Clear or the startup wipe (never TTL).
   */
  materializeConfigKey(pem: string): string {
    this.ensureDirs();
    const path = join(this.configKeysDir, `${createHash('sha1').update(pem).digest('hex')}.pem`);
    if (!existsSync(path)) this.atomicWrite(path, pem, 0o600);
    chmodSync(path, 0o600);
    return path;
  }

  // ── runs ────────────────────────────────────────────────────────────────

  newRunId(): string {
    return randomBytes(16).toString('hex');
  }

  static isRunId(s: string): boolean {
    return /^[0-9a-f]{32}$/.test(s);
  }

  /** Write a run atomically (write-temp + rename). A reader never sees a partial file. */
  writeRun(runId: string, data: RunRecord): void {
    data.runId = runId;
    this.atomicWrite(join(this.runsDir, `${runId}.json`), JSON.stringify(data, null, 2));
  }

  /**
   * Read a run, honouring the TTL. Returns null for unknown/expired ids (idempotent reads — an
   * outcome, once written, is returned on every poll until TTL/Clear removes it).
   */
  readRun(runId: string): RunRecord | null {
    if (!Runtime.isRunId(runId)) return null;
    const path = join(this.runsDir, `${runId}.json`);
    if (!existsSync(path)) return null;
    if (Date.now() - this.mtime(path) > TTL_MS) {
      this.tryUnlink(path);
      return null;
    }
    return (this.readJson(path) as RunRecord | null) ?? null;
  }

  // ── clear ─────────────────────────────────────────────────────────────────

  /**
   * Per-scenario clear: delete that scenario's run files AND its config + meta files, then
   * garbage-collect any key PEM no surviving config still references (keys are content-addressed and
   * may be shared, so a key is removed only once nothing points at it).
   */
  clearScenario(id: number): void {
    for (const name of this.list(this.runsDir)) {
      if (!name.endsWith('.json')) continue;
      const decoded = this.readJson(join(this.runsDir, name)) as RunRecord | null;
      if (decoded && Number(decoded.scenario ?? 0) === id) this.tryUnlink(join(this.runsDir, name));
    }
    this.tryUnlink(this.configPathFor(id));
    this.tryUnlink(this.metaPathFor(id));
    this.gcConfigKeys();
  }

  /** Global clear: wipe all run files and the entire config tree (configs, metas, keys). */
  clearAll(): void {
    for (const name of this.list(this.runsDir)) this.tryUnlink(join(this.runsDir, name));
    rmSync(this.configDir, { recursive: true, force: true });
    this.ensureDirs();
  }

  /**
   * Delete any key PEM in config/keys that no surviving config/{id}.json references by path. Robust to
   * content-addressed sharing: a key survives as long as ANY config points at it.
   */
  private gcConfigKeys(): void {
    const referenced = new Set<string>();
    for (const name of this.list(this.configDir)) {
      if (!name.endsWith('.json') || name.endsWith('.meta.json')) continue;
      const decoded = this.readJson(join(this.configDir, name));
      if (!decoded) continue;
      const p = decoded['service_private_key'];
      if (typeof p === 'string' && p !== '') referenced.add(p);
    }
    for (const name of this.list(this.configKeysDir)) {
      if (!name.endsWith('.pem')) continue;
      const keyPath = join(this.configKeysDir, name);
      if (!referenced.has(keyPath)) this.tryUnlink(keyPath);
    }
  }

  // ── helpers ─────────────────────────────────────────────────────────────

  /** Write-temp + atomic rename on the same filesystem (crash hygiene: no partial reads). */
  private atomicWrite(finalPath: string, contents: string, mode?: number): void {
    const tmp = `${finalPath}.${randomBytes(4).toString('hex')}.tmp`;
    writeFileSync(tmp, contents, mode !== undefined ? { mode } : undefined);
    if (mode !== undefined) chmodSync(tmp, mode);
    renameSync(tmp, finalPath);
  }

  private readJson(path: string): Record<string, unknown> | null {
    try {
      const decoded = JSON.parse(readFileSync(path, 'utf8'));
      return decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : null;
    } catch {
      return null;
    }
  }

  private list(dir: string): string[] {
    try {
      return readdirSync(dir);
    } catch {
      return [];
    }
  }

  private mtime(path: string): number {
    try {
      return statSync(path).mtimeMs;
    } catch {
      return 0;
    }
  }

  private tryUnlink(path: string): void {
    try {
      unlinkSync(path);
    } catch {
      /* already gone */
    }
  }
}
