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
 * Cross-request state for the company-data demo backend (contract §"Backend state", config-file model).
 *
 * SINGLE-worker server (Node's built-in http = one process) → requests serialize; there is NO
 * concurrency to guard, so there are NO locks, NO tombstones and NO burn-on-read. Everything lives
 * under {@link runtimeDir} (git-ignored, wiped at startup):
 *   - config/{sid}.json       — the canonical SDK config file a scenario runs OFF (written by
 *                               POST /api/scenarios/{id}/config from the browser settings; NOT TTL-swept)
 *   - config/{sid}.meta.json  — demo-only run parameters that are not SDK Config fields
 *                               (the documents target share_code; the webhook id)
 *   - config/keys/<sha1>.pem  — the service private-key file(s) a config references by path (mode 0600)
 *   - runs/{runId}.json       — one run's accumulated result (events / rows / docs) + calls
 *   - webhook-route.json      — the SINGLE active webhook run: {webhookId, runId}. A new
 *                               companydata:webhook run supersedes it; TTL/Clear of the run drops it.
 *   - cache/                  — the SDK pump's buffer + dead-letter dir (Config.cacheDir), wiped by Clear
 *
 * {@link sid} is a filesystem-safe token of the scenario's string id (e.g. "companydata:read" →
 * "companydata_read"). Config files persist across runs — they are configuration, not runs, so they are
 * removed ONLY by a Clear or the startup wipe, never by the TTL. Run files are written via write-temp +
 * atomic rename (crash hygiene only) and removed by their 30-minute TTL (lazy sweep on any request, which
 * also collects orphaned *.tmp files), by Clear, or by the startup wipe.
 */
export const TTL_MS = 30 * 60 * 1000; // 30-minute run TTL. Config files are exempt.

export type RunRecord = Record<string, unknown> & {
  scenario?: string;
  status?: string;
  calls?: string[];
};

export type Route = { webhookId: string; runId: string };

export class Runtime {
  readonly runtimeDir: string;
  readonly runsDir: string;
  readonly configDir: string;
  readonly configKeysDir: string;
  /** The SDK pump's buffer + dead-letter dir (Config.cacheDir → this path), wiped by Clear / startup. */
  readonly cacheDir: string;
  readonly routePath: string;

  constructor(baseDir: string) {
    this.runtimeDir = join(baseDir, '.runtime');
    this.runsDir = join(this.runtimeDir, 'runs');
    this.configDir = join(this.runtimeDir, 'config');
    this.configKeysDir = join(this.configDir, 'keys');
    this.cacheDir = join(this.runtimeDir, 'cache');
    this.routePath = join(this.runtimeDir, 'webhook-route.json');
  }

  /** Filesystem-safe token for a scenario id (e.g. "companydata:read" → "companydata_read"). */
  static sid(scenarioId: string): string {
    return scenarioId.replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '');
  }

  /** Ensure the runtime directories exist (idempotent). */
  ensureDirs(): void {
    for (const d of [this.runtimeDir, this.runsDir, this.configDir, this.configKeysDir, this.cacheDir]) {
      if (!existsSync(d)) mkdirSync(d, { recursive: true, mode: 0o700 });
    }
  }

  /** Startup wipe: remove ALL runtime state (configs + keys + runs + cache + route), then recreate. */
  wipeAll(): void {
    rmSync(this.runtimeDir, { recursive: true, force: true });
    this.ensureDirs();
  }

  // ── lazy TTL sweep ──────────────────────────────────────────────────────

  /**
   * Remove expired run files and orphaned *.tmp files. Called on every request. When the active webhook
   * run expires, its routing record is dropped too (a stale record never routes to a burned run). Config
   * files carry NO TTL — they are wiped only at startup or by Clear.
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
    // Drop the routing record if its run is gone (expired/swept above).
    const route = this.readRoute();
    if (route !== null && !existsSync(join(this.runsDir, `${route.runId}.json`))) {
      this.tryUnlink(this.routePath);
    }
  }

  // ── config files ────────────────────────────────────────────────────────

  configPathFor(id: string): string {
    return join(this.configDir, `${Runtime.sid(id)}.json`);
  }

  metaPathFor(id: string): string {
    return join(this.configDir, `${Runtime.sid(id)}.meta.json`);
  }

  hasConfig(id: string): boolean {
    return existsSync(this.configPathFor(id));
  }

  /**
   * Write a scenario's canonical SDK config file (config endpoint). Atomic write-temp + rename.
   * Returns the RELATIVE path (for display/inspection in the setup panel).
   */
  writeConfig(id: string, config: Record<string, unknown>): string {
    this.ensureDirs();
    this.atomicWrite(this.configPathFor(id), JSON.stringify(config, null, 2));
    return `.runtime/config/${Runtime.sid(id)}.json`;
  }

  /** Write a scenario's demo-only meta sidecar (share_code, webhook_id). */
  writeConfigMeta(id: string, meta: Record<string, unknown>): void {
    this.ensureDirs();
    this.atomicWrite(this.metaPathFor(id), JSON.stringify(meta, null, 2));
  }

  /** Read a scenario's meta sidecar; {} when absent. */
  readConfigMeta(id: string): Record<string, unknown> {
    return this.readJson(this.metaPathFor(id)) ?? {};
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

  // ── webhook routing record (single active webhook run) ──────────────────

  /**
   * Persist the single active webhook route {webhookId, runId}, superseding any prior one. A new
   * companydata:webhook run calls this on /start; the old run stops receiving (its file stays readable
   * until TTL/Clear).
   */
  writeRoute(webhookId: string, runId: string): void {
    this.ensureDirs();
    this.atomicWrite(this.routePath, JSON.stringify({ webhookId, runId }));
  }

  /** The active webhook route, or null when none is set. */
  readRoute(): Route | null {
    const decoded = this.readJson(this.routePath);
    if (!decoded || typeof decoded.webhookId !== 'string' || typeof decoded.runId !== 'string') return null;
    return { webhookId: decoded.webhookId, runId: decoded.runId };
  }

  clearRoute(): void {
    this.tryUnlink(this.routePath);
  }

  // ── clear ─────────────────────────────────────────────────────────────────

  /**
   * Per-scenario clear: delete that scenario's run files AND its config + meta files, then
   * garbage-collect any key PEM no surviving config still references (keys are content-addressed and
   * may be shared, so a key is removed only once nothing points at it). Clearing the webhook scenario
   * also drops the routing record; clearing anything wipes the shared pump cache dir (cheap,
   * single-worker).
   */
  clearScenario(id: string): void {
    for (const name of this.list(this.runsDir)) {
      if (!name.endsWith('.json')) continue;
      const decoded = this.readJson(join(this.runsDir, name)) as RunRecord | null;
      if (decoded && String(decoded.scenario ?? '') === id) this.tryUnlink(join(this.runsDir, name));
    }
    this.tryUnlink(this.configPathFor(id));
    this.tryUnlink(this.metaPathFor(id));
    if (id === 'companydata:webhook') this.clearRoute();
    rmSync(this.cacheDir, { recursive: true, force: true });
    this.gcConfigKeys();
    this.ensureDirs();
  }

  /** Global clear: wipe all run files, the config tree (configs, metas, keys), the route + pump cache. */
  clearAll(): void {
    for (const name of this.list(this.runsDir)) this.tryUnlink(join(this.runsDir, name));
    rmSync(this.configDir, { recursive: true, force: true });
    rmSync(this.cacheDir, { recursive: true, force: true });
    this.clearRoute();
    this.ensureDirs();
  }

  /**
   * Delete any key PEM in config/keys that no surviving config/{sid}.json references by path. Robust to
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
