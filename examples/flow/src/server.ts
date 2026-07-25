import type { IncomingMessage, ServerResponse } from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';

import { ApiError, Client, ConfigError, FlowRun, ValidationError } from '@allus-fyi/company-data';

import { Runtime, type RunRecord } from './runtime.js';

/**
 * The demo-backend contract for the ONE contract-flow scenario (flow family — contract v2). One class,
 * one worker (Node's built-in http): HTTP dispatch → handler → the SDK's intended top-level flow surface
 * only (identity / triggerFlowRun / flowRun / processFlowRun / flowRunAnswers / flowRunDocument).
 * Handlers NEVER perform raw platform HTTP.
 *
 * Single scenario "flow:run". There is NO cross-card flow-run-id handoff: the platform flow run lives
 * entirely INSIDE this one demo run's file — the demo runId is the backend run and the platform
 * flowRunId is stored inside it, never exposed as a separate browser input.
 *
 * Settings flow (config-file model): the browser POSTs the scenario's setup values to
 * POST /api/scenarios/{id}/config, which writes them to a canonical SDK config FILE
 * (.runtime/config/{store}.json; the service PEM → .runtime/config/keys/ by path). /start builds the
 * service {@link Client} from that file via {@link Client.fromConfig} and runs OFF the config — exactly
 * as a real integrator wires the SDK. The request body of /start is ignored; a /start with no saved
 * config → 409 not_configured.
 *
 * The GET /api/runs/{runId} poll is the drive loop AND the resume: each poll reads the platform run and,
 * if it is the company's turn, drives exactly ONE company step; otherwise it reports waiting/running and
 * touches nothing (the next poll after the person answers on their phone resumes automatically).
 */

export const CONTRACT_VERSION = 2; // flow family lands at the next-available version (identity=1)
export const SDK = 'typescript';

/** The single public scenario id (the flow family). */
const SCENARIO = 'flow:run';
/** Internal store key for the config/meta/run files (the public id is not filesystem-shaped). */
const STORE_ID = 1;

const DEFAULT_API_URL = 'https://api.allme.fyi';

/** The flow party keys the fixtures pin. */
const PARTY_COMPANY = 'company';
const PARTY_CUSTOMER = 'customer';

/** The canned INVALID value the validation-demo submits once for an email field. */
const INVALID_EMAIL = 'not-an-email';

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.webp': 'image/webp',
};

export class Server {
  constructor(
    private readonly rt: Runtime,
    private readonly frontendDir: string,
    private readonly sdkVersion: string,
    private readonly port: number,
  ) {}

  // ── entry point ────────────────────────────────────────────────────────

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    this.rt.ensureDirs();
    this.rt.sweep(); // lazy TTL sweep on every request

    const method = req.method ?? 'GET';
    const host = String(req.headers.host ?? `localhost:${this.port}`);
    const url = new URL(req.url ?? '/', `http://${host}`);
    const path = decodeURIComponent(url.pathname);

    try {
      let m: RegExpMatchArray | null;
      if (path === '/api/meta' && method === 'GET') {
        this.meta(res);
      } else if (path === '/api/clear' && method === 'POST') {
        this.rt.clearAll();
        this.json(res, { ok: true });
      } else if ((m = path.match(/^\/api\/scenarios\/([\w:.-]+)\/config$/)) && method === 'POST') {
        await this.config(m[1], req, res);
      } else if ((m = path.match(/^\/api\/scenarios\/([\w:.-]+)\/start$/)) && method === 'POST') {
        await this.start(m[1], res);
      } else if ((m = path.match(/^\/api\/scenarios\/([\w:.-]+)\/clear$/)) && method === 'POST') {
        if (!this.isKnownScenario(m[1])) return this.json(res, { error: 'not_found' }, 404);
        this.rt.clearScenario(STORE_ID);
        this.json(res, { ok: true });
      } else if ((m = path.match(/^\/api\/runs\/([0-9a-f]{32})$/)) && method === 'GET') {
        await this.run(m[1], res);
      } else if (path.startsWith('/api/')) {
        this.json(res, { error: 'not_found' }, 404);
      } else {
        this.serveStatic(path, res);
      }
    } catch (e) {
      this.json(res, { error: 'server_error', message: (e as Error).message }, 500);
    }
  }

  private isKnownScenario(id: string): boolean {
    return id === SCENARIO;
  }

  // ── GET /api/meta ──────────────────────────────────────────────────────

  private meta(res: ServerResponse): void {
    this.json(res, {
      sdk: SDK,
      sdkVersion: this.sdkVersion,
      contractVersion: CONTRACT_VERSION,
      scenarios: [{ id: SCENARIO, kind: 'runnable' }],
    });
  }

  // ── POST /api/scenarios/{id}/config ─────────────────────────────────────

  /**
   * Write the browser's setup values to a canonical SDK config FILE (service role). The service PEM is
   * written to config/keys/ and referenced by path; the demo-only run parameters (published flow id,
   * connection id, fixture choice) go to the meta sidecar so the config file stays a pure SDK config.
   */
  private async config(id: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.isKnownScenario(id)) return this.json(res, { error: 'not_found' }, 404);
    const in_ = await this.body(req);

    // Canonical SDK config — the service role (client_credentials + service PEM).
    const cfg: Record<string, unknown> = {
      api_url: (str(in_.apiUrl) || DEFAULT_API_URL).replace(/\/+$/, ''),
      client_id: str(in_.clientId),
      client_secret: str(in_.clientSecret),
      key_passphrase: str(in_.keyPassphrase),
    };
    const pem = str(in_.servicePrivateKeyPem);
    if (pem !== '') cfg.service_private_key = this.rt.materializeConfigKey(pem);
    const configPath = this.rt.writeConfig(STORE_ID, cfg);

    // Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
    this.rt.writeConfigMeta(STORE_ID, {
      flow_id: str(in_.flowId),
      connection_id: str(in_.connectionId),
      fixture: str(in_.fixture),
    });

    this.json(res, { ok: true, configPath });
  }

  // ── POST /api/scenarios/{id}/start ──────────────────────────────────────

  /**
   * Trigger the flow run. Build the service Client from the persisted config file, construct the
   * bindings via the intended SDK surface (company → identity().company_user_id; customer →
   * Connection.personId), call triggerFlowRun, and store the returned platform flowRunId in the demo
   * run file. Returns {runId, action:{"type":"none"}} — the drive happens on the GET /api/runs poll.
   */
  private async start(id: string, res: ServerResponse): Promise<void> {
    if (!this.isKnownScenario(id)) return this.json(res, { error: 'not_found' }, 404);
    // The run is built from the persisted config file, not the request body.
    if (!this.rt.hasConfig(STORE_ID)) return this.json(res, { error: 'not_configured' }, 409);

    const meta = this.rt.readConfigMeta(STORE_ID);
    const flowId = str(meta.flow_id);
    const connectionId = str(meta.connection_id);
    if (flowId === '' || connectionId === '') {
      return this.json(res, { error: 'not_configured', message: 'flow id and connection id are required' }, 409);
    }

    const calls: string[] = [];
    let flowRunId: string;
    try {
      const client = this.serviceClient();

      // The COMPANY party binds to this service's own company_user_id.
      const identity = await client.identity();
      calls.push('Client.identity');
      const companyUserId = identity.company_user_id;
      if (companyUserId === '') {
        return this.json(res, { error: 'identity_error', message: 'identity() returned no company_user_id' }, 502);
      }

      // The CUSTOMER party binds to the connected person's public personId.
      const connection = await client.connection(connectionId);
      calls.push('Client.connection');
      const personId = connection.personId;
      if (personId === '') {
        return this.json(
          res,
          { error: 'connection_error', message: `connection ${connectionId} has no personId (not found or not connected)` },
          502,
        );
      }

      const bindings = { [PARTY_COMPANY]: companyUserId, [PARTY_CUSTOMER]: personId };
      const flowRun = await client.triggerFlowRun(flowId, { connectionId, bindings });
      calls.push('Client.triggerFlowRun');

      flowRunId = flowRun.id;
      if (flowRunId === '') {
        return this.json(res, { error: 'trigger_error', message: 'triggerFlowRun returned no run id' }, 502);
      }
    } catch (e) {
      if (e instanceof ApiError || e instanceof ConfigError) {
        return this.json(res, { error: 'start_failed', message: e.message }, 502);
      }
      throw e;
    }

    const runId = this.rt.newRunId();
    this.rt.writeRun(runId, {
      scenario: STORE_ID,
      flowRunId,
      steps: [],
      rejectedNodes: [],
      calls,
      completed: false,
    });

    this.json(res, { runId, action: { type: 'none' } });
  }

  // ── GET /api/runs/{runId} ────────────────────────────────────────────────

  /**
   * The idempotent, short-cycled poll that IS the drive loop and the resume. Reads the platform run;
   * if it is the company's turn drives exactly ONE step; on completion fetches the answers and
   * (document-mode) downloads the generated contract. A terminal run returns its cached result on every
   * poll until TTL/Clear.
   */
  private async run(runId: string, res: ServerResponse): Promise<void> {
    let run = this.rt.readRun(runId);
    if (run === null) return this.json(res, { error: 'not_found' }, 404);

    // Idempotent: once terminal (completed OR errored) the outcome is returned unchanged on every
    // subsequent poll — a failed run must stay failed, not re-drive the platform.
    const terminal = run.completed === true || run.error !== undefined;
    if (!terminal) {
      run = await this.advance(run);
      this.rt.writeRun(runId, run);
    }

    this.json(res, this.result(run));
  }

  /** One poll's worth of work. Returns the (possibly mutated) run record. */
  private async advance(run: RunRecord): Promise<RunRecord> {
    const flowRunId = str(run.flowRunId);
    if (flowRunId === '') {
      run.status = 'error';
      run.error = 'run has no platform flowRunId';
      return run;
    }

    try {
      const client = this.serviceClient();
      const flowRun = await client.flowRun(flowRunId);
      run.calls = this.addCall(run.calls, 'Client.flowRun');

      const status = flowRun.status ?? '';
      const companyParty = flowRun.companyPartyKey;
      const companyTurn = companyParty !== null && status === `awaiting_${companyParty}`;

      if (status === 'completed') {
        return await this.complete(run, client, flowRun, flowRunId);
      }
      if (companyTurn) {
        return await this.driveStep(run, client, flowRun, flowRunId);
      }
      if (status.startsWith('awaiting_')) {
        // The person's turn (or the phone signature) — wait; the next poll resumes automatically.
        run.status = 'waiting_person';
        return run;
      }
      // Any transient in-between state (e.g. generating) — keep polling.
      run.status = 'running';
      return run;
    } catch (e) {
      if (e instanceof ApiError || e instanceof ConfigError) {
        run.status = 'error';
        run.error = e.message;
        return run;
      }
      throw e;
    }
  }

  /**
   * Drive ONE company step via processFlowRun. The validation demo: for an email field whose node has
   * not yet been rejected once, fillNode returns the canned INVALID value, which processFlowRun rejects
   * with a ValidationError BEFORE any submit — recorded as accepted:false without advancing. The next
   * poll (node marked rejected) fills the VALID value → advances → accepted:true.
   */
  private async driveStep(
    run: RunRecord,
    client: Client,
    flowRun: FlowRun,
    flowRunId: string,
  ): Promise<RunRecord> {
    const nodeKey = flowRun.currentNode ?? '';
    const rejectedNodes = ((run.rejectedNodes as unknown[]) ?? []).map(String);

    const filled: { slug: string; type: string; submitted: string }[] = [];
    const fillNode = (node: Record<string, unknown>): Record<string, unknown> => {
      const nk = str(node.key);
      const fill: Record<string, unknown> = {};
      const elements = Array.isArray(node.elements) ? node.elements : [];
      for (const el of elements) {
        if (el === null || typeof el !== 'object' || (el as Record<string, unknown>).kind !== 'field') continue;
        const slug = str((el as Record<string, unknown>).slug);
        if (slug === '') continue;
        const ftype = str((el as Record<string, unknown>).field_type) || 'text';
        const rejectDemo = ftype === 'email' && !rejectedNodes.includes(nk);
        const value = rejectDemo ? INVALID_EMAIL : cannedValue(ftype);
        fill[slug] = value;
        filled.push({ slug, type: ftype, submitted: value });
      }
      return fill;
    };

    const steps = (run.steps as unknown[]) ?? [];
    try {
      await client.processFlowRun(flowRunId, fillNode);
      run.calls = this.addCall(run.calls, 'Client.processFlowRun');
      // Advanced: every field filled for this node was accepted.
      for (const f of filled) {
        steps.push({ slug: f.slug, type: f.type, submitted: f.submitted, accepted: true });
      }
      run.steps = steps;
      run.status = 'running';
      return run;
    } catch (e) {
      if (!(e instanceof ValidationError)) throw e;
      // The canned invalid value was rejected BEFORE submit — record it and mark the node so the next
      // poll submits the valid value. The node did NOT advance.
      run.calls = this.addCall(run.calls, 'Client.processFlowRun');
      let submitted = INVALID_EMAIL;
      for (const f of filled) {
        if (f.slug === e.slug) {
          submitted = f.submitted;
          break;
        }
      }
      steps.push({
        slug: e.slug ?? '',
        type: e.fieldType ?? 'email',
        submitted,
        accepted: false,
        error: e.message,
      });
      run.steps = steps;
      if (nodeKey !== '' && !rejectedNodes.includes(nodeKey)) rejectedNodes.push(nodeKey);
      run.rejectedNodes = rejectedNodes;
      run.status = 'running';
      return run;
    }
  }

  /**
   * Terminal: fetch the decrypted answers and, for a document-mode run, download the generated
   * contract's company copy (flowRunDocument — the run-scoped, service-key-decryptable surface).
   */
  private async complete(
    run: RunRecord,
    client: Client,
    flowRun: FlowRun,
    flowRunId: string,
  ): Promise<RunRecord> {
    const answers = await client.flowRunAnswers(flowRun);
    run.calls = this.addCall(run.calls, 'Client.flowRunAnswers');
    run.answers = Object.entries(answers).map(([slug, value]) => ({ slug, value }));

    if (flowRun.outputMode === 'document') {
      try {
        const bytes = await client.flowRunDocument(flowRunId);
        run.calls = this.addCall(run.calls, 'Client.flowRunDocument');
        run.document = { status: 'downloaded', downloaded: true, bytes: bytes.length };
      } catch (e) {
        if (!(e instanceof ApiError)) throw e;
        // The run completed but the document is not retrievable yet — report it, don't fail.
        run.document = { status: 'unavailable', downloaded: false, error: e.message };
      }
    }

    run.status = 'completed';
    run.completed = true;
    return run;
  }

  /**
   * The GET /api/runs/{runId} response: the SHARED run envelope (outer
   * {status:"pending"|"done"|"failed", result?, error?, calls}) with the pinned FLOW shape nested under
   * `result` ({status:"running"|"waiting_person"|"completed", steps, answers?, document?}). The shared
   * frontend reads progress ONLY from `run.result` and keeps polling ONLY while the outer status is
   * "pending", so the inner flow status must NOT sit at the top level — it drives under "pending" until
   * the platform run completes ("done") or errors ("failed").
   */
  private result(run: RunRecord): Record<string, unknown> {
    const flowStatus = str(run.status) || 'running';
    const outer = run.error !== undefined ? 'failed' : flowStatus === 'completed' ? 'done' : 'pending';

    const result: Record<string, unknown> = {
      status: flowStatus,
      steps: (run.steps as unknown[]) ?? [],
    };
    if (run.answers !== undefined) result.answers = run.answers;
    if (run.document !== undefined) result.document = run.document;

    const out: Record<string, unknown> = { status: outer, result, calls: run.calls ?? [] };
    if (run.error !== undefined) out.error = run.error;
    return out;
  }

  // ── SDK client builder — built from the persisted config FILE ─────────────

  /** Build the service data client OFF the scenario's config file (service role, Config.fromFile). */
  private serviceClient(): Client {
    return Client.fromConfig(this.rt.configPathFor(STORE_ID));
  }

  /** Append a call name preserving first-occurrence order (a poll may repeat flowRun across polls). */
  private addCall(calls: string[] | undefined, name: string): string[] {
    const out = (calls ?? []).map(String);
    if (!out.includes(name)) out.push(name);
    return out;
  }

  // ── HTTP plumbing ─────────────────────────────────────────────────────────

  private async body(req: IncomingMessage): Promise<Record<string, unknown>> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString('utf8');
    if (raw === '') return {};
    try {
      const decoded = JSON.parse(raw);
      return decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : {};
    } catch {
      return {};
    }
  }

  private json(res: ServerResponse, data: unknown, status = 200): void {
    const body = JSON.stringify(data);
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(body);
  }

  private serveStatic(path: string, res: ServerResponse): void {
    const root = resolve(this.frontendDir);
    const rel = path === '/' ? '/index.html' : path;
    const full = resolve(join(root, normalize(rel)));

    // Path-traversal guard + SPA fallback to index.html.
    if ((full === root || full.startsWith(root + sep)) && existsSync(full) && statSync(full).isFile()) {
      res.writeHead(200, { 'Content-Type': MIME[extname(full).toLowerCase()] ?? 'application/octet-stream' });
      createReadStream(full).pipe(res);
      return;
    }
    const index = join(root, 'index.html');
    if (existsSync(index)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      createReadStream(index).pipe(res);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('bundle not found');
  }
}

/** A canned VALID plaintext for a field type (demo values over already-supported answerable types). */
function cannedValue(ftype: string): string {
  switch (ftype) {
    case 'email':
      return 'billing@acme.example';
    case 'number':
      return '42';
    case 'boolean':
      return 'true';
    case 'date':
      return '2024-01-15';
    case 'date_of_birth':
      return '1990-05-01';
    case 'phone':
      return '+31201234567';
    case 'url':
      return 'https://acme.example';
    case 'address':
      return JSON.stringify({ street: 'Herengracht 1', city: 'Amsterdam', postal_code: '1011AB', country: 'NL' });
    default:
      return 'Acme Corporation';
  }
}

/** Coerce any config/body value to a string (missing → ''). */
function str(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}
