import type { IncomingMessage, ServerResponse } from 'node:http';

import { Runtime, type RunRecord } from './runtime.js';
import { readJsonBody, sendJson, serveStatic } from './http.js';
import { IdentityHandler } from './handlers/identity.js';
import { FlowHandler } from './handlers/flow.js';
import { CompanyDataHandler } from './handlers/companyData.js';

/**
 * The ONE example-test-suite server (demo-backend contract v3). A single class, a single worker (Node's
 * built-in http): HTTP dispatch → the scenario's FAMILY handler → the SDK's intended top-level surface.
 * It serves the static bundle + the whole contract API + the identity OAuth `/callback` + the public
 * company-data `POST /webhook`, all on ONE port.
 *
 * This file is pure scaffolding: routing, the aggregated GET /api/meta, Clear, the static bundle, and the
 * dispatch to the three families. The SDK calls live in src/handlers/{identity,flow,companyData}.ts —
 * open a family's handler and you see exactly which SDK call implements each scenario.
 *
 * Scenario-id → family: integer ids (1–8) → identity, `flow:*` → flow, `companydata:*` → company-data.
 * A GET /api/runs/{runId} poll is dispatched by the run's stored scenario, so the three families' runs
 * live in ONE `.runtime/` without colliding (config/run/meta files are keyed by the public scenario id).
 */

export const CONTRACT_VERSION = 3;
export const SDK = 'typescript';

export class Server {
  private readonly identity: IdentityHandler;
  private readonly flow: FlowHandler;
  private readonly companyData: CompanyDataHandler;

  constructor(
    private readonly rt: Runtime,
    private readonly frontendDir: string,
    private readonly sdkVersion: string,
    private readonly port: number,
  ) {
    this.identity = new IdentityHandler(rt);
    this.flow = new FlowHandler(rt);
    this.companyData = new CompanyDataHandler(rt);
  }

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
      } else if (path === '/callback' && method === 'GET') {
        await this.identity.callback(url, host, res); // identity OAuth/OIDC redirect leg
      } else if (path === '/webhook' && method === 'POST') {
        await this.companyData.webhook(req, res); // PUBLIC company-data inbound delivery (not under /api/)
      } else if (path === '/api/clear' && method === 'POST') {
        this.rt.clearAll();
        sendJson(res, { ok: true });
      } else if ((m = path.match(/^\/api\/scenarios\/([\w:.-]+)\/config$/)) && method === 'POST') {
        await this.dispatchConfig(m[1], host, req, res);
      } else if ((m = path.match(/^\/api\/scenarios\/([\w:.-]+)\/start$/)) && method === 'POST') {
        await this.dispatchStart(m[1], host, res);
      } else if ((m = path.match(/^\/api\/scenarios\/([\w:.-]+)\/enroll$/)) && method === 'POST') {
        await this.dispatchEnroll(m[1], req, res);
      } else if ((m = path.match(/^\/api\/scenarios\/([\w:.-]+)\/clear$/)) && method === 'POST') {
        this.dispatchClearScenario(m[1], res);
      } else if ((m = path.match(/^\/api\/runs\/([0-9a-f]{32})$/)) && method === 'GET') {
        await this.dispatchRun(m[1], host, res);
      } else if (path.startsWith('/api/')) {
        sendJson(res, { error: 'not_found' }, 404);
      } else {
        serveStatic(this.frontendDir, path, res);
      }
    } catch (e) {
      // A start-time / handler failure surfaces as a NON-2xx the shared client raises — never a 200
      // without the success envelope.
      sendJson(res, { error: 'server_error', message: (e as Error).message }, 500);
    }
  }

  // ── GET /api/meta ──────────────────────────────────────────────────────

  /** ALL scenarios of ALL three families: identity 1–8 (7 = guide), flow:run, the five companydata:*. */
  private meta(res: ServerResponse): void {
    const scenarios = [
      ...this.identity.scenarios(),
      ...this.flow.scenarios(),
      ...this.companyData.scenarios(),
    ];
    sendJson(res, { sdk: SDK, sdkVersion: this.sdkVersion, contractVersion: CONTRACT_VERSION, scenarios });
  }

  // ── dispatch ─────────────────────────────────────────────────────────────

  private async dispatchConfig(id: string, host: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    const in_ = await readJsonBody(req);
    if (this.identity.owns(id)) return this.identity.config(id, host, in_, res);
    if (this.flow.owns(id)) return this.flow.config(id, host, in_, res);
    if (this.companyData.owns(id)) return this.companyData.config(id, host, in_, res);
    sendJson(res, { error: 'not_found' }, 404);
  }

  private async dispatchStart(id: string, host: string, res: ServerResponse): Promise<void> {
    if (this.identity.owns(id)) return this.identity.start(id, host, res);
    if (this.flow.owns(id)) return this.flow.start(id, host, res);
    if (this.companyData.owns(id)) return this.companyData.start(id, host, res);
    sendJson(res, { error: 'not_found' }, 404);
  }

  /** Enrollment is an identity-only leg (scenario 8). */
  private async dispatchEnroll(id: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.identity.owns(id)) return sendJson(res, { error: 'not_found' }, 404);
    const in_ = await readJsonBody(req);
    return this.identity.enroll(id, in_, res);
  }

  /** Per-scenario clear — the runtime handles config/run/meta/keys (and the webhook route) uniformly. */
  private dispatchClearScenario(id: string, res: ServerResponse): void {
    if (!this.identity.owns(id) && !this.flow.owns(id) && !this.companyData.owns(id)) {
      return sendJson(res, { error: 'not_found' }, 404);
    }
    this.rt.clearScenario(id);
    sendJson(res, { ok: true });
  }

  /** GET /api/runs/{runId} — dispatch to the family that owns the stored run. */
  private async dispatchRun(runId: string, host: string, res: ServerResponse): Promise<void> {
    const run: RunRecord | null = this.rt.readRun(runId);
    if (run === null) return sendJson(res, { error: 'not_found' }, 404);
    if (this.identity.ownsRun(run)) return this.identity.runRespond(runId, run, host, res);
    if (this.flow.ownsRun(run)) return this.flow.runRespond(runId, run, host, res);
    if (this.companyData.ownsRun(run)) return this.companyData.runRespond(runId, run, host, res);
    sendJson(res, { error: 'not_found' }, 404);
  }
}
