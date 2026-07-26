import type { IncomingMessage, ServerResponse } from 'node:http';

import { BinaryHandle, Client, WebhookError, type Change, type Headers } from '@allus-fyi/company-data';

import { Runtime, type RunRecord } from '../runtime.js';
import { TimeoutTransport } from '../timeoutTransport.js';
import { headerValue, readRawBody, sendJson, sendText, str } from '../http.js';

/**
 * The COMPANY-DATA scenario family (contract v3). Every scenario runs the SERVICE-role data {@link Client}
 * built from the persisted config file — there is NO OAuth/OIDC leg (no /callback, no /enroll). Each
 * handler reaches the SDK's intended top-level surface only; the scaffolding lives in src/.
 *
 *   read        — Client.connections()          → connection-grouped decrypted values
 *   definitions — Client.requestFields()         → your request-field catalog
 *   changes     — Client.processChanges()        → a crash-safe pump drain (idempotent on Change.id)
 *   webhook     — verifyWebhook() + parseWebhook() → a public POST /webhook receiver + a drainBatch()
 *                                                  feed fallback; ONE accumulating run keyed by webhook id
 *   documents   — Client.createDocument() ×6      → the six document/contract types
 *
 * Settings flow (config-file model): the browser POSTs a scenario's setup values to
 * POST /api/scenarios/{id}/config, which writes them to a canonical SDK config FILE
 * (.runtime/config/{sid}.json). /start builds the Client from that file (Client.fromConfig →
 * Config.fromFile) and runs OFF it. A /start with no saved config → 409 not_configured.
 */

const READ = 'companydata:read';
const DEFINITIONS = 'companydata:definitions';
const CHANGES = 'companydata:changes';
const WEBHOOK = 'companydata:webhook';
const DOCUMENTS = 'companydata:documents';

/** id => "runnable". Every company-data scenario runs synchronously (data) or accumulates (webhook). */
const SCENARIOS: Record<string, 'runnable'> = {
  [READ]: 'runnable',
  [DEFINITIONS]: 'runnable',
  [CHANGES]: 'runnable',
  [WEBHOOK]: 'runnable',
  [DOCUMENTS]: 'runnable',
};

/** Scenarios whose SDK Client uses the pump (needs a cache_dir for its buffer/dead-letters). */
const PUMP_SCENARIOS = new Set([CHANGES, WEBHOOK]);

const DEFAULT_API_URL = 'https://api.allme.fyi';

/** Short HTTP timeout (ms) for the per-poll drainBatch() feed fetch — bounds one worker per poll. */
const FEED_TIMEOUT_MS = 2000;

export class CompanyDataHandler {
  constructor(private readonly rt: Runtime) {}

  /** The company-data scenarios for GET /api/meta (the five service-role cards). */
  scenarios(): { id: string; kind: string }[] {
    return Object.entries(SCENARIOS).map(([id, kind]) => ({ id, kind }));
  }

  /** True when this family owns the scenario id. */
  owns(id: string): boolean {
    return SCENARIOS[id] !== undefined;
  }

  /** True when a stored run belongs to this family. */
  ownsRun(run: RunRecord): boolean {
    return String(run.scenario ?? '').startsWith('companydata:');
  }

  // ── POST /api/scenarios/{id}/config ─────────────────────────────────────

  /**
   * Write the browser's setup values to a canonical SDK config FILE. Every company-data scenario uses the
   * SERVICE-role Client, so the config always carries client_id/secret + the service PEM (by path) +
   * passphrase. The webhook scenario adds the webhooks:{id:secret} map (the SDK selects the secret by the
   * X-Allus-Webhook-Id header) and records the webhook id in a meta sidecar (the routing key /start
   * needs). The documents scenario records the target share code in the sidecar.
   */
  async config(id: string, _host: string, in_: Record<string, unknown>, res: ServerResponse): Promise<void> {
    if (SCENARIOS[id] !== 'runnable') return sendJson(res, { error: 'not_found' }, 404);

    // Canonical SDK config — the service role for every company-data scenario (sdk.html §2).
    const cfg: Record<string, unknown> = {
      api_url: (str(in_.apiUrl) || DEFAULT_API_URL).replace(/\/+$/, ''),
      client_id: str(in_.clientId),
      client_secret: str(in_.clientSecret),
      key_passphrase: str(in_.keyPassphrase),
    };
    const pem = str(in_.servicePrivateKeyPem);
    if (pem !== '') cfg.service_private_key = this.rt.materializeConfigKey(pem);

    // Pump scenarios persist their buffer/dead-letters under .runtime/cache (Config.cacheDir).
    if (PUMP_SCENARIOS.has(id)) cfg.cache_dir = this.rt.cacheDir;

    const meta: Record<string, unknown> = {};
    if (id === WEBHOOK) {
      // The verifier selects the secret by the delivery's X-Allus-Webhook-Id header, so the config's
      // webhooks map must be keyed by the real webhook id.
      const webhookId = str(in_.webhookId);
      const secret = str(in_.webhookSecret);
      if (webhookId !== '' && secret !== '') cfg.webhooks = { [webhookId]: secret };
      if (webhookId !== '') meta.webhook_id = webhookId; // the routing key /start writes into the route
    }
    if (id === DOCUMENTS) meta.share_code = str(in_.shareCode); // the per-person/contract target

    const configPath = this.rt.writeConfig(id, cfg);
    this.rt.writeConfigMeta(id, meta);

    sendJson(res, { ok: true, configPath });
  }

  // ── POST /api/scenarios/{id}/start ──────────────────────────────────────

  async start(id: string, _host: string, res: ServerResponse): Promise<void> {
    if (SCENARIOS[id] !== 'runnable') return sendJson(res, { error: 'not_found' }, 404);
    if (!this.rt.hasConfig(id)) return sendJson(res, { error: 'not_configured' }, 409); // built from the file

    if (id === WEBHOOK) return this.startWebhook(res);

    // The four data scenarios run the SDK call synchronously and store the terminal result.
    const runId = this.rt.newRunId();
    const calls: string[] = [];
    try {
      const client = Client.fromConfig(this.rt.configPathFor(id));
      let result: Record<string, unknown>;
      switch (id) {
        case READ:
          result = await this.doRead(client, calls);
          break;
        case DEFINITIONS:
          result = await this.doDefinitions(client, calls);
          break;
        case CHANGES:
          result = await this.doChanges(client, calls);
          break;
        case DOCUMENTS:
          result = await this.doDocuments(client, calls);
          break;
        default:
          return sendJson(res, { error: 'not_found' }, 404);
      }
      this.rt.writeRun(runId, { scenario: id, status: 'done', result, calls });
    } catch (e) {
      this.rt.writeRun(runId, { scenario: id, status: 'failed', error: (e as Error).message, calls });
    }
    sendJson(res, { runId, action: { type: 'data' } });
  }

  /**
   * companydata:read — Client.connections() grouped BY connection (one card per connected person), so
   * two people who both filled the same slug stay distinguishable.
   */
  private async doRead(client: Client, calls: string[]): Promise<Record<string, unknown>> {
    const connections: unknown[] = [];
    for await (const conn of client.connections()) {
      const values = Object.entries(conn.values).map(([slug, v]) => ({
        slug,
        value: valueToJson(v.value),
        live: v.live,
        at: v.updatedAt?.toISOString() ?? null,
      }));
      connections.push({
        connectionId: conn.id,
        personId: conn.personId,
        displayName: conn.displayName,
        customerType: conn.customerType,
        shareCode: conn.shareCode,
        values,
      });
    }
    calls.push('Client.connections');
    return { connections };
  }

  /**
   * companydata:definitions — Client.requestFields() → your request-field catalog (the folded mandatory
   * bool + one_time; the raw split flags are debug-only, off the intended surface).
   */
  private async doDefinitions(client: Client, calls: string[]): Promise<Record<string, unknown>> {
    const fields = (await client.requestFields()).map((f) => ({
      slug: f.slug,
      label: f.label,
      type: f.type,
      mandatory: f.mandatory,
      one_time: f.oneTime,
    }));
    calls.push('Client.requestFields');
    return { fields };
  }

  /**
   * companydata:changes — Client.processChanges() drains the feed on start through the crash-safe pump
   * (handler-before-ack, at-least-once), so the append handler is idempotent on the pull-feed Change.id.
   * Each event is the rendered-column projection PLUS a raw object with the full public Change fields.
   */
  private async doChanges(client: Client, calls: string[]): Promise<Record<string, unknown>> {
    const events: unknown[] = [];
    const seen = new Set<string>();
    await client.processChanges((c: Change) => {
      if (c.id) {
        if (seen.has(c.id)) return; // idempotent: the pump may replay after a crash — dedup on Change.id
        seen.add(c.id);
      }
      events.push(this.projectChange(c, null));
    });
    calls.push('Client.processChanges');
    return { events, drained: true };
  }

  /**
   * companydata:documents — Client.createDocument() for each of the six document/contract types (payloads
   * verbatim from apitests/php/documents.php). The per-person / private / contract types target the
   * connected person by share code (from the setup sidecar).
   */
  private async doDocuments(client: Client, calls: string[]): Promise<Record<string, unknown>> {
    const shareCode = str(this.rt.readConfigMeta(DOCUMENTS).share_code);
    const pdf = minimalPdf;
    type Spec = { label: string; perPerson: boolean; opts: Parameters<Client['createDocument']>[0] };
    const specs: Spec[] = [
      {
        label: 'Broadcast plaintext JSON (no target)',
        perPerson: false,
        opts: { name: 'Service notice', payloadKind: 'json', jsonValue: { msg: 'Scheduled maintenance Sunday' } },
      },
      {
        label: 'Broadcast PDF file (no target)',
        perPerson: false,
        opts: { name: 'Price list', payloadKind: 'file', fileBytes: pdf('Price list'), fileMime: 'application/pdf' },
      },
      {
        label: 'Per-person NON-private file',
        perPerson: true,
        opts: { name: 'Your invoice', payloadKind: 'file', fileBytes: pdf('Your invoice'), fileMime: 'application/pdf' },
      },
      {
        label: 'Per-person PRIVATE file (lock → reveal)',
        perPerson: true,
        opts: {
          name: 'Confidential report',
          payloadKind: 'file',
          isPrivate: true,
          fileBytes: pdf('Confidential report'),
          fileMime: 'application/pdf',
        },
      },
      {
        label: 'CONTRACT requiring SIGNATURE',
        perPerson: true,
        opts: {
          name: 'Service agreement',
          kind: 'agreement',
          payloadKind: 'file',
          requiresSignature: true,
          fileBytes: pdf('Service agreement'),
          fileMime: 'application/pdf',
          metadata: { can_be_cancelled_in_app: true },
        },
      },
      {
        label: 'CONTRACT requiring ACCEPTANCE',
        perPerson: true,
        opts: {
          name: 'Terms update',
          kind: 'agreement',
          payloadKind: 'json',
          requiresAcceptance: true,
          jsonValue: { version: '2.0' },
          metadata: {
            plan_name: 'Pro Plan',
            price: '9.99',
            currency: 'EUR',
            renewal_term: 'Monthly',
            renewal_date: '2026-07-30',
            valid_until: '2027-06-30',
            can_be_cancelled_in_app: true,
            management_url: 'https://example.com/manage',
          },
        },
      },
    ];

    const docs: unknown[] = [];
    for (let i = 0; i < specs.length; i++) {
      const spec = specs[i];
      const opts = { ...spec.opts };
      if (spec.perPerson) {
        if (shareCode === '') {
          throw new Error(
            'this document type targets a connected person — set a target person share code in the setup, then re-run',
          );
        }
        opts.shareCode = shareCode;
      }
      const doc = await client.createDocument(opts);
      docs.push({ index: i + 1, label: spec.label, document_id: doc.id, status: doc.status });
    }
    calls.push(`Client.createDocument ×${specs.length}`);
    return { docs };
  }

  // ── companydata:webhook — the accumulating run + public receiver ──────────

  /**
   * Start the single accumulating webhook run. Persists the routing record webhookId → runId (superseding
   * any prior active webhook run) and returns {action:{type:"none"}} — there is NO long-poll (it would
   * wedge the single worker). Events arrive via POST /webhook and via a per-poll drainBatch() feed
   * fallback; the frontend reads the growing list through GET /api/runs.
   */
  private startWebhook(res: ServerResponse): void {
    const webhookId = str(this.rt.readConfigMeta(WEBHOOK).webhook_id);
    if (webhookId === '') return sendJson(res, { error: 'not_configured' }, 409);
    const runId = this.rt.newRunId();
    this.rt.writeRun(runId, {
      scenario: WEBHOOK,
      status: 'pending', // accumulating — the v1 enum is unchanged
      webhookId,
      events: [],
      seenFeedIds: [], // feed-only dedup set for the drainBatch() fallback
      unparseable: 0,
      calls: ['(webhook run started — POST /webhook receives; each poll also drainBatch()s the feed)'],
    });
    this.rt.writeRoute(webhookId, runId);
    sendJson(res, { runId, action: { type: 'none' } });
  }

  /**
   * POST /webhook — the PUBLIC inbound delivery. The exact call/status sequence (NEVER the combined
   * handleWebhook(), which throws one WebhookError for BOTH a bad HMAC and a parse failure):
   *   (1) read X-Allus-Webhook-Id; unknown/stale id or no active run → 200 acknowledge-and-discard.
   *   (2) verifyWebhook(): false → 401 (a genuine signature failure; misconfiguration should be loud).
   *   (3) parseWebhook(): success → append (source:"webhook") + 200; a WebhookError here is a
   *       VERIFIED-but-unparseable delivery → 200 acknowledge-and-note (increment unparseable) — NOT 401.
   * All accepted-and-dropped cases return 200 because the platform worker counts EXACTLY 200 as success.
   */
  async webhook(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const rawBody = await readRawBody(req);
    const headers = req.headers as Headers;
    const webhookId = headerValue(req.headers['x-allus-webhook-id']);

    const route = this.rt.readRoute();
    if (route === null || webhookId === null || webhookId !== route.webhookId) {
      return sendText(res, 'discarded: unknown or stale webhook id', 200);
    }
    const run = this.rt.readRun(route.runId);
    if (run === null) return sendText(res, 'discarded: no active webhook run', 200);

    const client = Client.fromConfig(this.rt.configPathFor(WEBHOOK));
    this.recordCall(run, 'Client.verifyWebhook');
    if (!client.verifyWebhook(rawBody, headers)) {
      // A genuine signature failure — persist the attempted verify so the calls trace stays truthful.
      this.rt.writeRun(route.runId, run);
      return sendText(res, 'signature verification failed', 401);
    }
    try {
      this.recordCall(run, 'Client.parseWebhook');
      const change = client.parseWebhook(rawBody, headers);
      (run.events as unknown[]).push(this.projectChange(change, 'webhook'));
    } catch (e) {
      if (!(e instanceof WebhookError)) throw e;
      // Verified but unparseable/undecryptable — acknowledge (200) and note it in the raw view.
      run.unparseable = Number(run.unparseable ?? 0) + 1;
      (run.events as unknown[]).push({
        source: 'webhook',
        event: null,
        id: null,
        note: 'received, could not parse',
        raw: { error: (e as Error).message },
      });
    }
    this.rt.writeRun(route.runId, run);
    sendText(res, 'ok', 200);
  }

  // ── GET /api/runs/{runId} ────────────────────────────────────────────────

  async runRespond(runId: string, run: RunRecord, _host: string, res: ServerResponse): Promise<void> {
    // The accumulating webhook run: each poll also does ONE immediate drainBatch() raw feed fetch (NOT
    // processChanges(), which loops the pump to empty and could stall the single worker) so events
    // generated AFTER start still appear in deployed-no-tunnel mode.
    if (String(run.scenario ?? '') === WEBHOOK) {
      run = await this.webhookFeedFallback(runId, run);
      return sendJson(res, {
        status: run.status ?? 'pending',
        calls: run.calls ?? [],
        result: {
          webhookId: run.webhookId ?? '',
          events: run.events ?? [],
          unparseable: Number(run.unparseable ?? 0),
        },
      });
    }

    const out: Record<string, unknown> = { status: run.status ?? 'pending', calls: run.calls ?? [] };
    if (run.result !== undefined) out.result = run.result;
    if (run.error !== undefined) out.error = run.error;
    sendJson(res, out);
  }

  /**
   * One immediate drainBatch() fetch per poll for the active webhook run, appending new source:"feed"
   * events deduped on the pull-feed Change.id (a feed-only seen-id set in run state). Only the CURRENT
   * active run pulls (a superseded run stops receiving). A transport/API error is swallowed so a
   * blackholed feed never fails the accumulating run — the webhook path still works.
   */
  private async webhookFeedFallback(runId: string, run: RunRecord): Promise<RunRecord> {
    const route = this.rt.readRoute();
    if (route === null || route.runId !== runId) return run; // superseded/cleared — this run no longer pulls

    const seen = new Set<string>((run.seenFeedIds as string[] | undefined) ?? []);
    try {
      const client = Client.fromConfig(this.rt.configPathFor(WEBHOOK), {
        httpOptions: { transport: new TimeoutTransport(FEED_TIMEOUT_MS) },
      });
      // Every poll ATTEMPTS the feed pull — record the call now (deduped), so an empty poll still reports
      // the drainBatch it performed rather than claiming no call.
      const drainNew = this.recordCall(run, 'Client.drainBatch');
      let appended = false;
      for (const change of await client.drainBatch()) {
        if (change.id) {
          if (seen.has(change.id)) continue;
          seen.add(change.id);
          (run.seenFeedIds as string[]).push(change.id);
        }
        (run.events as unknown[]).push(this.projectChange(change, 'feed'));
        appended = true;
      }
      if (appended || drainNew) this.rt.writeRun(runId, run);
    } catch {
      // A blackholed/failed feed fetch must not fail the accumulating webhook run.
    }
    return run;
  }

  /**
   * Append an SDK-call name to a run's "what just happened" trace, deduped so the panel stays small no
   * matter how many deliveries/polls a call is attempted across. Returns true when the name was newly
   * added (so the caller can persist on that transition).
   */
  private recordCall(run: RunRecord, name: string): boolean {
    const calls = (run.calls as string[] | undefined) ?? (run.calls = []);
    if (calls.includes(name)) return false;
    calls.push(name);
    return true;
  }

  // ── Change projection ──────────────────────────────────────────────────

  /**
   * The rendered-column projection of a Change PLUS a raw object holding the full public Change fields,
   * so the frontend's JSON.stringify(result) Raw view can show the event-specific extras. Nothing is
   * dropped from result. `source` labels a webhook delivery vs a pull-feed row (null for the changes
   * scenario, where every row is a pull-feed drain).
   */
  private projectChange(c: Change, source: 'webhook' | 'feed' | null): Record<string, unknown> {
    const at = c.at?.toISOString() ?? null;
    const event: Record<string, unknown> = {
      event: c.event,
      personId: c.personId,
      shareCode: c.shareCode,
      customerType: c.customerType,
      slug: c.slug,
      value: valueToJson(c.value),
      live: c.live,
      at,
      documentId: c.documentId,
      status: c.status,
      action: c.action,
      id: c.id,
      raw: {
        id: c.id,
        event: c.event,
        personId: c.personId,
        shareCode: c.shareCode,
        customerType: c.customerType,
        slug: c.slug,
        value: valueToJson(c.value),
        live: c.live,
        documentId: c.documentId,
        status: c.status,
        action: c.action,
        note: c.note,
        method: c.method,
        contentSha256: c.contentSha256,
        signedAt: c.signedAt,
        cancelEffectiveDate: c.cancelEffectiveDate,
        requestId: c.requestId,
        publicKeySha256: c.publicKeySha256,
        verified: c.verified,
        at,
      },
    };
    return source !== null ? { source, ...event } : event;
  }
}

// ── module helpers ──────────────────────────────────────────────────────────

/**
 * Render a decrypted value for JSON. A binary value is a lazy {@link BinaryHandle} — render a short
 * descriptor (its bytes are resolved lazily/async, not dumped into the result); a Date is ISO-8601; a
 * structured value stays an object/array (the frontend JSON-stringifies it).
 */
function valueToJson(v: unknown): unknown {
  if (v === null || v === undefined) return null;
  if (v instanceof Date) return v.toISOString();
  if (v instanceof BinaryHandle) return '[binary value]';
  if (typeof v === 'bigint') return v.toString();
  return v; // string | number | boolean | object | array
}

/**
 * A tiny valid one-page PDF carrying `label` (verbatim shape from apitests/php/documents.php) — so the
 * broadcast/per-person/contract file docs upload real bytes without a fixture file.
 */
function minimalPdf(label: string): Buffer {
  const stream = `BT /F1 18 Tf 40 90 Td (${label.replace(/\(/g, '[').replace(/\)/g, ']')}) Tj ET`;
  const objs: Record<number, string> = {
    1: '<< /Type /Catalog /Pages 2 0 R >>',
    2: '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    3: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 420 160] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    4: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    5: `<< /Length ${Buffer.byteLength(stream, 'utf8')} >>\nstream\n${stream}\nendstream`,
  };
  let pdf = '%PDF-1.4\n';
  const offsets: Record<number, number> = {};
  const nums = Object.keys(objs).map(Number);
  for (const n of nums) {
    offsets[n] = Buffer.byteLength(pdf, 'utf8');
    pdf += `${n} 0 obj\n${objs[n]}\nendobj\n`;
  }
  const xrefPos = Buffer.byteLength(pdf, 'utf8');
  pdf += `xref\n0 ${nums.length + 1}\n0000000000 65535 f \n`;
  for (const n of nums) pdf += `${String(offsets[n]).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${nums.length + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF`;
  return Buffer.from(pdf, 'utf8');
}
