import type { ServerResponse } from 'node:http';

import { ApiError, Client, ConfigError, FlowRun, ValidationError } from '@allus-fyi/company-data';

import { Runtime, addCall, type RunRecord } from '../runtime.js';
import { sendFailure, sendJson, str } from '../http.js';

/**
 * The FLOW scenario family — the ONE contract-flow scenario "flow:run". Everything the handler does goes
 * through the SDK's intended top-level flow surface (identity / triggerFlowRun / flowRun / processFlowRun /
 * flowRunAnswers / flowRunDocument); the scaffolding (routing, config files, run store, static bundle)
 * lives in src/.
 *
 * There is NO cross-card flow-run-id handoff: the platform flow run lives entirely INSIDE this one demo
 * run's file — the demo runId is the backend run and the platform flowRunId is stored inside it, never
 * exposed as a separate browser input.
 *
 * Settings flow (config-file model): the browser POSTs the scenario's setup values to
 * POST /api/scenarios/flow:run/config, which writes them to a canonical SDK config FILE
 * (.runtime/config/flow_run.json; the service PEM → .runtime/config/keys/ by path). /start builds the
 * service {@link Client} from that file via {@link Client.fromConfig} and runs OFF the config. The request
 * body of /start is ignored; a /start with no saved config → 409 not_configured.
 *
 * The GET /api/runs/{runId} poll is the drive loop AND the resume: each poll reads the platform run and,
 * if it is the company's turn, drives exactly ONE company step; otherwise it reports waiting/running and
 * touches nothing (the next poll after the person answers on their phone resumes automatically).
 */

/** The single public scenario id (the flow family), used as its config/run key too. */
const SCENARIO = 'flow:run';

const DEFAULT_API_URL = 'https://api.allme.fyi';

/** The flow party keys the fixtures pin. */
const PARTY_COMPANY = 'company';
const PARTY_CUSTOMER = 'customer';

/** The canned INVALID value the validation-demo submits once for an email field. */
const INVALID_EMAIL = 'not-an-email';

/**
 * The "what just happened" trace (#578). Every entry is `<SDK method> — <what that call did in THIS
 * scenario>`, appended AT the call site, in the order the calls were made. The annotations are
 * byte-identical in all six SDK examples — only the method reference is written in the language's own
 * idiom — so one scenario teaches one thing whichever example a reader starts. Keep them in step when
 * this handler changes.
 */
const CALL_SERVICE_BUILD =
  'Client.fromConfig — builds the SERVICE-role data client from the saved config file: client credentials plus the service private key, decrypted with its passphrase';
const CALL_IDENTITY =
  "Client.identity — GET /api/company-data/whoami: this service's own company_user_id, which the COMPANY party binds to";
const CALL_CONNECTION =
  "Client.connection — reads the configured connection; the connected person's id on it is what the CUSTOMER party binds to";
const CALL_TRIGGER =
  "Client.triggerFlowRun — starts a run of the published flow for that connection, pinning the flow's latest published version";
const CALL_FLOW_RUN = 'Client.flowRun — re-read on every poll to see whose turn the run is on';
const CALL_PROCESS =
  'Client.processFlowRun — drives ONE company step: decrypts the answers so far, fills the node, type-checks the values, encrypts a copy per party, submits — and generates the document when the submit lands on a document-mode leaf';
const CALL_ANSWERS = "Client.flowRunAnswers — the completed run's answers, decrypted with the service key";
const CALL_DOCUMENT =
  "Client.flowRunDocument — downloads the company's own copy of the generated contract and decrypts it with the service key";


export class FlowHandler {
  constructor(private readonly rt: Runtime) {}

  /** The flow scenarios for GET /api/meta (the single flow:run card). */
  scenarios(): { id: string; kind: string }[] {
    return [{ id: SCENARIO, kind: 'runnable' }];
  }

  /** True when this family owns the scenario id. */
  owns(id: string): boolean {
    return id === SCENARIO;
  }

  /** True when a stored run belongs to this family. */
  ownsRun(run: RunRecord): boolean {
    return String(run.scenario ?? '') === SCENARIO;
  }

  // ── POST /api/scenarios/{id}/config ─────────────────────────────────────

  /**
   * Write the browser's setup values to a canonical SDK config FILE (service role). The service PEM is
   * written to config/keys/ and referenced by path; the demo-only run parameters (published flow id,
   * connection id, fixture choice) go to the meta sidecar so the config file stays a pure SDK config.
   */
  async config(id: string, _host: string, in_: Record<string, unknown>, res: ServerResponse): Promise<void> {
    if (!this.owns(id)) return sendJson(res, { error: 'not_found' }, 404);

    // Canonical SDK config — the service role (client_credentials + service PEM).
    const cfg: Record<string, unknown> = {
      api_url: (str(in_.apiUrl) || DEFAULT_API_URL).replace(/\/+$/, ''),
      client_id: str(in_.clientId),
      client_secret: str(in_.clientSecret),
      key_passphrase: str(in_.keyPassphrase),
    };
    const pem = str(in_.servicePrivateKeyPem);
    if (pem !== '') cfg.service_private_key = this.rt.materializeConfigKey(pem);
    const configPath = this.rt.writeConfig(SCENARIO, cfg);

    // Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
    this.rt.writeConfigMeta(SCENARIO, {
      flow_id: str(in_.flowId),
      connection_id: str(in_.connectionId),
      fixture: str(in_.fixture),
    });

    sendJson(res, { ok: true, configPath });
  }

  // ── POST /api/scenarios/{id}/start ──────────────────────────────────────

  /**
   * Trigger the flow run. Build the service Client from the persisted config file, construct the
   * bindings via the intended SDK surface (company → identity().company_user_id; customer →
   * Connection.personId), call triggerFlowRun, and store the returned platform flowRunId in the demo
   * run file. Returns {runId, action:{"type":"none"}} — the drive happens on the GET /api/runs poll.
   */
  async start(id: string, _host: string, res: ServerResponse): Promise<void> {
    if (!this.owns(id)) return sendJson(res, { error: 'not_found' }, 404);
    // The run is built from the persisted config file, not the request body.
    if (!this.rt.hasConfig(SCENARIO)) return sendJson(res, { error: 'not_configured' }, 409);

    const meta = this.rt.readConfigMeta(SCENARIO);
    const flowId = str(meta.flow_id);
    const connectionId = str(meta.connection_id);
    if (flowId === '' || connectionId === '') {
      return sendJson(res, { error: 'not_configured', message: 'flow id and connection id are required' }, 409);
    }

    const calls: string[] = [];
    let flowRunId: string;
    try {
      calls.push(CALL_SERVICE_BUILD);
      const client = this.serviceClient();

      // The COMPANY party binds to this service's own company_user_id.
      calls.push(CALL_IDENTITY);
      const identity = await client.identity();
      const companyUserId = identity.company_user_id;
      if (companyUserId === '') {
        return sendFailure(res, 'identity() returned no company_user_id', 'identity_error', 502);
      }

      // The CUSTOMER party binds to the connected person's public personId.
      calls.push(CALL_CONNECTION);
      const connection = await client.connection(connectionId);
      const personId = connection.personId;
      if (personId === '') {
        return sendFailure(
          res,
          `connection ${connectionId} has no personId (not found or not connected)`,
          'connection_error',
          502,
        );
      }

      const bindings = { [PARTY_COMPANY]: companyUserId, [PARTY_CUSTOMER]: personId };
      calls.push(CALL_TRIGGER);
      const flowRun = await client.triggerFlowRun(flowId, { connectionId, bindings });

      flowRunId = flowRun.id;
      if (flowRunId === '') {
        return sendFailure(res, 'triggerFlowRun returned no run id', 'trigger_error', 502);
      }
    } catch (e) {
      if (e instanceof ApiError || e instanceof ConfigError) {
        return sendFailure(res, e, 'start_failed', 502);
      }
      throw e;
    }

    const runId = this.rt.newRunId();
    this.rt.writeRun(runId, {
      scenario: SCENARIO,
      flowRunId,
      steps: [],
      rejectedNodes: [],
      calls,
      completed: false,
    });

    sendJson(res, { runId, action: { type: 'none' } });
  }

  // ── GET /api/runs/{runId} ────────────────────────────────────────────────

  /**
   * The idempotent, short-cycled poll that IS the drive loop and the resume. Reads the platform run;
   * if it is the company's turn drives exactly ONE step; on completion fetches the answers and
   * (document-mode) downloads the generated contract. A terminal run returns its cached result on every
   * poll until TTL/Clear.
   */
  async runRespond(runId: string, run: RunRecord, _host: string, res: ServerResponse): Promise<void> {
    // Idempotent: once terminal (completed OR errored) the outcome is returned unchanged on every
    // subsequent poll — a failed run must stay failed, not re-drive the platform.
    const terminal = run.completed === true || run.error !== undefined;
    if (!terminal) {
      run = await this.advance(run);
      this.rt.writeRun(runId, run);
    }

    sendJson(res, this.result(run));
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
      run.calls = addCall(run.calls, CALL_SERVICE_BUILD);
      const client = this.serviceClient();
      run.calls = addCall(run.calls, CALL_FLOW_RUN);
      const flowRun = await client.flowRun(flowRunId);

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
    run.calls = addCall(run.calls, CALL_PROCESS);
    try {
      await client.processFlowRun(flowRunId, fillNode);
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
    run.calls = addCall(run.calls, CALL_ANSWERS);
    const answers = await client.flowRunAnswers(flowRun);
    run.answers = Object.entries(answers).map(([slug, value]) => ({ slug, value }));

    if (flowRun.outputMode === 'document') {
      try {
        run.calls = addCall(run.calls, CALL_DOCUMENT);
        const bytes = await client.flowRunDocument(flowRunId);
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
    return Client.fromConfig(this.rt.configPathFor(SCENARIO));
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
