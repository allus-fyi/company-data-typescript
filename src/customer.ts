/**
 * The CUSTOMER-role client (#168).
 *
 * `CustomerClient` is what a *connecting company* uses to consume and answer another
 * company's service over its `acct_*` credentials: list company↔company connections,
 * provide/edit typed answers to consent requests, read (and decrypt) issued documents,
 * run contract flows, drain the account change feed, and verify account-level webhooks.
 * It reuses the same crash-safe {@link Pump}, webhook helpers, and hybrid-crypto core as
 * the service {@link Client}.
 *
 * **No sign/accept methods (spec D6).** Signing/accepting a contract is a deliberate
 * human step-up that stays portal-only; a machine `acct_*` token is rejected by the API
 * for those routes, so this SDK deliberately exposes no `sign`/`accept`.
 */
import type { KeyObject } from 'node:crypto';

import { Config } from './config.js';
import { decrypt as cryptoDecrypt, encryptForPublicKey, loadPublicKey, type EncWrapper } from './crypto.js';
import { ConfigError, ValidationError } from './errors.js';
import { isFieldValueValid } from './fieldValidation.js';
import { HttpClient, type HttpClientOptions } from './http.js';
import { Change, Document, FlowRun } from './models.js';
import { Pump, type Handler, type Logger, type ProcessOptions } from './pump.js';
import type { DeadLetterRecord } from './buffer.js';
import { handleWebhook, loadAccountKey, parseWebhook, verifyWebhook, type Headers } from './webhooks.js';

const CONN = '/api/company-connections';
const CONSENTS = `${CONN}/consents`;
const CUSTOMER_CHANGES = '/api/customer/changes';
const KEYS = '/api/keys';
const DEFAULT_PAGE = 100;

const defaultSleep = (seconds: number): Promise<void> =>
  new Promise((res) => setTimeout(res, Math.max(0, seconds) * 1000));

/** One service the customer is connected to, inside a {@link CustomerConnection}. */
export interface CustomerServiceLink {
  serviceLinkId: string | null;
  serviceId: string | null;
  serviceName: string | null;
  serviceCode: string | null;
  shared: Record<string, unknown>[]; // plaintext {slug,label,type,value}
  mappings: Record<string, unknown>[];
  pendingConsent: unknown;
  raw: Record<string, unknown>;
}

/** One company↔company connection from the customer's side. */
export interface CustomerConnection {
  id: string | null;
  companyUserId: string | null;
  companyName: string | null;
  companyCode: string | null;
  customerType: string | null; // "company" for a b2b link
  companyProfile: Record<string, unknown>[]; // plaintext values
  services: CustomerServiceLink[];
  raw: Record<string, unknown>;
}

function parseServiceLink(obj: Record<string, unknown>): CustomerServiceLink {
  return {
    serviceLinkId: (obj['service_link_id'] ?? obj['id'] ?? null) as string | null,
    serviceId: (obj['service_id'] ?? null) as string | null,
    serviceName: (obj['service_name'] ?? obj['name'] ?? null) as string | null,
    serviceCode: (obj['service_code'] ?? obj['share_code'] ?? null) as string | null,
    shared: (obj['shared'] as Record<string, unknown>[]) ?? [],
    mappings: (obj['mappings'] as Record<string, unknown>[]) ?? [],
    pendingConsent: obj['pending_consent'] ?? null,
    raw: obj,
  };
}

function parseConnection(obj: Record<string, unknown>): CustomerConnection {
  const company = (obj['company'] as Record<string, unknown>) ?? {};
  const services = ((obj['services'] as Record<string, unknown>[]) ?? [])
    .filter((s) => s && typeof s === 'object')
    .map(parseServiceLink);
  return {
    id: (obj['id'] ?? obj['company_connection_id'] ?? null) as string | null,
    companyUserId: (obj['company_user_id'] ?? company['user_id'] ?? null) as string | null,
    companyName: (obj['company_name'] ?? company['display_name'] ?? null) as string | null,
    companyCode: (obj['company_code'] ?? company['share_code'] ?? null) as string | null,
    customerType: (obj['customer_type'] ?? null) as string | null,
    companyProfile: (obj['company_profile'] as Record<string, unknown>[]) ?? [],
    services,
    raw: obj,
  };
}

function parseConnectionList(body: unknown): CustomerConnection[] {
  const items = Array.isArray(body)
    ? body
    : (((body as Record<string, unknown>)?.['connections'] ??
        (body as Record<string, unknown>)?.['items'] ??
        []) as unknown[]);
  return (items as Record<string, unknown>[])
    .filter((o) => o && typeof o === 'object')
    .map(parseConnection);
}

export interface CustomerClientOptions {
  http?: HttpClient;
  httpOptions?: HttpClientOptions;
  logger?: Logger;
  sleep?: (seconds: number) => Promise<void>;
}

/** A typed answer to a consent/edit request row (before encryption). */
export interface TypedAnswer {
  request_field_id: string;
  value: string;
  kind?: 'typed' | 'one_time';
}

/** A flow party for {@link CustomerClient.encryptFlowAnswer}. */
export interface FlowParty {
  user_id: string;
  type?: string;
  is_owner?: boolean;
}

/** B2B customer-side facade. NO sign/accept (spec D6). */
export class CustomerClient {
  private readonly config: Config;
  private readonly log: Logger;
  private readonly sleep: (seconds: number) => Promise<void>;
  private readonly http: HttpClient;
  private readonly accountKey: KeyObject | null;
  private readonly pubKeyCache = new Map<string, KeyObject | null>();
  private readonly serviceKeyCache = new Map<string, KeyObject | null>();
  // "companyCode/serviceCode" → {request_field_id: field_type}, resolved from the
  // connect-screen lookup for typed-answer validation (#302).
  private readonly requestTypeCache = new Map<string, Record<string, string>>();
  private _pump: Pump | null = null;

  constructor(config: Config, opts: CustomerClientOptions = {}) {
    if (!config.customerClientId || !config.customerClientSecret) {
      throw new ConfigError(
        'CustomerClient requires customer_client_id + customer_client_secret ' +
          '(load with Config.fromCustomerFile / fromCustomerEnv)',
      );
    }
    this.config = config;
    this.log = opts.logger ?? {};
    this.sleep = opts.sleep ?? defaultSleep;
    // The transport authenticates as the acct_* client — hand HttpClient a config
    // whose clientId/secret are the customer pair.
    const httpConfig = new Config({
      apiUrl: config.apiUrl,
      clientId: config.customerClientId,
      clientSecret: config.customerClientSecret,
      accountPrivateKey: config.accountPrivateKey,
      accountPassphrase: config.accountPassphrase,
      customerClientId: config.customerClientId,
      customerClientSecret: config.customerClientSecret,
      webhooks: config.webhooks,
      webhookBearerToken: config.webhookBearerToken,
      webhookBasic: config.webhookBasic,
      webhookHeader: config.webhookHeader,
      webhookAuthNone: config.webhookAuthNone,
      cacheDir: config.cacheDir,
      format: config.format,
    });
    this.http = opts.http ?? new HttpClient(httpConfig, opts.httpOptions);
    // ACCOUNT private key — decrypts received documents/flow copies (loaded once).
    this.accountKey = loadAccountKey(config);
  }

  /** Build from a customer-role JSON config file. */
  static fromConfig(path: string, opts: CustomerClientOptions = {}): CustomerClient {
    return new CustomerClient(Config.fromCustomerFile(path), opts);
  }

  /** Build entirely from `ALLUS_*` env vars (customer role). */
  static fromEnv(opts: CustomerClientOptions = {}): CustomerClient {
    return new CustomerClient(Config.fromCustomerEnv(), opts);
  }

  // ── connections ─────────────────────────────────────────────────────────────

  async connections(): Promise<CustomerConnection[]> {
    return parseConnectionList(await this.http.get(CONN));
  }

  async connection(id: string): Promise<CustomerConnection> {
    return parseConnection((await this.http.get(`${CONN}/${id}`)) as Record<string, unknown>);
  }

  // ── consents (typed answers) ────────────────────────────────────────────────

  async pendingConsents(): Promise<Record<string, unknown>[]> {
    const body = (await this.http.get(CONSENTS)) as Record<string, unknown>;
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      return ((body['consents'] ?? body['items'] ?? []) as Record<string, unknown>[]);
    }
    return (body as unknown as Record<string, unknown>[]) ?? [];
  }

  async provideConsent(
    consentId: string,
    answers: TypedAnswer[],
    opts: { companyCode: string; serviceCode: string },
  ): Promise<unknown> {
    const decisions = await this.encryptTyped(answers, opts.companyCode, opts.serviceCode);
    return this.http.post(`${CONSENTS}/${consentId}/provide`, { json: { decisions } });
  }

  async declineConsent(consentId: string): Promise<unknown> {
    return this.http.post(`${CONSENTS}/${consentId}/decline`, {});
  }

  async editAnswers(
    connectionId: string,
    serviceLinkId: string,
    answers: TypedAnswer[],
    opts: { companyCode: string; serviceCode: string },
  ): Promise<unknown> {
    const decisions = await this.encryptTyped(answers, opts.companyCode, opts.serviceCode);
    return this.http.put(`${CONN}/${connectionId}/services/${serviceLinkId}/mappings`, {
      json: { decisions },
    });
  }

  // ── documents (account-key decrypt; NO sign/accept — D6) ─────────────────────

  documents(connection: CustomerConnection): Document[] {
    const out: Document[] = [];
    const decryptValue = (w: EncWrapper | string): string => this.decryptAccount(w);
    for (const svc of connection.services) {
      for (const d of (svc.raw['documents'] as Record<string, unknown>[]) ?? []) {
        if (d && typeof d === 'object') out.push(Document.fromApi(d, { decryptValue }));
      }
    }
    for (const d of (connection.raw['documents'] as Record<string, unknown>[]) ?? []) {
      if (d && typeof d === 'object') out.push(Document.fromApi(d, { decryptValue }));
    }
    return out;
  }

  async documentFile(connectionId: string, documentId: string): Promise<unknown> {
    const body = (await this.http.get(
      `${CONN}/${connectionId}/documents/${documentId}/file`,
    )) as Record<string, unknown>;
    if (body && body['encrypted'] && 'value' in body) {
      return JSON.parse(this.decryptAccount(body['value'] as EncWrapper | string));
    }
    if (body && (body as Record<string, unknown>)['_enc'] === 1) {
      return JSON.parse(this.decryptAccount(body as unknown as EncWrapper));
    }
    return body;
  }

  async cancelDocument(connectionId: string, documentId: string, note?: string): Promise<unknown> {
    return this.http.post(`${CONN}/${connectionId}/documents/${documentId}/cancel`, {
      json: note ? { note } : undefined,
    });
  }

  // ── contract flows ──────────────────────────────────────────────────────────

  async flowRuns(connectionId: string): Promise<FlowRun[]> {
    const body = (await this.http.get(`${CONN}/${connectionId}/flow-runs`)) as Record<string, unknown>;
    const items = (Array.isArray(body) ? body : (body?.['runs'] as unknown[])) ?? [];
    return (items as Record<string, unknown>[]).filter((o) => o && typeof o === 'object').map((o) => FlowRun.fromApi(o));
  }

  async flowRun(connectionId: string, runId: string): Promise<FlowRun> {
    return FlowRun.fromApi(
      (await this.http.get(`${CONN}/${connectionId}/flow-runs/${runId}`)) as Record<string, unknown>,
    );
  }

  async submitFlowAnswers(connectionId: string, runId: string, body: Record<string, unknown>): Promise<unknown> {
    return this.http.post(`${CONN}/${connectionId}/flow-runs/${runId}/answers`, { json: body });
  }

  async declineFlowRun(connectionId: string, runId: string): Promise<unknown> {
    return this.http.post(`${CONN}/${connectionId}/flow-runs/${runId}/decline`, {});
  }

  /** Encrypt one answer value for one flow `party` per the P4 key rule. */
  async encryptFlowAnswer(
    plaintext: string,
    party: FlowParty,
    opts: { companyCode: string; serviceCode: string },
  ): Promise<EncWrapper> {
    const pub = party.is_owner
      ? await this.serviceKey(opts.companyCode, opts.serviceCode)
      : await this.batchKey(party.user_id);
    if (!pub) throw new ConfigError(`no public key available for party ${party.user_id}`);
    return encryptForPublicKey(plaintext, pub);
  }

  // ── change feed (P2 account feed) ───────────────────────────────────────────

  get pump(): Pump {
    if (this._pump === null) {
      this._pump = new Pump(this.config, {
        fetchChanges: (limit) => this.fetchChanges(limit),
        decrypt: (event) => this.decryptChange(event),
        logger: this.log,
        sleep: this.sleep,
      });
    }
    return this._pump;
  }

  private async fetchChanges(limit: number): Promise<Record<string, unknown>[]> {
    const body = (await this.http.get(CUSTOMER_CHANGES, { limit: Math.trunc(limit) })) as Record<string, unknown>;
    const items = (body?.['changes'] as unknown[]) ?? (Array.isArray(body) ? (body as unknown[]) : []);
    return (items as Record<string, unknown>[]).filter((o) => o && typeof o === 'object');
  }

  private decryptChange(event: Record<string, unknown>): Change {
    return Change.fromApi(event, {
      typeForSlug: () => null,
      decryptValue: (w) => this.decryptAccount(w),
    });
  }

  async processChanges(handler: Handler, options: ProcessOptions = {}): Promise<void> {
    await this.pump.processChanges(handler, options);
  }

  async drainBatch(max: number = DEFAULT_PAGE): Promise<Change[]> {
    return this.pump.drainBatch(max);
  }

  deadLetters(): DeadLetterRecord[] {
    return this.pump.deadLetters();
  }

  async retryDeadLetters(handler: Handler, options: ProcessOptions = {}): Promise<number> {
    return this.pump.retryDeadLetters(handler, options);
  }

  // ── account-level webhook receiver helpers (config-driven) ───────────────────

  verifyWebhook(rawBody: Buffer | Uint8Array | string, headers: Headers): boolean {
    return verifyWebhook(rawBody, headers, this.config);
  }

  parseWebhook(rawBody: Buffer | Uint8Array | string, headers: Headers): Change {
    return parseWebhook(rawBody, headers, this.config, {
      typeForSlug: () => null,
      decryptValue: (w) => this.decryptAccount(w),
      accountKey: this.accountKey,
    });
  }

  handleWebhook(rawBody: Buffer | Uint8Array | string, headers: Headers): Change {
    return handleWebhook(rawBody, headers, this.config, {
      typeForSlug: () => null,
      decryptValue: (w) => this.decryptAccount(w),
      accountKey: this.accountKey,
    });
  }

  // ── internals ────────────────────────────────────────────────────────────────

  private decryptAccount(wrapper: EncWrapper | string): string {
    if (this.accountKey === null) {
      throw new ConfigError('account_private_key is required to decrypt this value');
    }
    return cryptoDecrypt(wrapper, this.accountKey);
  }

  /**
   * Resolve `{request_field_id: field_type}` for a service from the connect-screen
   * lookup, cached per company/service. Best-effort — a lookup failure yields an empty
   * map so typed-answer validation is simply skipped (#302).
   */
  private async requestFieldTypes(companyCode: string, serviceCode: string): Promise<Record<string, string>> {
    const key = `${companyCode}/${serviceCode}`;
    const cached = this.requestTypeCache.get(key);
    if (cached) return cached;
    const out: Record<string, string> = {};
    try {
      const body = (await this.http.get(`${CONN}/lookup/${companyCode}/${serviceCode}`)) as Record<string, unknown>;
      const rows = (body?.['request_fields'] as Record<string, unknown>[]) ?? [];
      for (const r of rows) {
        if (!r || typeof r !== 'object') continue;
        const id = r['id'];
        const ft = r['field_type'] ?? r['type'];
        if (typeof id === 'string' && id && typeof ft === 'string' && ft) out[id] = ft;
      }
    } catch {
      // best-effort — a failed lookup skips validation
    }
    this.requestTypeCache.set(key, out);
    return out;
  }

  private async encryptTyped(
    answers: TypedAnswer[],
    companyCode: string,
    serviceCode: string,
  ): Promise<Record<string, unknown>[]> {
    const pub = await this.serviceKey(companyCode, serviceCode);
    if (!pub) throw new ConfigError(`no service key for ${companyCode}/${serviceCode}`);
    // #302: validate each typed answer against its request row's field type BEFORE
    // encryption. The type is resolved server-side from the connect-screen lookup
    // (cached per service); an answer whose type can't be resolved is skipped.
    const types = await this.requestFieldTypes(companyCode, serviceCode);
    return answers.map((a) => {
      const plain = String(a.value);
      const ft = types[a.request_field_id];
      if (ft && !isFieldValueValid(ft, plain)) {
        throw new ValidationError(a.request_field_id, ft);
      }
      return {
        request_field_id: a.request_field_id,
        kind: a.kind ?? 'typed',
        value: encryptForPublicKey(plain, pub),
      };
    });
  }

  private async serviceKey(companyCode: string, serviceCode: string): Promise<KeyObject | null> {
    const key = `${companyCode}/${serviceCode}`;
    if (!this.serviceKeyCache.has(key)) {
      const body = (await this.http.get(`${KEYS}/${companyCode}/${serviceCode}`)) as Record<string, unknown>;
      const spki = body?.['public_key'] as string | undefined;
      this.serviceKeyCache.set(key, spki ? loadPublicKey(spki) : null);
    }
    return this.serviceKeyCache.get(key) ?? null;
  }

  private async batchKey(userId: string): Promise<KeyObject | null> {
    if (!this.pubKeyCache.has(userId)) {
      const body = (await this.http.post(`${KEYS}/batch`, { json: { user_ids: [userId] } })) as Record<string, unknown>;
      const keys = body?.['keys'] as Record<string, string> | undefined;
      const spki = keys?.[userId];
      this.pubKeyCache.set(userId, spki ? loadPublicKey(spki) : null);
    }
    return this.pubKeyCache.get(userId) ?? null;
  }
}
