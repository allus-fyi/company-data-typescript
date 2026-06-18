/**
 * Configuration loading.
 *
 * Config-only key handling is a hard rule: **no SDK method ever takes a key,
 * passphrase, or secret as an argument.** Everything cryptographic — decrypting
 * the service PEM, decrypting field values, verifying the webhook HMAC, unwrapping
 * the account-key envelope — is driven entirely by this config. The developer's
 * only key responsibility is putting the right values here.
 *
 * A single JSON file holds everything; any field may be overridden by an `ALLUS_*`
 * env var, so secrets needn't live in the file.
 */

import { readFileSync } from 'node:fs';

import { ConfigError } from './errors.js';

export type WireFormat = 'json' | 'xml';

/** Mapping from a Config field name to its `ALLUS_*` env-var override. */
const ENV_MAP: Record<string, string> = {
  apiUrl: 'ALLUS_API_URL',
  clientId: 'ALLUS_CLIENT_ID',
  clientSecret: 'ALLUS_CLIENT_SECRET',
  servicePrivateKey: 'ALLUS_SERVICE_PRIVATE_KEY',
  keyPassphrase: 'ALLUS_KEY_PASSPHRASE',
  accountPrivateKey: 'ALLUS_ACCOUNT_PRIVATE_KEY',
  accountPassphrase: 'ALLUS_ACCOUNT_PASSPHRASE',
  cacheDir: 'ALLUS_CACHE_DIR',
  format: 'ALLUS_FORMAT',
};

// JSON file keys are snake_case (identical across all six SDKs' config files);
// this maps a Config attribute back to the file key it reads.
const FILE_KEY: Record<string, string> = {
  apiUrl: 'api_url',
  clientId: 'client_id',
  clientSecret: 'client_secret',
  servicePrivateKey: 'service_private_key',
  keyPassphrase: 'key_passphrase',
  accountPrivateKey: 'account_private_key',
  accountPassphrase: 'account_passphrase',
  cacheDir: 'cache_dir',
  format: 'format',
};

const WEBHOOK_SECRET_ENV = 'ALLUS_WEBHOOK_SECRET';

const REQUIRED = ['apiUrl', 'clientId', 'clientSecret', 'servicePrivateKey', 'keyPassphrase'] as const;

const VALID_FORMATS: readonly WireFormat[] = ['json', 'xml'];

/** Reserved webhook-map key under which a flat `webhook_secret` is stored. */
export const SINGLE_WEBHOOK_KEY = '__single__';

/** HTTP Basic webhook-auth credentials ({@link Config.webhookBasic}). */
export interface WebhookBasic {
  username: string;
  password: string;
}

/** Custom-header webhook auth ({@link Config.webhookHeader}). */
export interface WebhookHeader {
  name: string;
  value: string;
}

/** The single configured webhook auth method, if any. */
export type WebhookAuthMethod = 'hmac' | 'bearer' | 'basic' | 'header' | 'none';

interface ConfigInit {
  apiUrl: string;
  clientId: string;
  clientSecret: string;
  servicePrivateKey: string;
  keyPassphrase: string;
  accountPrivateKey?: string | null;
  accountPassphrase?: string | null;
  webhooks?: Record<string, string>;
  webhookBearerToken?: string | null;
  webhookBasic?: WebhookBasic | null;
  webhookHeader?: WebhookHeader | null;
  webhookAuthNone?: boolean;
  cacheDir?: string;
  format?: WireFormat;
}

/** The whole SDK configuration. Keys live here and nowhere else. */
export class Config {
  readonly apiUrl: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly servicePrivateKey: string; // path to the OpenSSL-encrypted PKCS#8 PEM
  readonly keyPassphrase: string; // decrypts the service PEM in memory

  // OPTIONAL — only needed if you receive encrypt_payload webhooks.
  readonly accountPrivateKey: string | null;
  readonly accountPassphrase: string | null;

  // OPTIONAL — per-webhook HMAC secrets keyed by webhook id; matched via the
  // X-Allus-Webhook-Id header. A single-webhook service can use the flat
  // "webhook_secret" shortcut, captured under SINGLE_WEBHOOK_KEY.
  readonly webhooks: Record<string, string>;

  // OPTIONAL — alternative webhook auth methods, mirroring the platform's
  // per-webhook delivery auth. Configure AT MOST ONE family among
  // hmac (webhooks/webhook_secret) | bearer | basic | header | none;
  // two or more → ConfigError. See webhookAuthMethod().
  readonly webhookBearerToken: string | null; // "Authorization: Bearer <token>"
  readonly webhookBasic: WebhookBasic | null; // {username,password} → Basic auth
  readonly webhookHeader: WebhookHeader | null; // {name,value} → custom header
  readonly webhookAuthNone: boolean; // explicit opt-out — verify always true

  // Durable local buffer for the changes pump.
  readonly cacheDir: string;

  // Wire format json|xml (default json) — invisible in the output.
  readonly format: WireFormat;

  /** Reserved webhook-map key under which a flat `webhook_secret` is stored. */
  static readonly SINGLE_WEBHOOK_KEY = SINGLE_WEBHOOK_KEY;

  constructor(init: ConfigInit) {
    this.apiUrl = init.apiUrl;
    this.clientId = init.clientId;
    this.clientSecret = init.clientSecret;
    this.servicePrivateKey = init.servicePrivateKey;
    this.keyPassphrase = init.keyPassphrase;
    this.accountPrivateKey = init.accountPrivateKey ?? null;
    this.accountPassphrase = init.accountPassphrase ?? null;
    this.webhooks = init.webhooks ?? {};
    this.webhookBearerToken = init.webhookBearerToken ?? null;
    this.webhookBasic = init.webhookBasic ?? null;
    this.webhookHeader = init.webhookHeader ?? null;
    this.webhookAuthNone = init.webhookAuthNone ?? false;
    this.cacheDir = init.cacheDir ?? './allus-cache';
    this.format = init.format ?? 'json';
  }

  /** Load from a JSON file; env vars override file values. */
  static fromFile(path: string): Config {
    let raw: string;
    try {
      raw = readFileSync(path, 'utf8');
    } catch (exc) {
      const e = exc as NodeJS.ErrnoException;
      if (e.code === 'ENOENT') {
        throw new ConfigError(`config file not found: ${path}`);
      }
      throw new ConfigError(`could not read config file: ${path}: ${e.message}`);
    }
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch (exc) {
      throw new ConfigError(`config file is not valid JSON: ${path}: ${(exc as Error).message}`);
    }
    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
      throw new ConfigError(`config file must be a JSON object: ${path}`);
    }
    return Config.build(data as Record<string, unknown>);
  }

  /** Build entirely from `ALLUS_*` env vars. */
  static fromEnv(): Config {
    return Config.build({});
  }

  /** Merge file values with env overrides, validate, and construct. */
  private static build(data: Record<string, unknown>): Config {
    const values: Record<string, unknown> = {};

    // Scalar fields: env var (if set) overrides the file value.
    for (const attr of Object.keys(ENV_MAP)) {
      const envVal = process.env[ENV_MAP[attr]];
      const fileKey = FILE_KEY[attr];
      if (envVal !== undefined) {
        values[attr] = envVal;
      } else if (data[fileKey] !== undefined && data[fileKey] !== null) {
        values[attr] = data[fileKey];
      }
    }

    // Webhook secrets: the "webhooks" map plus the flat "webhook_secret" shortcut
    // (and its env override), normalized into a single dict.
    const webhooks: Record<string, string> = {};
    const fileWebhooks = data['webhooks'];
    if (fileWebhooks !== undefined && fileWebhooks !== null) {
      if (typeof fileWebhooks !== 'object' || Array.isArray(fileWebhooks)) {
        throw new ConfigError('"webhooks" must be an object mapping webhook id -> secret');
      }
      for (const [k, v] of Object.entries(fileWebhooks as Record<string, unknown>)) {
        webhooks[String(k)] = String(v);
      }
    }

    let flatSecret: unknown = process.env[WEBHOOK_SECRET_ENV];
    if (flatSecret === undefined) {
      flatSecret = data['webhook_secret'];
    }
    if (flatSecret !== undefined && flatSecret !== null) {
      webhooks[SINGLE_WEBHOOK_KEY] = String(flatSecret);
    }
    const hasWebhooks = Object.keys(webhooks).length > 0;

    // Alternative webhook auth methods (file-config only; no env overrides).
    // Validate object shapes.
    let webhookBearerToken: string | null = null;
    const bearer = data['webhook_bearer_token'];
    if (bearer) {
      webhookBearerToken = String(bearer);
    }

    let webhookBasic: WebhookBasic | null = null;
    const basic = data['webhook_basic'];
    if (basic !== undefined && basic !== null) {
      const b = basic as Record<string, unknown>;
      if (typeof basic !== 'object' || Array.isArray(basic) || !b['username'] || !b['password']) {
        throw new ConfigError('"webhook_basic" must be an object with non-empty "username" and "password"');
      }
      webhookBasic = { username: String(b['username']), password: String(b['password']) };
    }

    let webhookHeader: WebhookHeader | null = null;
    const hdr = data['webhook_header'];
    if (hdr !== undefined && hdr !== null) {
      const h = hdr as Record<string, unknown>;
      if (typeof hdr !== 'object' || Array.isArray(hdr) || !h['name'] || !h['value']) {
        throw new ConfigError('"webhook_header" must be an object with non-empty "name" and "value"');
      }
      webhookHeader = { name: String(h['name']), value: String(h['value']) };
    }

    const webhookAuthNone = data['webhook_auth_none'] === true;

    // At most one webhook auth method may be configured.
    const present: string[] = [];
    if (hasWebhooks) present.push('hmac');
    if (webhookBearerToken) present.push('bearer');
    if (webhookBasic) present.push('basic');
    if (webhookHeader) present.push('header');
    if (webhookAuthNone) present.push('none');
    if (present.length > 1) {
      throw new ConfigError('configure at most one webhook auth method (found: ' + present.join(', ') + ')');
    }

    // Required fields (fail fast). Report by the config-file key
    // (snake_case) so the message is actionable for whoever wrote the file.
    const missing = REQUIRED.filter((name) => {
      const v = values[name];
      return v === undefined || v === null || v === '';
    }).map((name) => FILE_KEY[name]);
    if (missing.length > 0) {
      throw new ConfigError(`missing required config field(s): ${missing.join(', ')}`);
    }

    // Validate the wire format if supplied.
    let format: WireFormat = 'json';
    if (values['format'] !== undefined) {
      const fmt = String(values['format']).toLowerCase();
      if (!VALID_FORMATS.includes(fmt as WireFormat)) {
        throw new ConfigError(`invalid "format": '${fmt}' (expected one of ${VALID_FORMATS.join(', ')})`);
      }
      format = fmt as WireFormat;
    }

    return new Config({
      apiUrl: String(values['apiUrl']),
      clientId: String(values['clientId']),
      clientSecret: String(values['clientSecret']),
      servicePrivateKey: String(values['servicePrivateKey']),
      keyPassphrase: String(values['keyPassphrase']),
      accountPrivateKey: values['accountPrivateKey'] !== undefined ? String(values['accountPrivateKey']) : null,
      accountPassphrase: values['accountPassphrase'] !== undefined ? String(values['accountPassphrase']) : null,
      webhooks: hasWebhooks ? webhooks : {},
      webhookBearerToken,
      webhookBasic,
      webhookHeader,
      webhookAuthNone,
      cacheDir: values['cacheDir'] !== undefined ? String(values['cacheDir']) : './allus-cache',
      format,
    });
  }

  /**
   * Resolve the HMAC secret for a webhook id.
   *
   * Falls back to the single-webhook shortcut secret when there is no id or no
   * id-specific match. The webhook helpers read this — application code never
   * passes a secret in. (This method takes a webhook *id*, never a secret.)
   */
  webhookSecret(webhookId?: string | null): string | null {
    if (webhookId !== undefined && webhookId !== null && webhookId in this.webhooks) {
      return this.webhooks[webhookId];
    }
    return this.webhooks[SINGLE_WEBHOOK_KEY] ?? null;
  }

  /**
   * The single configured webhook auth method, or `null` if none is set.
   *
   * Returns one of `"hmac" | "bearer" | "basic" | "header" | "none"`. Config
   * loading guarantees at most one is configured, so the order here is only a
   * tie-break that never triggers.
   */
  webhookAuthMethod(): WebhookAuthMethod | null {
    if (this.webhookAuthNone) return 'none';
    if (this.webhookBearerToken) return 'bearer';
    if (this.webhookBasic) return 'basic';
    if (this.webhookHeader) return 'header';
    if (Object.keys(this.webhooks).length > 0) return 'hmac';
    return null;
  }
}
