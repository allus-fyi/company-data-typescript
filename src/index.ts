/**
 * allus company-data SDK for TypeScript / Node — one of six language ports that
 * share an identical API surface.
 *
 * This package wraps the allus company-data API: point it at a JSON config file and
 * it hands back typed, plaintext, your-slug-keyed conclusions with transparent
 * hybrid decryption.
 *
 * Exported: config loading, the decryption core, the full error taxonomy, the
 * HTTP/auth layer, the output model, the crash-safe changes pump (durable file
 * buffer + pump), the `Client` facade, and the webhook receiver helpers. `Client`
 * is the one object an integrating company touches.
 *
 * Both ESM (`import { Client } from '@allus/company-data'`) and CommonJS
 * (`const { Client } = require('@allus/company-data')`) are supported via the
 * package's `exports` map.
 */

// client facade — the main entry point
export { Client } from './client.js';
export type { ClientOptions } from './client.js';

// config
export { Config, SINGLE_WEBHOOK_KEY } from './config.js';
export type { WireFormat, WebhookBasic, WebhookHeader, WebhookAuthMethod } from './config.js';

// crypto
export { loadPrivateKey, decrypt, BinaryHandle, GCM_IV_LEN, GCM_TAG_LEN } from './crypto.js';
export type { EncWrapper, BinaryFetch, DecryptWrapper } from './crypto.js';

// errors
export {
  AllusError,
  ConfigError,
  AuthError,
  ApiError,
  DecryptError,
  WebhookError,
  RateLimitError,
} from './errors.js';

// transport
export { HttpClient, FetchTransport } from './http.js';
export type { HttpTransport, HttpResponse, HttpClientOptions, Sleep, Clock } from './http.js';

// output model
export {
  RequestField,
  Connection,
  Value,
  Change,
  LogEntry,
  STRUCTURED_TYPES,
  BINARY_TYPES,
  DATE_TYPES,
} from './models.js';
export type { TypeForSlug } from './models.js';

// changes pump
export { FileBuffer } from './buffer.js';
export type { BufferedEvent, DeadLetterRecord } from './buffer.js';
export { Pump, MAX_BATCH } from './pump.js';
export type {
  FetchChanges,
  DecryptChange,
  Handler,
  Logger,
  OnError,
  ProcessOptions,
  PumpOptions,
} from './pump.js';

// webhook receiver helpers
export { verifyWebhook, parseWebhook, handleWebhook, loadAccountKey } from './webhooks.js';
export type { Headers } from './webhooks.js';

// XML (XXE-safe parser — exported for advanced use / testing)
export { parseXml, XmlParseError } from './xml.js';

export const VERSION = '0.1.0';
