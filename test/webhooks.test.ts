/**
 * Webhook receiver-helper tests. Ports test_webhooks.py.
 *
 * We build fixture webhook requests exactly the way the platform's
 * WebhookDeliveryService does: body = the slug-keyed Change shape, X-Allus-Signature
 * = lowercase-hex HMAC-SHA256(body, secret), X-Allus-Webhook-Id selects the secret;
 * for an encrypt_payload webhook the body is REPLACED by a {"_enc":1,...} envelope
 * encrypted to the company ACCOUNT public key with OpenSSL's default OAEP (MGF1-SHA1).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createHmac,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
  createCipheriv,
  constants as cryptoConstants,
  type KeyObject,
} from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Client, Config, HttpClient, WebhookError, decrypt, handleWebhook, parseWebhook, verifyWebhook } from '../src/index.js';
import type { EncWrapper, Headers, HttpResponse, HttpTransport } from '../src/index.js';
import { loadVector, loadVectorPrivateKey } from './helpers.js';

const vector = loadVector();
const SECRET = 'wh_secret_abc123';
const WEBHOOK_ID = 'wh-1';

const privateKey = loadVectorPrivateKey(vector);
const decryptValue = (w: EncWrapper | string): string => decrypt(w, privateKey);
const typeForSlug = (slug: string): string | null => ({ work_email: 'email', logo: 'photo' } as Record<string, string>)[slug] ?? null;

function withTmp<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'allus-wh-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function makeConfig(dir: string, extra: Partial<{ webhooks: Record<string, string>; accountPrivateKey: string; accountPassphrase: string }> = {}): Config {
  const pem = join(dir, 'service-key.pem');
  writeFileSync(pem, vector.encrypted_private_key_pem, 'ascii');
  return new Config({
    apiUrl: 'https://api.allme.fyi',
    clientId: 'svc',
    clientSecret: 's',
    servicePrivateKey: pem,
    keyPassphrase: vector.passphrase,
    cacheDir: join(dir, 'cache'),
    webhooks: extra.webhooks ?? { [WEBHOOK_ID]: SECRET },
    accountPrivateKey: extra.accountPrivateKey ?? null,
    accountPassphrase: extra.accountPassphrase ?? null,
  });
}

function sign(body: Buffer, secret: string = SECRET): string {
  return createHmac('sha256', secret).update(body).digest('hex');
}

function headers(body: Buffer, opts: { secret?: string; webhookId?: string; signFlag?: boolean } = {}): Headers {
  const h: Headers = { 'X-Allus-Webhook-Id': opts.webhookId ?? WEBHOOK_ID, 'X-Allus-Event': 'field_updated' };
  if (opts.signFlag !== false) h['X-Allus-Signature'] = sign(body, opts.secret ?? SECRET);
  return h;
}

function changeBody(): Buffer {
  const payload = {
    id: 'chg-1',
    event: 'field_updated',
    person_user_id: 'person-1',
    slug: 'work_email',
    at: '2026-06-17T12:00:00Z',
    live: true,
    value: vector.text.wrapper,
  };
  return Buffer.from(JSON.stringify(payload), 'utf8');
}

// ── verify ─────────────────────────────────────────────────────────────────────

test('verify true with known secret', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const body = changeBody();
    assert.equal(verifyWebhook(body, headers(body), config), true);
  });
});

test('verify false on tampered body', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const body = changeBody();
    const h = headers(body); // signature for the ORIGINAL body
    const tampered = Buffer.concat([body, Buffer.from(' ')]);
    assert.equal(verifyWebhook(tampered, h, config), false);
  });
});

test('verify false on unknown webhook id', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const body = changeBody();
    assert.equal(verifyWebhook(body, headers(body, { webhookId: 'wh-UNKNOWN' }), config), false);
  });
});

test('verify false on missing signature', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const body = changeBody();
    assert.equal(verifyWebhook(body, headers(body, { signFlag: false }), config), false);
  });
});

test('verify accepts uppercase hex', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const body = changeBody();
    const h: Headers = { 'X-Allus-Webhook-Id': WEBHOOK_ID, 'X-Allus-Signature': sign(body).toUpperCase() };
    assert.equal(verifyWebhook(body, h, config), true);
  });
});

test('verify single-webhook shortcut', () => {
  withTmp((dir) => {
    const config = makeConfig(dir, { webhooks: { [Config.SINGLE_WEBHOOK_KEY]: SECRET } });
    const body = changeBody();
    // Header carries an id, but config has only the flat secret → falls back to it.
    assert.equal(verifyWebhook(body, headers(body), config), true);
  });
});

// ── parse (plain JSON) ──────────────────────────────────────────────────────────

test('parse plain JSON body', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const body = changeBody();
    const change = parseWebhook(body, headers(body), config, { typeForSlug, decryptValue });
    assert.equal(change.id, 'chg-1');
    assert.equal(change.event, 'field_updated');
    assert.equal(change.personId, 'person-1');
    assert.equal(change.slug, 'work_email');
    assert.equal(change.value, vector.text.plaintext); // decrypted via the service key
    assert.equal(change.live, true);
  });
});

test('parse XML body', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const w = vector.text.wrapper;
    const xml = Buffer.from(
      '<response>' +
        '<id>chg-7</id>' +
        '<event>field_updated</event>' +
        '<person_user_id>person-1</person_user_id>' +
        '<slug>work_email</slug>' +
        '<at>2026-06-17T12:00:00Z</at>' +
        '<live>true</live>' +
        '<value>' +
        `<_enc>1</_enc><k>${w.k}</k><iv>${w.iv}</iv><d>${w.d}</d>` +
        '</value>' +
        '</response>',
      'utf8',
    );
    const change = parseWebhook(xml, headers(xml), config, { typeForSlug, decryptValue });
    assert.equal(change.id, 'chg-7');
    assert.equal(change.event, 'field_updated');
    assert.equal(change.slug, 'work_email');
    assert.equal(change.value, vector.text.plaintext);
  });
});

// ── parse (account-key encrypt_payload envelope) ────────────────────────────────

function makeAccountKey(dir: string, passphrase: string): { path: string; publicKey: KeyObject } {
  const { privateKey: priv, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = priv.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase });
  const path = join(dir, 'account.pem');
  writeFileSync(path, pem);
  return { path, publicKey };
}

function wrapToAccountKey(publicKey: KeyObject, plaintext: Buffer): Buffer {
  // Mimic the account-key envelope — OAEP-SHA1 + AES-256-GCM.
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  // OpenSSL's default OAEP padding is MGF1-SHA1 — the webhook envelope path.
  const k = publicEncrypt({ key: publicKey, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, aesKey);
  const envelope = {
    _enc: 1,
    k: k.toString('base64'),
    iv: iv.toString('base64'),
    d: Buffer.concat([ct, tag]).toString('base64'),
  };
  return Buffer.from(JSON.stringify(envelope), 'utf8');
}

test('parse account-key envelope', () => {
  withTmp((dir) => {
    const { path: accountPem, publicKey } = makeAccountKey(dir, 'acctpp');
    const config = makeConfig(dir, { accountPrivateKey: accountPem, accountPassphrase: 'acctpp' });

    const inner = changeBody(); // the serialized change (JSON)
    const body = wrapToAccountKey(publicKey, inner); // the envelope IS the sent body
    const h = headers(body); // HMAC is over the envelope (the final body)

    assert.equal(verifyWebhook(body, h, config), true);
    const change = parseWebhook(body, h, config, { typeForSlug, decryptValue });
    assert.equal(change.id, 'chg-1');
    assert.equal(change.event, 'field_updated');
    assert.equal(change.slug, 'work_email');
    // OUTER envelope is account-key (SHA-1); INNER value is service-key (SHA-256).
    assert.equal(change.value, vector.text.plaintext);
  });
});

test('parse account envelope without account key raises', () => {
  withTmp((dir) => {
    const config = makeConfig(dir); // no account_private_key
    const { publicKey } = makeAccountKey(dir, 'x');
    const body = wrapToAccountKey(publicKey, changeBody());
    assert.throws(() => parseWebhook(body, headers(body), config, { typeForSlug, decryptValue }), WebhookError);
  });
});

// ── handle = verify + parse ─────────────────────────────────────────────────────

test('handle verify then parse', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const body = changeBody();
    const change = handleWebhook(body, headers(body), config, { typeForSlug, decryptValue });
    assert.equal(change.id, 'chg-1');
  });
});

test('handle bad signature raises', () => {
  withTmp((dir) => {
    const config = makeConfig(dir);
    const body = changeBody();
    const h = headers(body);
    h['X-Allus-Signature'] = 'deadbeef';
    assert.throws(() => handleWebhook(body, h, config, { typeForSlug, decryptValue }), WebhookError);
  });
});

// ── Client method delegation ────────────────────────────────────────────────────

class TokenResp implements HttpResponse {
  status = 200;
  async text(): Promise<string> {
    return '{"access_token":"t","token_type":"Bearer","expires_in":3600}';
  }
  get headers(): { get(name: string): string | null } {
    return { get: () => null };
  }
}

class RFResp implements HttpResponse {
  status = 200;
  async text(): Promise<string> {
    return JSON.stringify({
      request_fields: [{ slug: 'work_email', label: 'Work email', type: 'email', one_time: false, mandatory_provide: true, mandatory_connected: false }],
    });
  }
  get headers(): { get(name: string): string | null } {
    return { get: () => null };
  }
}

test('client methods delegate', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const catalogCalls = { n: 0 };
    const transport: HttpTransport = {
      async post() {
        return new TokenResp();
      },
      async get(url) {
        assert.ok(url.endsWith('/request-fields'), `unexpected GET ${url}`);
        catalogCalls.n += 1;
        return new RFResp();
      },
    };
    const client = new Client(config, { http: new HttpClient(config, { transport }) });
    const body = changeBody();
    const h = headers(body);

    // verify makes NO HTTP at all.
    assert.equal(client.verifyWebhook(body, h), true);
    assert.equal(catalogCalls.n, 0);

    // handleWebhook needs the catalog (one lazy fetch) — but it's async there. The
    // Client method is sync; ensure the catalog is loaded first.
    await client.requestFields();
    const change = client.handleWebhook(body, h);
    assert.equal(change.id, 'chg-1');
    assert.equal(change.value, vector.text.plaintext);
    assert.equal(catalogCalls.n, 1);
    // A second webhook reuses the cached catalog (no further HTTP).
    client.handleWebhook(body, h);
    assert.equal(catalogCalls.n, 1);
  });
});

// ── the account key is loaded ONCE and reused per webhook ───────────────────────

test('account key loaded once and reused', async () => {
  await withTmp(async (dir) => {
    const { path: accountPem, publicKey } = makeAccountKey(dir, 'acctpp');
    const config = makeConfig(dir, { accountPrivateKey: accountPem, accountPassphrase: 'acctpp' });

    const transport: HttpTransport = {
      async post() {
        return new TokenResp();
      },
      async get(url) {
        assert.ok(url.endsWith('/request-fields'));
        return new RFResp();
      },
    };
    // The Client loads the account key ONCE at construction (no per-webhook PBKDF2).
    // We can't easily spy on node:crypto, so we assert behavior: three enveloped
    // webhooks all decrypt with the cached key, and decryption never re-reads the
    // PEM (the file could be removed after construction and it would still work).
    const client = new Client(config, { http: new HttpClient(config, { transport }) });
    await client.requestFields();

    // Remove the PEM file: if the key were re-loaded per webhook, this would fail.
    rmSync(accountPem, { force: true });

    const inner = changeBody();
    const body = wrapToAccountKey(publicKey, inner);
    const h = headers(body);
    for (let i = 0; i < 3; i++) {
      const change = client.handleWebhook(body, h);
      assert.equal(change.id, 'chg-1');
      assert.equal(change.value, vector.text.plaintext);
    }
  });
});

test('parseWebhook loads account key when not supplied (standalone)', () => {
  withTmp((dir) => {
    const { path: accountPem, publicKey } = makeAccountKey(dir, 'acctpp');
    const config = makeConfig(dir, { accountPrivateKey: accountPem, accountPassphrase: 'acctpp' });
    const body = wrapToAccountKey(publicKey, changeBody());
    const change = parseWebhook(body, headers(body), config, { typeForSlug, decryptValue }); // no accountKey dep → loaded on demand
    assert.equal(change.id, 'chg-1');
    assert.equal(change.value, vector.text.plaintext);
  });
});
