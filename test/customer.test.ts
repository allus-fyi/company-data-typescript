/**
 * CustomerClient (b2b) — parse + method-shape + key-sourcing tests.
 * Reuses the shared decryption vector's key as the customer ACCOUNT key (vector read-only).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPublicKey, randomBytes, publicEncrypt, createCipheriv, constants } from 'node:crypto';

import { Config, ConfigError, CustomerClient, HttpClient, decrypt, loadPrivateKey } from '../src/index.js';
import type { HttpResponse, HttpTransport, RequestBody } from '../src/http.js';
import { loadVector } from './helpers.js';

const vector = loadVector();

class FakeResponse implements HttpResponse {
  constructor(
    public readonly status: number,
    private readonly body: unknown,
  ) {}
  async json(): Promise<unknown> {
    return this.body;
  }
  async text(): Promise<string> {
    return JSON.stringify(this.body);
  }
  get headers(): { get(name: string): string | null } {
    return { get: () => null };
  }
}

type Router = (url: string) => FakeResponse;
type WriteRouter = (method: string, url: string, body: RequestBody | undefined) => FakeResponse;

class RoutedTransport implements HttpTransport {
  gets: { url: string }[] = [];
  requests: { method: string; url: string; json?: unknown }[] = [];
  constructor(
    private readonly router: Router,
    private readonly writeRouter?: WriteRouter,
  ) {}
  async post(url: string): Promise<HttpResponse> {
    return new FakeResponse(200, { access_token: 'tok-1', token_type: 'Bearer', expires_in: 3600 });
  }
  async get(url: string): Promise<HttpResponse> {
    this.gets.push({ url });
    return this.router(url);
  }
  async request(method: string, url: string, _p: unknown, _h: unknown, body: RequestBody | undefined): Promise<HttpResponse> {
    this.requests.push({ method, url, json: body?.json });
    if (this.writeRouter === undefined) return new FakeResponse(200, {});
    return this.writeRouter(method, url, body);
  }
}

function withTmp<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'allus-customer-'));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function makeConfig(dir: string): Config {
  const pem = join(dir, 'account-key.pem');
  writeFileSync(pem, vector.encrypted_private_key_pem, 'ascii');
  return new Config({
    apiUrl: 'https://api.allme.fyi',
    customerClientId: 'acct_abc',
    customerClientSecret: 'topsecret',
    accountPrivateKey: pem,
    accountPassphrase: vector.passphrase,
    cacheDir: join(dir, 'cache'),
  });
}

function makeCustomer(config: Config, router: Router, writeRouter?: WriteRouter): { customer: CustomerClient; transport: RoutedTransport } {
  const transport = new RoutedTransport(router, writeRouter);
  const http = new HttpClient(config, { transport });
  return { customer: new CustomerClient(config, { http }), transport };
}

function vectorPubSpkiB64(): string {
  const priv = loadPrivateKey(vector.encrypted_private_key_pem, vector.passphrase);
  return createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64');
}

function encForAccount(plaintext: string): { _enc: number; k: string; iv: string; d: string } {
  const priv = loadPrivateKey(vector.encrypted_private_key_pem, vector.passphrase);
  const pub = createPublicKey(priv);
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const k = publicEncrypt({ key: pub, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, aesKey);
  return { _enc: 1, k: k.toString('base64'), iv: iv.toString('base64'), d: Buffer.concat([ct, tag]).toString('base64') };
}

test('customer config requires the acct_* pair', async () => {
  await withTmp(async (dir) => {
    const p = join(dir, 'c.json');
    writeFileSync(p, JSON.stringify({ api_url: 'https://api.allme.fyi' }));
    assert.throws(() => Config.fromCustomerFile(p), ConfigError);
  });
});

test('connections() parses company + services', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const body = {
      connections: [
        {
          id: 'conn-1',
          customer_type: 'company',
          company: { user_id: 'co-1', display_name: 'Acme BV', share_code: 'ACME01' },
          company_profile: [{ slug: 'company_email', value: 'hi@acme.example' }],
          services: [{ service_link_id: 'sl-1', service_name: 'CRM', shared: [{ slug: 'x', value: 'y' }] }],
        },
      ],
    };
    const { customer } = makeCustomer(config, () => new FakeResponse(200, body));
    const conns = await customer.connections();
    assert.equal(conns.length, 1);
    assert.equal(conns[0].customerType, 'company');
    assert.equal(conns[0].companyName, 'Acme BV');
    assert.equal(conns[0].companyCode, 'ACME01');
    assert.equal(conns[0].services[0].serviceName, 'CRM');
  });
});

test('provideConsent encrypts typed answers to the target service key', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const spki = vectorPubSpkiB64();
    const { customer, transport } = makeCustomer(
      config,
      (url) => (url.includes('/api/keys/ACME01/CRM') ? new FakeResponse(200, { public_key: spki }) : new FakeResponse(200, {})),
      (_m, _u, body) => new FakeResponse(200, { ok: true }),
    );
    await customer.provideConsent('consent-1', [{ request_field_id: 'rf-1', value: 'billing@me.example' }], {
      companyCode: 'ACME01',
      serviceCode: 'CRM',
    });
    const posted = transport.requests.at(-1)!;
    assert.ok(posted.url.endsWith('/consents/consent-1/provide'));
    const decisions = (posted.json as { decisions: { kind: string; value: unknown }[] }).decisions;
    assert.equal(decisions[0].kind, 'typed');
    const priv = loadPrivateKey(vector.encrypted_private_key_pem, vector.passphrase);
    assert.equal(decrypt(decisions[0].value as { _enc: number; k: string; iv: string; d: string }, priv), 'billing@me.example');
  });
});

test('documentFile decrypts with the account key', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const wrapper = encForAccount(JSON.stringify({ file: 'data:application/pdf;base64,AAA', name: 'contract.pdf' }));
    const { customer } = makeCustomer(config, () => new FakeResponse(200, { encrypted: true, value: wrapper }));
    const out = (await customer.documentFile('conn-1', 'doc-1')) as { name: string };
    assert.equal(out.name, 'contract.pdf');
  });
});

test('drainBatch hits the customer changes route', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    let hit = false;
    const { customer } = makeCustomer(config, (url) => {
      if (url.includes('/api/customer/changes')) {
        hit = true;
        return new FakeResponse(200, { changes: [{ id: 'ch-1', event: 'share_changed', customer_type: 'company' }] });
      }
      return new FakeResponse(200, {});
    });
    const changes = await customer.drainBatch(10);
    assert.ok(hit);
    assert.equal(changes[0].id, 'ch-1');
    assert.equal(changes[0].customerType, 'company');
  });
});

test('D6: no sign/accept methods on CustomerClient', () => {
  const proto = CustomerClient.prototype as unknown as Record<string, unknown>;
  for (const banned of ['sign', 'accept', 'signDocument', 'acceptDocument', 'signEmailCode']) {
    assert.equal(banned in proto, false, `CustomerClient must not expose ${banned} (D6)`);
  }
});
