/**
 * Client-facade tests. Ports test_client.py.
 *
 * Everything is MOCKED — no live API. A routed FakeTransport replays canned hardened
 * API JSON: the token, the request-fields catalog, the connections list, a single
 * connection, the logs, the changes feed, and a slot file endpoint. Ciphertext
 * fields reuse the shared decryption vector's real {_enc:1,...} wrapper + the
 * vector's key (written to a temp PEM the Client loads at construction).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { BinaryHandle, Client, Config, ConfigError, Connection, HttpClient, LogEntry, RequestField } from '../src/index.js';
import type { HttpResponse, HttpTransport, EncWrapper } from '../src/index.js';
import { encryptForKey, loadVector } from './helpers.js';

const vector = loadVector();

class FakeResponse implements HttpResponse {
  readonly status: number;
  private readonly bodyText: string;
  constructor(status: number, jsonBody?: unknown, text?: string) {
    this.status = status;
    this.bodyText = text ?? (jsonBody !== undefined ? JSON.stringify(jsonBody) : '');
  }
  async text(): Promise<string> {
    return this.bodyText;
  }
  get headers(): { get(name: string): string | null } {
    return { get: () => null };
  }
}

type Router = (url: string, params: Record<string, string | number> | undefined) => FakeResponse;

class RoutedTransport implements HttpTransport {
  posts: { url: string }[] = [];
  gets: { url: string; params: Record<string, string | number> | undefined }[] = [];
  constructor(private readonly router: Router) {}
  async post(url: string): Promise<HttpResponse> {
    this.posts.push({ url });
    return new FakeResponse(200, { access_token: 'tok-1', token_type: 'Bearer', expires_in: 3600 });
  }
  async get(url: string, params: Record<string, string | number> | undefined): Promise<HttpResponse> {
    this.gets.push({ url, params });
    return this.router(url, params);
  }
}

function withTmp<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'allus-client-'));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function makeConfig(dir: string): Config {
  const pem = join(dir, 'service-key.pem');
  writeFileSync(pem, vector.encrypted_private_key_pem, 'ascii');
  return new Config({
    apiUrl: 'https://api.allme.fyi',
    clientId: 'svc_abc',
    clientSecret: 'topsecret',
    servicePrivateKey: pem,
    keyPassphrase: vector.passphrase,
    cacheDir: join(dir, 'cache'),
  });
}

function makeClient(config: Config, router: Router): { client: Client; transport: RoutedTransport } {
  const transport = new RoutedTransport(router);
  const http = new HttpClient(config, { transport });
  return { client: new Client(config, { http }), transport };
}

const REQUEST_FIELDS_BODY = {
  request_fields: [
    { slug: 'work_email', label: 'Work email', type: 'email', one_time: false, mandatory_provide: true, mandatory_connected: false },
    { slug: 'billing_address', label: 'Billing address', type: 'address', one_time: false, mandatory_provide: false, mandatory_connected: false },
    { slug: 'logo', label: 'Logo', type: 'photo', one_time: true, mandatory_provide: false, mandatory_connected: false },
  ],
};

// ── request_fields() caches ────────────────────────────────────────────────────

test('requestFields parsed and cached', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const calls = { requestFields: 0 };
    const { client } = makeClient(config, (url) => {
      if (url.endsWith('/request-fields')) {
        calls.requestFields += 1;
        return new FakeResponse(200, REQUEST_FIELDS_BODY);
      }
      throw new Error('unexpected GET ' + url);
    });
    const fields = await client.requestFields();
    assert.deepEqual(fields.map((f) => f.slug), ['work_email', 'billing_address', 'logo']);
    assert.ok(fields.every((f) => f instanceof RequestField));
    assert.equal(fields[0].mandatory, true);

    await client.requestFields();
    assert.equal(calls.requestFields, 1); // cached
  });
});

// ── connections() lazy generator with decrypted values ────────────────────────

test('connections yields typed decrypted', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const addrWrapper = encryptForKey(vector, JSON.stringify({ city: 'Utrecht', country: 'NL' }));
    const page1 = {
      total: 1,
      items: [
        {
          connection_id: 'csc-1',
          user_id: 'person-1',
          display_name: 'Anna',
          connected_at: '2026-06-10T00:00:00Z',
          values: {
            work_email: { value: vector.text.wrapper, live: true, updatedAt: '2026-06-17T10:00:00Z' },
            billing_address: { value: addrWrapper, live: false },
            logo: { value_url: 'https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file', live: true },
          },
          pending_consent: [],
        },
      ],
    };
    const { client, transport } = makeClient(config, (url) => {
      if (url.endsWith('/request-fields')) return new FakeResponse(200, REQUEST_FIELDS_BODY);
      if (url.endsWith('/connections')) return new FakeResponse(200, page1);
      throw new Error('unexpected GET ' + url);
    });

    const conns: Connection[] = [];
    for await (const c of client.connections(100)) conns.push(c);
    assert.equal(conns.length, 1);
    const conn = conns[0];
    assert.ok(conn instanceof Connection);
    assert.equal(conn.id, 'csc-1');
    assert.equal(conn.personId, 'person-1');
    assert.equal(conn.displayName, 'Anna');

    assert.equal(conn.values.work_email.value, vector.text.plaintext);
    assert.equal(conn.values.work_email.live, true);
    assert.deepEqual(conn.values.billing_address.value, { city: 'Utrecht', country: 'NL' });
    const logo = conn.values.logo.value;
    assert.ok(logo instanceof BinaryHandle);

    const connGets = transport.gets.filter((g) => g.url.endsWith('/connections'));
    assert.equal(connGets.length, 1);
    assert.ok(!transport.gets.some((g) => g.url.includes('/file')));
  });
});

test('connections auto-pages (honors total / short page)', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const makeItem = (i: number): Record<string, unknown> => ({
      connection_id: `c${i}`,
      user_id: `p${i}`,
      display_name: `N${i}`,
      values: {},
    });
    const pages = [
      { total: 3, items: [makeItem(1), makeItem(2)] }, // full page (==limit 2)
      { total: 3, items: [makeItem(3)] }, // short page → stop
    ];
    let pageIdx = 0;
    const { client, transport } = makeClient(config, (url) => {
      if (url.endsWith('/request-fields')) return new FakeResponse(200, { request_fields: [] });
      if (url.endsWith('/connections')) return new FakeResponse(200, pages[pageIdx++]);
      throw new Error('unexpected GET ' + url);
    });
    const ids: string[] = [];
    for await (const c of client.connections(2)) ids.push(c.id);
    assert.deepEqual(ids, ['c1', 'c2', 'c3']);
    const connGets = transport.gets.filter((g) => g.url.endsWith('/connections'));
    assert.deepEqual(connGets.map((g) => g.params?.offset), [0, 2]);
  });
});

test('connections stops at total without an extra fetch', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const makeItem = (i: number): Record<string, unknown> => ({ connection_id: `c${i}`, user_id: `p${i}`, values: {} });
    // total=2, page size 2, one full page that exactly covers `total` → must NOT
    // fetch a second page (the over-fetch the task warns against).
    const { client, transport } = makeClient(config, (url) => {
      if (url.endsWith('/request-fields')) return new FakeResponse(200, { request_fields: [] });
      if (url.endsWith('/connections')) return new FakeResponse(200, { total: 2, items: [makeItem(1), makeItem(2)] });
      throw new Error('unexpected GET ' + url);
    });
    const ids: string[] = [];
    for await (const c of client.connections(2)) ids.push(c.id);
    assert.deepEqual(ids, ['c1', 'c2']);
    const connGets = transport.gets.filter((g) => g.url.endsWith('/connections'));
    assert.equal(connGets.length, 1); // honored `total` — no over-fetch of a 2nd page
  });
});

// ── binary handle fetches the slot endpoint + decrypts ─────────────────────────

test('binary handle fetches slot and decrypts', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const page = {
      total: 1,
      items: [
        {
          connection_id: 'csc-1',
          user_id: 'person-1',
          display_name: 'Anna',
          values: { logo: { value_url: 'https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file', live: true } },
        },
      ],
    };
    const { client, transport } = makeClient(config, (url) => {
      if (url.endsWith('/request-fields')) return new FakeResponse(200, REQUEST_FIELDS_BODY);
      if (url.endsWith('/connections')) return new FakeResponse(200, page);
      if (url.endsWith('/slots/sf-9/file')) return new FakeResponse(200, { encrypted: true, value: vector.binary.wrapper });
      throw new Error('unexpected GET ' + url);
    });

    const conns: Connection[] = [];
    for await (const c of client.connections()) conns.push(c);
    const handle = conns[0].values.logo.value as BinaryHandle;
    assert.ok(handle instanceof BinaryHandle);
    assert.ok(!transport.gets.some((g) => g.url.includes('/file'))); // lazy

    const data = await handle.bytes();
    assert.ok(transport.gets.some((g) => g.url.endsWith('/slots/sf-9/file')));
    assert.equal(createHash('sha256').update(data).digest('hex'), vector.binary.inner_full_sha256);
  });
});

// ── connection(id) ─────────────────────────────────────────────────────────────

test('connection by id', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const detail = {
      connection_id: 'csc-7',
      user_id: 'person-7',
      values: { work_email: { value: vector.text.wrapper, live: true } },
    };
    const { client } = makeClient(config, (url) => {
      if (url.endsWith('/request-fields')) return new FakeResponse(200, REQUEST_FIELDS_BODY);
      if (url.endsWith('/connections/csc-7')) return new FakeResponse(200, detail);
      throw new Error('unexpected GET ' + url);
    });
    const conn = await client.connection('csc-7');
    assert.equal(conn.id, 'csc-7');
    assert.equal(conn.personId, 'person-7');
    assert.equal(conn.values.work_email.value, vector.text.plaintext);
  });
});

// ── logs() ──────────────────────────────────────────────────────────────────

test('logs deserialize', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    const body = {
      total: 2,
      items: [
        { type: 'email', message: 'stale-queue alert', metadata: { days: 3 }, created_at: '2026-06-17T06:00:00Z' },
        { type: 'purge', message: 'purged 4', metadata: { count: 4 }, created_at: '2026-06-17T07:00:00Z' },
      ],
    };
    const { client, transport } = makeClient(config, (url) => {
      if (url.endsWith('/logs')) return new FakeResponse(200, body);
      throw new Error('unexpected GET ' + url);
    });
    const logs = await client.logs(50);
    assert.equal(logs.length, 2);
    assert.ok(logs.every((e) => e instanceof LogEntry));
    assert.equal(logs[0].type, 'email');
    assert.deepEqual(logs[0].metadata, { days: 3 });
    assert.equal(transport.gets[0].params?.limit, 50);
  });
});

// ── processChanges() drains the feed through the pump one-by-one ──────────────

test('processChanges drains through pump', async () => {
  await withTmp(async (dir) => {
    const config = makeConfig(dir);
    let served = false;
    const { client } = makeClient(config, (url) => {
      if (url.endsWith('/request-fields')) return new FakeResponse(200, REQUEST_FIELDS_BODY);
      if (url.endsWith('/changes')) {
        if (served) return new FakeResponse(200, { changes: [] });
        served = true;
        return new FakeResponse(200, {
          changes: [
            { id: 'chg-1', event: 'field_updated', person_user_id: 'person-1', slug: 'work_email', value: vector.text.wrapper, live: true, at: '2026-06-17T12:00:00Z' },
            { id: 'chg-2', event: 'connection_created', person_user_id: 'person-2', at: '2026-06-17T12:05:00Z' },
          ],
        });
      }
      throw new Error('unexpected GET ' + url);
    });

    const seen: Array<[string, string, unknown]> = [];
    await client.processChanges((c) => {
      seen.push([c.id, c.event, c.value]);
    });

    assert.deepEqual(seen.map((s) => s[0]), ['chg-1', 'chg-2']);
    assert.equal(seen[0][1], 'field_updated');
    assert.equal(seen[0][2], vector.text.plaintext);
    assert.equal(seen[1][1], 'connection_created');
    assert.equal(seen[1][2], null);
    assert.deepEqual(client.pump.buffer.pending(), []);
  });
});

// ── construction reads the key once (config-only keys) ────────────

test('fromConfig loads key', async () => {
  await withTmp(async (dir) => {
    const pem = join(dir, 'k.pem');
    writeFileSync(pem, vector.encrypted_private_key_pem, 'ascii');
    const cfg = join(dir, 'config.json');
    writeFileSync(
      cfg,
      JSON.stringify({
        api_url: 'https://api.allme.fyi',
        client_id: 'svc_abc',
        client_secret: 's',
        service_private_key: pem,
        key_passphrase: vector.passphrase,
        cache_dir: join(dir, 'cache'),
      }),
      'utf8',
    );
    const client = Client.fromConfig(cfg);
    // The key is loaded into memory; the decrypt closure works on the vector. We go
    // through a public path (handleWebhook value decrypt) to avoid private access.
    const handleVerified = (client as unknown as { decryptValue: (w: EncWrapper | string) => string }).decryptValue;
    assert.equal(handleVerified(vector.text.wrapper), vector.text.plaintext);
  });
});

test('fromConfig bad passphrase is ConfigError', async () => {
  await withTmp(async (dir) => {
    const pem = join(dir, 'k.pem');
    writeFileSync(pem, vector.encrypted_private_key_pem, 'ascii');
    const cfg = join(dir, 'config.json');
    writeFileSync(
      cfg,
      JSON.stringify({
        api_url: 'https://api.allme.fyi',
        client_id: 'x',
        client_secret: 's',
        service_private_key: pem,
        key_passphrase: 'WRONG',
        cache_dir: join(dir, 'cache'),
      }),
      'utf8',
    );
    assert.throws(() => Client.fromConfig(cfg), ConfigError);
  });
});
