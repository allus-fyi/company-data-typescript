/**
 * HTTP/auth layer tests.
 *
 * All mocked — no live API. A FakeTransport records requests and replays scripted
 * responses so we can exercise: the client_credentials token fetch + caching, 401 →
 * one refresh-and-retry → AuthError, 429 → Retry-After backoff → retry /
 * RateLimitError, ApiError mapping (carrying the body error_key), and the JSON/XML
 * accept + parse paths. Ports test_http.py.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Config, HttpClient, ApiError, AuthError, RateLimitError } from '../src/index.js';
import type { HttpResponse, HttpTransport } from '../src/index.js';

class FakeResponse implements HttpResponse {
  readonly status: number;
  private readonly bodyText: string;
  private readonly hdrs: Record<string, string>;

  constructor(status: number, opts: { jsonBody?: unknown; text?: string; headers?: Record<string, string> } = {}) {
    this.status = status;
    if (opts.text !== undefined) this.bodyText = opts.text;
    else if (opts.jsonBody !== undefined) this.bodyText = JSON.stringify(opts.jsonBody);
    else this.bodyText = '';
    this.hdrs = opts.headers ?? {};
  }

  async text(): Promise<string> {
    return this.bodyText;
  }

  get headers(): { get(name: string): string | null } {
    const lower: Record<string, string> = {};
    for (const [k, v] of Object.entries(this.hdrs)) lower[k.toLowerCase()] = v;
    return { get: (name: string) => lower[name.toLowerCase()] ?? null };
  }
}

interface RecordedPost {
  url: string;
  form: Record<string, string>;
}
interface RecordedGet {
  url: string;
  params: Record<string, string | number> | undefined;
  headers: Record<string, string>;
}

class FakeTransport implements HttpTransport {
  postResponses: FakeResponse[] = [];
  getResponses: FakeResponse[] = [];
  posts: RecordedPost[] = [];
  gets: RecordedGet[] = [];

  async post(url: string, form: Record<string, string>): Promise<HttpResponse> {
    this.posts.push({ url, form });
    const r = this.postResponses.shift();
    if (!r) throw new Error('no queued POST response');
    return r;
  }

  async get(url: string, params: Record<string, string | number> | undefined, headers: Record<string, string>): Promise<HttpResponse> {
    this.gets.push({ url, params, headers });
    const r = this.getResponses.shift();
    if (!r) throw new Error('no queued GET response');
    return r;
  }
}

function withTmp<T>(fn: (dir: string) => T | Promise<T>): T | Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'allus-http-'));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  try {
    const out = fn(dir);
    if (out instanceof Promise) return out.finally(cleanup);
    cleanup();
    return out;
  } catch (e) {
    cleanup();
    throw e;
  }
}

function config(dir: string, fmt: 'json' | 'xml' = 'json'): Config {
  return new Config({
    apiUrl: 'https://api.allme.fyi',
    clientId: 'svc_abc',
    clientSecret: 'topsecret',
    servicePrivateKey: join(dir, 'k.pem'),
    keyPassphrase: 'pp',
    format: fmt,
  });
}

function tokenOk(): FakeResponse {
  return new FakeResponse(200, { jsonBody: { access_token: 'tok-123', token_type: 'Bearer', expires_in: 3600 } });
}

function makeClient(dir: string, t: FakeTransport, fmt: 'json' | 'xml' = 'json', sleeps: number[] = []): HttpClient {
  return new HttpClient(config(dir, fmt), {
    transport: t,
    sleep: async (s) => {
      sleeps.push(s);
    },
  });
}

// ── token fetch + caching ───────────────────────────────────────────────────

test('token is fetched with client_credentials and attached', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [new FakeResponse(200, { jsonBody: { ok: true } })];
    const c = makeClient(dir, t);

    const body = await c.get('/api/company-data/request-fields');
    assert.deepEqual(body, { ok: true });

    assert.equal(t.posts[0].url, 'https://api.allme.fyi/oauth2/token');
    assert.deepEqual(t.posts[0].form, {
      grant_type: 'client_credentials',
      client_id: 'svc_abc',
      client_secret: 'topsecret',
    });
    assert.equal(t.gets[0].headers.Authorization, 'Bearer tok-123');
    assert.equal(t.gets[0].headers.Accept, 'application/json');
  });
});

test('token is cached across calls', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [new FakeResponse(200, { jsonBody: { n: 1 } }), new FakeResponse(200, { jsonBody: { n: 2 } })];
    const c = makeClient(dir, t);
    await c.get('/api/company-data/changes');
    await c.get('/api/company-data/changes');
    assert.equal(t.posts.length, 1); // token fetched once and reused
  });
});

test('token re-fetched when expired', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [
      new FakeResponse(200, { jsonBody: { access_token: 'first', expires_in: 0 } }),
      new FakeResponse(200, { jsonBody: { access_token: 'second', expires_in: 3600 } }),
    ];
    t.getResponses = [new FakeResponse(200, { jsonBody: {} }), new FakeResponse(200, { jsonBody: {} })];
    const ticks = [0, 0, 100, 100, 100, 100];
    let i = 0;
    const c = new HttpClient(config(dir), { transport: t, clock: () => ticks[i++] ?? 100 });
    await c.get('/api/company-data/changes'); // fetches "first" (expires_in=0 → stale)
    await c.get('/api/company-data/changes'); // must refetch → "second"
    assert.equal(t.posts.length, 2);
    assert.equal(t.gets[1].headers.Authorization, 'Bearer second');
  });
});

test('token fetch failure raises AuthError', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [new FakeResponse(401, { jsonBody: { error_key: 'oauth.bad_client' } })];
    const c = makeClient(dir, t);
    await assert.rejects(() => c.get('/api/company-data/changes'), AuthError);
  });
});

// ── 401 refresh-and-retry ───────────────────────────────────────────────────

test('401 triggers one refresh-and-retry then succeeds', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk(), tokenOk()];
    t.getResponses = [
      new FakeResponse(401, { jsonBody: { error_key: 'auth.expired' } }),
      new FakeResponse(200, { jsonBody: { recovered: true } }),
    ];
    const c = makeClient(dir, t);
    const body = await c.get('/api/company-data/connections');
    assert.deepEqual(body, { recovered: true });
    assert.equal(t.posts.length, 2); // token refreshed exactly once
    assert.equal(t.gets.length, 2); // original + retry
  });
});

test('401 after refresh raises AuthError', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk(), tokenOk()];
    t.getResponses = [
      new FakeResponse(401, { jsonBody: { error_key: 'auth.expired' } }),
      new FakeResponse(401, { jsonBody: { error_key: 'auth.expired' } }),
    ];
    const c = makeClient(dir, t);
    await assert.rejects(() => c.get('/api/company-data/connections'), AuthError);
    assert.equal(t.posts.length, 2); // only ONE refresh, then gives up
  });
});

// ── 429 backoff ─────────────────────────────────────────────────────────────

test('429 with Retry-After backs off then succeeds', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [
      new FakeResponse(429, { headers: { 'Retry-After': '2' }, jsonBody: { error_key: 'rate.limited' } }),
      new FakeResponse(200, { jsonBody: { done: true } }),
    ];
    const sleeps: number[] = [];
    const c = makeClient(dir, t, 'json', sleeps);
    const body = await c.get('/api/company-data/changes');
    assert.deepEqual(body, { done: true });
    assert.deepEqual(sleeps, [2.0]); // honored Retry-After
  });
});

test('429 exhausts retries then raises RateLimitError', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    for (let i = 0; i < 10; i++) {
      t.getResponses.push(new FakeResponse(429, { headers: { 'Retry-After': '1' }, jsonBody: { error_key: 'rate.limited' } }));
    }
    const sleeps: number[] = [];
    const c = new HttpClient(config(dir), {
      transport: t,
      sleep: async (s) => {
        sleeps.push(s);
      },
      maxRetries429: 3,
    });
    await assert.rejects(
      () => c.get('/api/company-data/connections'),
      (e) => {
        assert.ok(e instanceof RateLimitError);
        assert.equal(e.retryAfter, 1.0);
        assert.equal(e.status, 429);
        assert.equal(e.errorKey, 'rate.limited');
        return true;
      },
    );
    assert.equal(sleeps.length, 3); // 3 bounded retries
    assert.equal(t.gets.length, 4); // 4 GET attempts total
  });
});

test('429 default backoff when no Retry-After', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [new FakeResponse(429, { jsonBody: { error_key: 'rate.limited' } }), new FakeResponse(200, { jsonBody: { ok: 1 } })];
    const sleeps: number[] = [];
    const c = makeClient(dir, t, 'json', sleeps);
    assert.deepEqual(await c.get('/api/company-data/changes'), { ok: 1 });
    assert.equal(sleeps.length, 1);
    assert.ok(sleeps[0] > 0); // exponential default kicked in
  });
});

// ── ApiError mapping ────────────────────────────────────────────────────────

test('non-2xx maps to ApiError with error_key', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [
      new FakeResponse(403, { jsonBody: { error: 'Not a registered service client', error_key: 'company_data.no_client' } }),
    ];
    const c = makeClient(dir, t);
    await assert.rejects(
      () => c.get('/api/company-data/connections'),
      (e) => {
        assert.ok(e instanceof ApiError);
        assert.equal(e.status, 403);
        assert.equal(e.errorKey, 'company_data.no_client');
        assert.equal(e.apiMessage, 'Not a registered service client');
        assert.ok(!(e instanceof RateLimitError)); // not a 429
        return true;
      },
    );
  });
});

test('404 maps to ApiError', async () => {
  await withTmp(async (dir) => {
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [new FakeResponse(404, { jsonBody: { error_key: 'company_data.connection_not_found' } })];
    const c = makeClient(dir, t);
    await assert.rejects(
      () => c.get('/api/company-data/connections/zzz'),
      (e) => {
        assert.ok(e instanceof ApiError);
        assert.equal(e.status, 404);
        assert.equal(e.errorKey, 'company_data.connection_not_found');
        return true;
      },
    );
  });
});

// ── XML format ──────────────────────────────────────────────────────────────

test('XML Accept header and parsing', async () => {
  await withTmp(async (dir) => {
    const xml =
      '<?xml version="1.0" encoding="UTF-8"?>' +
      '<response>' +
      '<request_fields>' +
      '<item><slug>work_email</slug><label>Work email</label><type>email</type>' +
      '<one_time>false</one_time><mandatory_provide>true</mandatory_provide>' +
      '<mandatory_connected>false</mandatory_connected></item>' +
      '<item><slug>logo</slug><label>Logo</label><type>photo</type>' +
      '<one_time>false</one_time><mandatory_provide>false</mandatory_provide>' +
      '<mandatory_connected>false</mandatory_connected></item>' +
      '</request_fields>' +
      '</response>';
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [new FakeResponse(200, { text: xml })];
    const c = makeClient(dir, t, 'xml');

    const body = (await c.get('/api/company-data/request-fields')) as Record<string, unknown>;
    assert.equal(t.gets[0].headers.Accept, 'application/xml');
    assert.ok(typeof body === 'object');
    const fields = body.request_fields as Record<string, unknown>[];
    assert.ok(Array.isArray(fields) && fields.length === 2);
    assert.equal(fields[0].slug, 'work_email');
    assert.equal(fields[0].type, 'email');
    // Booleans come back as the "true"/"false" strings the API wrote.
    assert.equal(fields[0].one_time, 'false');
    assert.equal(fields[0].mandatory_provide, 'true');
  });
});

test('XML error body carries error_key', async () => {
  await withTmp(async (dir) => {
    const xml =
      '<?xml version="1.0" encoding="UTF-8"?>' +
      '<response><error>nope</error><error_key>company_data.no_client</error_key></response>';
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [new FakeResponse(403, { text: xml })];
    const c = makeClient(dir, t, 'xml');
    await assert.rejects(
      () => c.get('/api/company-data/connections'),
      (e) => {
        assert.ok(e instanceof ApiError);
        assert.equal(e.errorKey, 'company_data.no_client');
        return true;
      },
    );
  });
});

test('XML single-item list is still a list', async () => {
  await withTmp(async (dir) => {
    const xml =
      '<?xml version="1.0" encoding="UTF-8"?>' +
      '<response><changes><item><id>c1</id><event>connection_created</event>' +
      '<person_user_id>u1</person_user_id></item></changes></response>';
    const t = new FakeTransport();
    t.postResponses = [tokenOk()];
    t.getResponses = [new FakeResponse(200, { text: xml })];
    const c = makeClient(dir, t, 'xml');
    const body = (await c.get('/api/company-data/changes')) as Record<string, unknown>;
    assert.ok(Array.isArray(body.changes));
    assert.equal((body.changes as Record<string, unknown>[])[0].event, 'connection_created');
  });
});
