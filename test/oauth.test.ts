/** "Sign in with allme" RP OAuth client tests (#195). Ports test_oauth.py. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Config, ConfigError, ApiError, OAuthClient } from '../src/index.js';
import type { Claim } from '../src/index.js';
import type { HttpResponse, HttpTransport } from '../src/http.js';

const VECTOR = JSON.parse(
  readFileSync(join(fileURLToPath(new URL('.', import.meta.url)), '..', 'testdata', 'decryption-vector.json'), 'utf8'),
);

function idwCfg(overrides: Record<string, unknown> = {}): Config {
  return new Config({
    apiUrl: 'https://api.allme.fyi',
    oauthClientId: 'idw_abc123',
    oauthRedirectUri: 'https://shop.example/cb',
    ...overrides,
  } as never);
}

class FakeResponse implements HttpResponse {
  constructor(
    readonly status: number,
    private readonly body?: unknown,
  ) {}
  async text(): Promise<string> {
    return this.body === undefined ? '' : JSON.stringify(this.body);
  }
  headers = { get: () => null };
}

class FakeTransport implements HttpTransport {
  posts: Array<{ url: string; form: Record<string, string> }> = [];
  gets: Array<{ url: string; headers: Record<string, string> }> = [];
  private postQ: HttpResponse[] = [];
  private getQ: HttpResponse[] = [];
  queuePost(...r: HttpResponse[]): void {
    this.postQ.push(...r);
  }
  queueGet(...r: HttpResponse[]): void {
    this.getQ.push(...r);
  }
  async post(url: string, form: Record<string, string>): Promise<HttpResponse> {
    this.posts.push({ url, form });
    return this.postQ.shift()!;
  }
  async get(url: string, _p: unknown, headers: Record<string, string>): Promise<HttpResponse> {
    this.gets.push({ url, headers });
    return this.getQ.shift()!;
  }
  async request(): Promise<HttpResponse> {
    throw new Error('not used');
  }
}

function withTmp<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'allus-oauth-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function parseUrl(url: string): { base: string; q: URLSearchParams } {
  const u = new URL(url);
  return { base: `${u.protocol}//${u.host}${u.pathname}`, q: u.searchParams };
}

// ── config ───────────────────────────────────────────────────────────────
test('idw config requires client + redirect', () => {
  withTmp((dir) => {
    const p = join(dir, 'c.json');
    writeFileSync(p, JSON.stringify({ api_url: 'https://api.allme.fyi' }));
    assert.throws(() => Config.fromIdwFile(p), ConfigError);
  });
});

test('idw config from file', () => {
  withTmp((dir) => {
    const p = join(dir, 'c.json');
    writeFileSync(p, JSON.stringify({ api_url: 'https://api.allme.fyi', oauth_client_id: 'idw_x', oauth_redirect_uri: 'https://x/cb' }));
    const cfg = Config.fromIdwFile(p);
    assert.equal(cfg.oauthClientId, 'idw_x');
    assert.equal(cfg.oauthRedirectUri, 'https://x/cb');
  });
});

// ── authorize_url ────────────────────────────────────────────────────────
test('authorizeUrl signin golden', () => {
  const c = new OAuthClient(idwCfg());
  const { base, q } = parseUrl(c.authorizeUrl('signin', { state: 'st1' }));
  assert.equal(base, 'https://web.allme.fyi/auth');
  assert.equal(q.get('client_id'), 'idw_abc123');
  assert.equal(q.get('redirect_uri'), 'https://shop.example/cb');
  assert.equal(q.get('mode'), 'signin');
  assert.equal(q.get('response_mode'), 'redirect');
  assert.equal(q.get('state'), 'st1');
  assert.equal(q.get('claims'), null);
});

test('authorizeUrl pkce + detached', () => {
  const c = new OAuthClient(idwCfg());
  const { q } = parseUrl(c.authorizeUrl('signin', { responseMode: 'detached', codeChallenge: 'CH' }));
  assert.equal(q.get('response_mode'), 'detached');
  assert.equal(q.get('code_challenge'), 'CH');
  assert.equal(q.get('code_challenge_method'), 'S256');
});

test('authorizeUrl claim validation drops binary/empty', () => {
  const c = new OAuthClient(idwCfg());
  const claims: Claim[] = [
    { type: 'email', suggest: 'email_personal' },
    { type: 'photo' },
    { type: 'phone', required: true },
    { type: '' },
  ];
  const { q } = parseUrl(c.authorizeUrl('one_time', { claims }));
  const parsed = JSON.parse(q.get('claims')!);
  assert.deepEqual(parsed.map((x: { type: string }) => x.type), ['email', 'phone']);
  assert.equal(parsed[0].suggest, 'email_personal');
  assert.equal(parsed[1].required, true);
});

test('authorizeUrl caps 15 claims', () => {
  const c = new OAuthClient(idwCfg());
  const claims: Claim[] = Array.from({ length: 30 }, () => ({ type: 'text' }));
  const { q } = parseUrl(c.authorizeUrl('one_time', { claims }));
  assert.equal(JSON.parse(q.get('claims')!).length, 15);
});

test('authorizeUrl invalid mode throws', () => {
  const c = new OAuthClient(idwCfg());
  assert.throws(() => c.authorizeUrl('bogus' as never), ConfigError);
});

// ── exchange / userinfo / complete ───────────────────────────────────────
test('exchange + userinfo', async () => {
  const t = new FakeTransport();
  t.queuePost(new FakeResponse(200, { access_token: 'AT', mode: 'signin' }));
  t.queueGet(new FakeResponse(200, { sub: 'u1', share_code: 'AB12CD', display_name: 'Alice', mode: 'signin', two_factor: false }));
  const c = new OAuthClient(idwCfg(), { transport: t });
  const tok = await c.exchangeCode('CODE', 'V');
  assert.equal(tok.access_token, 'AT');
  assert.equal(t.posts[0].form.grant_type, 'authorization_code');
  assert.equal(t.posts[0].form.code_verifier, 'V');
  const info = await c.userinfo('AT');
  assert.equal(info.display_name, 'Alice');
});

test('completeSignIn decrypts one_time values', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'allus-oauth-'));
  try {
    const pem = join(dir, 'app.pem');
    writeFileSync(pem, VECTOR.encrypted_private_key_pem);
    const cfg = idwCfg({ oauthPrivateKey: pem, oauthKeyPassphrase: VECTOR.passphrase });
    const t = new FakeTransport();
    t.queuePost(new FakeResponse(200, { access_token: 'AT', mode: 'one_time' }));
    t.queueGet(new FakeResponse(200, {
      sub: 'u1', share_code: 'AB12CD', display_name: 'Alice', mode: 'one_time', two_factor: true,
      values: { email_personal: VECTOR.text.wrapper },
    }));
    const c = new OAuthClient(cfg, { transport: t });
    const out = await c.completeSignIn('CODE', 'V');
    assert.equal(out.mode, 'one_time');
    assert.equal(out.two_factor, true);
    assert.equal(out.user.display_name, 'Alice');
    assert.equal(out.values.email_personal, VECTOR.text.plaintext);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── detached poll ────────────────────────────────────────────────────────
test('pollResult pending then code', async () => {
  const t = new FakeTransport();
  t.queuePost(new FakeResponse(202), new FakeResponse(202), new FakeResponse(200, { code: 'AUTHCODE', state: 'DET1' }));
  const c = new OAuthClient(idwCfg(), { transport: t, sleep: async () => {} });
  const res = await c.pollResult('DET1', { interval: 0.01, timeout: 5 });
  assert.equal(res.code, 'AUTHCODE');
  assert.equal(t.posts.length, 3);
});

test('pollResult expired throws', async () => {
  const t = new FakeTransport();
  t.queuePost(new FakeResponse(410, { error_key: 'oauth.result_expired' }));
  const c = new OAuthClient(idwCfg(), { transport: t, sleep: async () => {} });
  await assert.rejects(() => c.pollResult('DET1', { interval: 0.01, timeout: 5 }), (e: unknown) => e instanceof ApiError && (e as ApiError).status === 410);
});
