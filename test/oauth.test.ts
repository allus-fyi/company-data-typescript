/** "Sign in with allme" RP OAuth client tests. Ports test_oauth.py. */
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
  // Every claim carries a mandatory `name` — the identity everything downstream is keyed by.
  const claims: Claim[] = [
    { name: 'email', type: 'email', suggest: 'email_personal' },
    { name: 'avatar', type: 'photo' },
    { name: 'phone', type: 'phone', required: true },
    { name: 'nothing', type: '' },
  ];
  const { q } = parseUrl(c.authorizeUrl('one_time', { claims }));
  const parsed = JSON.parse(q.get('claims')!);
  assert.deepEqual(parsed.map((x: { type: string }) => x.type), ['email', 'phone']);
  assert.deepEqual(parsed.map((x: { name: string }) => x.name), ['email', 'phone']);
  assert.equal(parsed[0].suggest, 'email_personal');
  assert.equal(parsed[1].required, true);
});

// §2: a nameless claim, and two sharing a name, are refused at the call that made them.
test('authorizeUrl requires a claim name and rejects duplicates', () => {
  const c = new OAuthClient(idwCfg());
  assert.throws(() => c.authorizeUrl('one_time', { claims: [{ type: 'email' } as Claim] }), ConfigError);
  assert.throws(() => c.authorizeUrl('one_time', {
    claims: [{ name: 'email', type: 'email' }, { name: 'email', type: 'text' }],
  }), ConfigError);
});

// §3: `verified` travels on the wire, so an RP can demand an attested answer.
test('authorizeUrl carries the verified requirement', () => {
  const c = new OAuthClient(idwCfg());
  const { q } = parseUrl(c.authorizeUrl('signin', {
    claims: [{ name: 'email', type: 'email', verified: true }],
  }));
  const parsed = JSON.parse(q.get('claims')!);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].verified, true);
});

test('authorizeUrl caps 15 claims', () => {
  const c = new OAuthClient(idwCfg());
  const claims: Claim[] = Array.from({ length: 30 }, (_, i) => ({ name: `c${i}`, type: 'text' }));
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
  t.queueGet(new FakeResponse(200, { sub: 'AB12CD', share_code: 'AB12CD', mode: 'signin', two_factor: false }));
  const c = new OAuthClient(idwCfg(), { transport: t });
  const tok = await c.exchangeCode('CODE', 'V');
  assert.equal(tok.access_token, 'AT');
  assert.equal(t.posts[0].form.grant_type, 'authorization_code');
  assert.equal(t.posts[0].form.code_verifier, 'V');
  const info = await c.userinfo('AT');
  // §5: `sub` IS the share code (byte-identical to the id_token's); display_name is gone.
  assert.equal(info.sub, 'AB12CD');
  assert.equal(info.sub, info.share_code);
  assert.equal(info.display_name, undefined);
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
      sub: 'AB12CD', share_code: 'AB12CD', mode: 'one_time', two_factor: true,
      values: { email_personal: VECTOR.text.wrapper },
    }));
    const c = new OAuthClient(cfg, { transport: t });
    const out = await c.completeSignIn('CODE', 'V');
    assert.equal(out.mode, 'one_time');
    assert.equal(out.two_factor, true);
    assert.equal(out.user.sub, 'AB12CD');
    // §3.1a: no `values_attestation` on the wire → "not attested", never "wrong".
    assert.deepEqual(out.attestations, {});
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

// ── 2fa_enroll mode + detached enrollment poll delivery ────────────────────
test('authorizeUrl accepts 2fa_enroll mode', () => {
  const c = new OAuthClient(idwCfg());
  const { q } = parseUrl(c.authorizeUrl('2fa_enroll', { responseMode: 'detached', state: 'EN1' }));
  assert.equal(q.get('mode'), '2fa_enroll');
  assert.equal(q.get('response_mode'), 'detached');
});

test('pollResult pending then enrolled', async () => {
  // A detached 2fa_enroll delivers {enrolled: true, state}, NOT a code. pollResult must
  // return on the `enrolled` sentinel — otherwise it consumes the one-shot result and times out.
  const t = new FakeTransport();
  t.queuePost(new FakeResponse(202), new FakeResponse(200, { enrolled: true, state: 'EN1' }));
  const c = new OAuthClient(idwCfg(), { transport: t, sleep: async () => {} });
  const res = await c.pollResult('EN1', { interval: 0.01, timeout: 5 });
  assert.equal(res.enrolled, true);
  assert.equal(res.state, 'EN1');
  assert.equal(t.posts.length, 2); // returned on first delivery, never polled past it
});

test('pollResult still returns on code after enroll change', async () => {
  // Regression: the enroll addition must not break the sign-in `code` delivery.
  const t = new FakeTransport();
  t.queuePost(new FakeResponse(200, { code: 'AUTHCODE', state: 'DET1' }));
  const c = new OAuthClient(idwCfg(), { transport: t, sleep: async () => {} });
  assert.equal((await c.pollResult('DET1', { interval: 0.01, timeout: 5 })).code, 'AUTHCODE');
});
