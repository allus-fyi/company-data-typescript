/** Config loader tests. Ports test_config.py. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Config, ConfigError } from '../src/index.js';

function withTmp<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'allus-cfg-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function writeCfg(dir: string, data: unknown): string {
  const p = join(dir, 'config.json');
  writeFileSync(p, JSON.stringify(data), 'utf8');
  return p;
}

function full(): Record<string, unknown> {
  return {
    api_url: 'https://api.allme.fyi',
    client_id: 'svc_abc',
    client_secret: 'file-secret',
    service_private_key: './service-CRM.pem',
    key_passphrase: 'file-passphrase',
    account_private_key: './account.pem',
    account_passphrase: 'acct-pass',
    webhooks: { wh_1: 'secret-one', wh_2: 'secret-two' },
    cache_dir: './allus-cache',
    format: 'json',
  };
}

// Reset env between tests that touch ALLUS_* vars.
function clearAllusEnv(): void {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('ALLUS_')) delete process.env[k];
  }
}

test('fromFile loads all fields', () => {
  clearAllusEnv();
  withTmp((dir) => {
    const cfg = Config.fromFile(writeCfg(dir, full()));
    assert.equal(cfg.apiUrl, 'https://api.allme.fyi');
    assert.equal(cfg.clientId, 'svc_abc');
    assert.equal(cfg.clientSecret, 'file-secret');
    assert.equal(cfg.servicePrivateKey, './service-CRM.pem');
    assert.equal(cfg.keyPassphrase, 'file-passphrase');
    assert.equal(cfg.accountPrivateKey, './account.pem');
    assert.equal(cfg.accountPassphrase, 'acct-pass');
    assert.equal(cfg.cacheDir, './allus-cache');
    assert.equal(cfg.format, 'json');
    assert.equal(cfg.webhookSecret('wh_1'), 'secret-one');
    assert.equal(cfg.webhookSecret('wh_2'), 'secret-two');
  });
});

test('optional fields default', () => {
  clearAllusEnv();
  withTmp((dir) => {
    const cfg = Config.fromFile(
      writeCfg(dir, {
        api_url: 'https://api.allme.fyi',
        client_id: 'svc_abc',
        client_secret: 's',
        service_private_key: './k.pem',
        key_passphrase: 'p',
      }),
    );
    assert.equal(cfg.accountPrivateKey, null);
    assert.equal(cfg.accountPassphrase, null);
    assert.deepEqual(cfg.webhooks, {});
    assert.equal(cfg.cacheDir, './allus-cache'); // default
    assert.equal(cfg.format, 'json'); // default
  });
});

test('env overrides file values', () => {
  clearAllusEnv();
  withTmp((dir) => {
    const path = writeCfg(dir, full());
    process.env.ALLUS_CLIENT_SECRET = 'env-secret';
    process.env.ALLUS_KEY_PASSPHRASE = 'env-passphrase';
    process.env.ALLUS_API_URL = 'https://api-eu.allme.fyi';
    try {
      const cfg = Config.fromFile(path);
      assert.equal(cfg.clientSecret, 'env-secret');
      assert.equal(cfg.keyPassphrase, 'env-passphrase');
      assert.equal(cfg.apiUrl, 'https://api-eu.allme.fyi');
      assert.equal(cfg.clientId, 'svc_abc'); // from file (no env)
    } finally {
      clearAllusEnv();
    }
  });
});

test('fromEnv builds without a file', () => {
  clearAllusEnv();
  process.env.ALLUS_API_URL = 'https://api.allme.fyi';
  process.env.ALLUS_CLIENT_ID = 'svc_env';
  process.env.ALLUS_CLIENT_SECRET = 'env-secret';
  process.env.ALLUS_SERVICE_PRIVATE_KEY = './k.pem';
  process.env.ALLUS_KEY_PASSPHRASE = 'env-pass';
  try {
    const cfg = Config.fromEnv();
    assert.equal(cfg.clientId, 'svc_env');
    assert.equal(cfg.clientSecret, 'env-secret');
  } finally {
    clearAllusEnv();
  }
});

test('missing required field raises ConfigError', () => {
  clearAllusEnv();
  withTmp((dir) => {
    const data = full();
    delete data.client_secret;
    assert.throws(() => Config.fromFile(writeCfg(dir, data)), (e) => e instanceof ConfigError && /client_secret/.test((e as Error).message));
  });
});

test('missing file raises ConfigError', () => {
  clearAllusEnv();
  withTmp((dir) => {
    assert.throws(() => Config.fromFile(join(dir, 'does-not-exist.json')), ConfigError);
  });
});

test('invalid JSON raises ConfigError', () => {
  clearAllusEnv();
  withTmp((dir) => {
    const p = join(dir, 'bad.json');
    writeFileSync(p, '{ not valid json', 'utf8');
    assert.throws(() => Config.fromFile(p), ConfigError);
  });
});

test('invalid format raises ConfigError', () => {
  clearAllusEnv();
  withTmp((dir) => {
    const data = full();
    data.format = 'yaml';
    assert.throws(() => Config.fromFile(writeCfg(dir, data)), ConfigError);
  });
});

test('flat webhook_secret shortcut', () => {
  clearAllusEnv();
  withTmp((dir) => {
    const cfg = Config.fromFile(
      writeCfg(dir, {
        api_url: 'https://api.allme.fyi',
        client_id: 'svc_abc',
        client_secret: 's',
        service_private_key: './k.pem',
        key_passphrase: 'p',
        webhook_secret: 'the-only-secret',
      }),
    );
    // No id, or an unknown id, falls back to the single-webhook secret.
    assert.equal(cfg.webhookSecret(), 'the-only-secret');
    assert.equal(cfg.webhookSecret('anything'), 'the-only-secret');
  });
});

test('no key or secret is ever a method argument', () => {
  // Config-only key handling: the only cryptographic-adjacent method,
  // webhookSecret(), takes a webhook *id* — never a secret. TS erases param names at
  // runtime, so we assert the documented arity: exactly one (optional) id argument,
  // and that calling it with a *bogus id* (not a secret) yields the configured
  // fallback rather than treating the argument as a secret.
  assert.equal(Config.prototype.webhookSecret.length, 1); // a single id parameter
  const cfg = new Config({
    apiUrl: 'x',
    clientId: 'x',
    clientSecret: 'x',
    servicePrivateKey: 'x',
    keyPassphrase: 'x',
    webhooks: { 'wh-1': 'the-secret' },
  });
  // Passing an id resolves to that webhook's secret; an arbitrary string is NOT
  // treated as a secret — it's looked up as an id (miss → null).
  assert.equal(cfg.webhookSecret('wh-1'), 'the-secret');
  assert.equal(cfg.webhookSecret('not-an-id'), null);
});
