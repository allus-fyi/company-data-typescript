/**
 * The 2FA client's additions on top of the base challenge/result client: waitForResult.
 * Ports test_two_factor.py.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { TwoFactorClient, ApiError } from '../src/index.js';
import type { HttpClient } from '../src/http.js';

/** Minimal stand-in for HttpClient — queues the dict bodies get() returns. */
class FakeHttp {
  private getQ: unknown[] = [];
  gets: string[] = [];
  queueGet(...bodies: unknown[]): void {
    this.getQ.push(...bodies);
  }
  async get(path: string): Promise<unknown> {
    this.gets.push(path);
    if (this.getQ.length === 0) throw new Error('no queued GET response');
    return this.getQ.shift();
  }
  async post(): Promise<unknown> {
    throw new Error('post not expected');
  }
}

function makeClient(): { c: TwoFactorClient; http: FakeHttp } {
  const http = new FakeHttp();
  const c = new TwoFactorClient(http as unknown as HttpClient, { sleep: async () => {} });
  return { c, http };
}

test('waitForResult returns first terminal', async () => {
  const { c, http } = makeClient();
  http.queueGet(
    { status: 'pending' },
    { status: 'pending' },
    { status: 'approved', completed_at: '2026-07-24T10:00:00Z' },
  );
  const res = await c.waitForResult('chal_1', { timeout: 600, interval: 0 });
  assert.equal(res.status, 'approved');
  assert.equal(res.completedAt, '2026-07-24T10:00:00Z');
  // Stopped at the first terminal read — never re-read a burned challenge.
  assert.equal(http.gets.length, 3);
});

for (const terminal of ['approved', 'denied', 'expired', 'revoked', 'gone']) {
  test(`waitForResult each terminal status: ${terminal}`, async () => {
    const { c, http } = makeClient();
    http.queueGet({ status: 'pending' }, { status: terminal });
    assert.equal((await c.waitForResult('chal_1', { timeout: 600, interval: 0 })).status, terminal);
  });
}

test('waitForResult timeout rejects with ApiError', async () => {
  const { c, http } = makeClient();
  // timeout=0 → after the first pending poll the deadline has passed.
  http.queueGet({ status: 'pending' }, { status: 'pending' });
  await assert.rejects(
    () => c.waitForResult('chal_late', { timeout: 0, interval: 0 }),
    (e: unknown) => e instanceof ApiError && /not completed within/.test((e as Error).message),
  );
});
