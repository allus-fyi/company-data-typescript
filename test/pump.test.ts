/**
 * Crash-safe changes-pump tests. Ports test_pump.py.
 *
 * Drives the pump with a fake in-memory changes source that returns canned
 * CIPHERTEXT events (reusing the shared decryption vector's real {_enc:1,...}
 * wrapper as a value) and a decrypt callable that runs the real crypto core.
 * Nothing here touches the live API.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Change, Config, DecryptError, FileBuffer, Pump, decrypt } from '../src/index.js';
import type { BufferedEvent, EncWrapper } from '../src/index.js';
import { loadVector, loadVectorPrivateKey } from './helpers.js';

const vector = loadVector();
const privateKey = loadVectorPrivateKey(vector);
const cipherWrapper = vector.text.wrapper;
const expectedPlaintext = vector.text.plaintext;

function tmpCache(): string {
  return join(mkdtempSync(join(tmpdir(), 'allus-pump-')), 'allus-cache');
}

function makeConfig(cacheDir: string): Config {
  return new Config({
    apiUrl: 'https://api.example.test',
    clientId: 'svc_test',
    clientSecret: 'secret',
    servicePrivateKey: 'unused.pem',
    keyPassphrase: vector.passphrase,
    cacheDir,
  });
}

const decryptChange = (event: BufferedEvent): Change =>
  Change.fromApi(event, { typeForSlug: () => 'text', decryptValue: (w) => decrypt(w as EncWrapper, privateKey) });

function makeEvents(count: number, start = 1): BufferedEvent[] {
  const events: BufferedEvent[] = [];
  for (let i = start; i < start + count; i++) {
    events.push({
      id: `chg-${String(i).padStart(4, '0')}`,
      event: 'field_updated',
      person_user_id: `person-${i}`,
      slug: 'work_email',
      value: cipherWrapper, // ciphertext, exactly as the API serves it
      live: true,
      at: `2026-06-17T10:0${i}:00Z`,
    });
  }
  return events;
}

class FakeSource {
  queue: BufferedEvent[];
  fetchCalls: number[] = [];
  constructor(events: BufferedEvent[]) {
    this.queue = [...events];
  }
  fetch = (limit: number): BufferedEvent[] => {
    this.fetchCalls.push(limit);
    const batch = this.queue.slice(0, limit);
    this.queue.splice(0, batch.length);
    return batch;
  };
}

const noSleep = async (): Promise<void> => {};

async function withCache(fn: (cacheDir: string) => Promise<void>): Promise<void> {
  const cacheDir = tmpCache();
  const root = join(cacheDir, '..');
  try {
    await fn(cacheDir);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// ── (a) persist-before-deliver ────────────────────────────────────────────────

test('batch persisted before any handler call', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(3));
    let pendingAtFirst = -1;
    const handler = (): void => {
      if (pendingAtFirst === -1) {
        // On the very first delivery, the buffer must already hold the WHOLE batch.
        pendingAtFirst = new FileBuffer(cacheDir).pending().length;
      }
    };
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await pump.processChanges(handler);
    assert.equal(pendingAtFirst, 3);
  });
});

// ── (b) ack on success ─────────────────────────────────────────────────────────

test('handler success acks pending file', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(3));
    const seen: string[] = [];
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await pump.processChanges((c) => {
      seen.push(c.id);
    });
    assert.deepEqual(seen, ['chg-0001', 'chg-0002', 'chg-0003']);
    const buf = new FileBuffer(cacheDir);
    assert.deepEqual(buf.pending(), []);
    assert.deepEqual(buf.deadLetters(), []);
  });
});

test('delivered change is decrypted plaintext', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(1));
    const delivered: Change[] = [];
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await pump.processChanges((c) => {
      delivered.push(c);
    });
    assert.equal(delivered.length, 1);
    assert.equal(delivered[0].value, expectedPlaintext); // not the wrapper
  });
});

// ── (c) retry → dead-letter → continue ────────────────────────────────────────

test('poison event dead-lettered, others processed', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(3));
    let attempts2 = 0;
    const deliveredOk: string[] = [];
    const handler = (change: Change): void => {
      if (change.id === 'chg-0002') {
        attempts2 += 1;
        throw new Error('poison');
      }
      deliveredOk.push(change.id);
    };
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange, sleep: noSleep });
    await pump.processChanges(handler, { maxRetries: 3 });

    assert.equal(attempts2, 4); // 1 + max_retries
    assert.deepEqual(deliveredOk, ['chg-0001', 'chg-0003']);

    const buf = new FileBuffer(cacheDir);
    assert.deepEqual(buf.pending(), []);
    const dl = buf.deadLetters();
    assert.deepEqual(dl.map((d) => d.id), ['chg-0002']);
    assert.ok(String(dl[0].error).includes('poison'));
    assert.equal(dl[0].attempts, 4);
  });
});

test("on_error='halt' raises and leaves pending", async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(3));
    const handler = (change: Change): void => {
      if (change.id === 'chg-0002') throw new Error('halt-me');
    };
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange, sleep: noSleep });
    await assert.rejects(() => pump.processChanges(handler, { maxRetries: 1, onError: 'halt' }), /halt-me/);
    const buf = new FileBuffer(cacheDir);
    const pendingIds = buf.pending().map((e) => e.id);
    // chg-0001 acked; chg-0002 (failed) + chg-0003 (never reached) still pending.
    assert.deepEqual(pendingIds, ['chg-0002', 'chg-0003']);
  });
});

// ── (d) crash test ─────────────────────────────────────────────────────────────

test('crash after one then replay on restart', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(3));
    class Crash extends Error {}
    const deliveredRun1: string[] = [];
    const crashingHandler = (change: Change): void => {
      deliveredRun1.push(change.id);
      if (deliveredRun1.length === 1) return; // #1 succeeds → acked
      throw new Crash(); // process dies right after #1's ack, before #2/#3 ack
    };
    const pump1 = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await assert.rejects(() => pump1.processChanges(crashingHandler, { maxRetries: 0, onError: 'halt' }), Crash);

    assert.deepEqual(deliveredRun1, ['chg-0001', 'chg-0002']);
    const bufMid = new FileBuffer(cacheDir);
    assert.deepEqual(bufMid.pending().map((e) => e.id), ['chg-0002', 'chg-0003']);

    // Restart: a brand-new pump on the SAME cache_dir, with NO new events.
    const emptySource = new FakeSource([]);
    const deliveredRun2: string[] = [];
    const pump2 = new Pump(config, { fetchChanges: emptySource.fetch, decrypt: decryptChange });
    await pump2.processChanges((c) => {
      deliveredRun2.push(c.id);
    });
    assert.deepEqual(deliveredRun2, ['chg-0002', 'chg-0003']);
    assert.ok(emptySource.fetchCalls.length > 0 && emptySource.fetchCalls[0] >= 1);

    const bufEnd = new FileBuffer(cacheDir);
    assert.deepEqual(bufEnd.pending(), []);
  });
});

test('Change.id stable across replay', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(2));
    class Crash extends Error {}
    const run1: Array<[string, unknown]> = [];
    const crashAfterNone = (change: Change): void => {
      run1.push([change.id, change.value]);
      throw new Crash(); // crash immediately → both stay pending
    };
    const pump1 = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await assert.rejects(() => pump1.processChanges(crashAfterNone, { maxRetries: 0, onError: 'halt' }), Crash);

    const run2: Array<[string, unknown]> = [];
    const empty = new FakeSource([]);
    const pump2 = new Pump(config, { fetchChanges: empty.fetch, decrypt: decryptChange });
    await pump2.processChanges((c) => {
      run2.push([c.id, c.value]);
    });

    assert.equal(run1[0][0], 'chg-0001');
    assert.deepEqual(run2[0], ['chg-0001', run1[0][1]]); // same id AND same decrypted value
  });
});

// ── (e) ciphertext at rest ─────────────────────────────────────────────────────

test('buffer files store ciphertext not plaintext', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(2));
    class Stop extends Error {}
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await assert.rejects(
      () =>
        pump.processChanges(
          () => {
            throw new Stop();
          },
          { maxRetries: 0, onError: 'halt' },
        ),
      Stop,
    );

    const pendingDir = join(cacheDir, 'pending');
    const files = readdirSync(pendingDir)
      .filter((n) => n.endsWith('.json'))
      .sort();
    assert.ok(files.length > 0, 'expected pending files on disk');
    for (const name of files) {
      const rawText = readFileSync(join(pendingDir, name), 'utf8');
      assert.ok(!rawText.includes(expectedPlaintext)); // plaintext NOT on disk
      const stored = JSON.parse(rawText) as { value: EncWrapper };
      assert.equal(stored.value._enc, 1);
      assert.equal(stored.value.k, cipherWrapper.k);
    }
  });
});

// ── (f) returns when drained ───────────────────────────────────────────────────

test('processChanges returns when source drained', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(5));
    const delivered: string[] = [];
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await pump.processChanges((c) => {
      delivered.push(c.id);
    }, { batchSize: 2 });
    assert.deepEqual(delivered, ['chg-0001', 'chg-0002', 'chg-0003', 'chg-0004', 'chg-0005']);
    assert.deepEqual(source.queue, []);
    assert.equal(source.fetchCalls[source.fetchCalls.length - 1], 2);
  });
});

test('empty source returns immediately', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource([]);
    const delivered: Change[] = [];
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await pump.processChanges((c) => {
      delivered.push(c);
    });
    assert.deepEqual(delivered, []);
    assert.deepEqual(source.fetchCalls, [100]); // one drain, default batch size, got nothing
  });
});

test('batch size clamped to 500', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(1));
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await pump.processChanges(() => {}, { batchSize: 9999 });
    assert.equal(Math.max(...source.fetchCalls), 500);
  });
});

// ── drain_batch primitive + dead-letter retry ─────────────────────────────────

test('drainBatch is raw unbuffered', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(3));
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    const batch = await pump.drainBatch(2);
    assert.deepEqual(batch.map((c) => c.id), ['chg-0001', 'chg-0002']);
    const buf = new FileBuffer(cacheDir);
    assert.deepEqual(buf.pending(), []); // nothing buffered
    assert.deepEqual(source.fetchCalls, [2]);
  });
});

test('drainBatch clamped to 500', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource([]);
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange });
    await pump.drainBatch(10000);
    assert.deepEqual(source.fetchCalls, [500]);
  });
});

test('retryDeadLetters re-drives', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(2));
    const alwaysFail2 = (change: Change): void => {
      if (change.id === 'chg-0002') throw new Error('boom');
    };
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange, sleep: noSleep });
    await pump.processChanges(alwaysFail2, { maxRetries: 1 });

    const buf = new FileBuffer(cacheDir);
    assert.deepEqual(buf.deadLetters().map((d) => d.id), ['chg-0002']);

    const redriven: string[] = [];
    await pump.retryDeadLetters((c) => {
      redriven.push(c.id);
    });
    assert.deepEqual(redriven, ['chg-0002']);
    assert.deepEqual(new FileBuffer(cacheDir).deadLetters(), []);
  });
});

test('retryDeadLetters still failing stays deadlettered, never pending', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(2));
    const fail2 = (change: Change): void => {
      if (change.id === 'chg-0002') throw new Error('boom');
    };
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange, sleep: noSleep });
    await pump.processChanges(fail2, { maxRetries: 1 });

    const buf = new FileBuffer(cacheDir);
    const dl0 = buf.deadLetters();
    assert.deepEqual(dl0.map((d) => d.id), ['chg-0002']);
    assert.equal(dl0[0].attempts, 2); // 1 + max_retries
    const pendingDir = join(cacheDir, 'pending');
    const deadletterDir = join(cacheDir, 'deadletter');

    const redriven = await pump.retryDeadLetters(fail2, { maxRetries: 2 });
    assert.equal(redriven, 0);

    const buf2 = new FileBuffer(cacheDir);
    const dl1 = buf2.deadLetters();
    assert.deepEqual(dl1.map((d) => d.id), ['chg-0002']);
    assert.equal(dl1[0].attempts, 3); // 1 + the 2 re-drive attempts
    assert.ok(String(dl1[0].error).includes('boom'));
    assert.deepEqual(buf2.pending(), []);
    assert.deepEqual(readdirSync(pendingDir), []); // not even a temp/leftover file
    const dlFiles = readdirSync(deadletterDir).filter((n) => n.endsWith('.json'));
    assert.equal(dlFiles.length, 1);

    const ok: string[] = [];
    const again = await pump.retryDeadLetters((c) => {
      ok.push(c.id);
    });
    assert.equal(again, 1);
    assert.deepEqual(ok, ['chg-0002']);
    assert.deepEqual(new FileBuffer(cacheDir).deadLetters(), []);
    assert.deepEqual(new FileBuffer(cacheDir).pending(), []);
  });
});

test('retryDeadLetters attempts monotonic across runs', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(2));
    const fail2 = (change: Change): void => {
      if (change.id === 'chg-0002') throw new Error('boom');
    };
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange, sleep: noSleep });
    await pump.processChanges(fail2, { maxRetries: 3 });
    const dl0 = new FileBuffer(cacheDir).deadLetters();
    assert.deepEqual(dl0.map((d) => d.id), ['chg-0002']);
    assert.equal(dl0[0].attempts, 4); // 1 initial + 3 retries

    // Re-drive with a SMALLER budget (run-local attempts = 1). Stored count stays 4.
    assert.equal(await pump.retryDeadLetters(fail2, { maxRetries: 0 }), 0);
    const dl1 = new FileBuffer(cacheDir).deadLetters();
    assert.deepEqual(dl1.map((d) => d.id), ['chg-0002']);
    assert.equal(dl1[0].attempts, 4); // monotonic — NOT 1
  });
});

test('retryDeadLetters crash window never resurrects to pending', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const source = new FakeSource(makeEvents(1, 2)); // one event: chg-0002
    const alwaysFail = (): void => {
      throw new Error('boom');
    };
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: decryptChange, sleep: noSleep });
    await pump.processChanges(alwaysFail, { maxRetries: 0 }); // → chg-0002 dead-lettered
    assert.deepEqual(new FileBuffer(cacheDir).deadLetters().map((d) => d.id), ['chg-0002']);

    class Crash extends Error {}
    // The buggy path would do remove→append-to-pending→dead_letter; crashing at
    // dead_letter is the window that leaves the event LIVE in pending/. The FIXED
    // code never calls deadLetter on a re-fail (it uses updateDeadLetter in place),
    // so this patch is inert for the fix — but lethal for the bug.
    (pump.buffer as unknown as { deadLetter: () => void }).deadLetter = () => {
      throw new Crash();
    };
    try {
      await pump.retryDeadLetters(alwaysFail, { maxRetries: 0 });
    } catch (e) {
      if (!(e instanceof Crash)) throw e;
    }

    const replayed: string[] = [];
    const pump2 = new Pump(config, { fetchChanges: new FakeSource([]).fetch, decrypt: decryptChange, sleep: noSleep });
    await pump2.processChanges((c) => {
      replayed.push(c.id);
    });
    assert.deepEqual(replayed, []); // nothing resurrected into the live stream
    assert.deepEqual(new FileBuffer(cacheDir).pending(), []);
    assert.deepEqual(new FileBuffer(cacheDir).deadLetters().map((d) => d.id), ['chg-0002']);
  });
});

// ── poison-decrypt: must not wedge the stream ─────────────────────────────────

function makePoisonEvent(startId: string): BufferedEvent {
  return {
    id: startId,
    event: 'field_updated',
    person_user_id: 'person-x',
    slug: 'work_email',
    value: { _enc: 1, k: '@@notbase64@@', iv: 'AAAA', d: 'AAAA' },
    live: true,
    at: '2026-06-17T10:09:00Z',
  };
}

test('poison decrypt dead-letters without wedging', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const decryptCalls: Record<string, number> = { 'chg-0002': 0 };
    const poisonDecrypt = (event: BufferedEvent): Change => {
      const cid = event.id as string;
      if (cid === 'chg-0002') {
        decryptCalls['chg-0002'] += 1;
        throw new DecryptError('corrupt ciphertext for chg-0002');
      }
      return Change.fromApi(event, { typeForSlug: () => 'text', decryptValue: (w) => decrypt(w as EncWrapper, privateKey) });
    };

    const events = makeEvents(1, 1);
    events.push(makePoisonEvent('chg-0002'));
    events.push(...makeEvents(1, 3));
    const source = new FakeSource(events);

    const delivered: string[] = [];
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: poisonDecrypt, sleep: noSleep });
    await pump.processChanges((c) => {
      delivered.push(c.id);
    }, { maxRetries: 3 });

    assert.deepEqual(delivered, ['chg-0001', 'chg-0003']);
    assert.equal(decryptCalls['chg-0002'], 1); // dead-lettered IMMEDIATELY, no retries

    const buf = new FileBuffer(cacheDir);
    assert.deepEqual(buf.pending(), []);
    const dl = buf.deadLetters();
    assert.deepEqual(dl.map((d) => d.id), ['chg-0002']);
    assert.ok(String(dl[0].error).includes('DecryptError'));
    assert.equal(dl[0].attempts, 1);

    assert.deepEqual(readdirSync(join(cacheDir, 'pending')), []);
    const dlFiles = readdirSync(join(cacheDir, 'deadletter')).filter((n) => n.endsWith('.json'));
    assert.equal(dlFiles.length, 1);

    const delivered2: string[] = [];
    const pump2 = new Pump(config, { fetchChanges: new FakeSource([]).fetch, decrypt: poisonDecrypt, sleep: noSleep });
    await pump2.processChanges((c) => {
      delivered2.push(c.id);
    });
    assert.deepEqual(delivered2, []);
    assert.deepEqual(new FileBuffer(cacheDir).deadLetters().map((d) => d.id), ['chg-0002']);
  });
});

test('poison decrypt with halt re-raises', async () => {
  await withCache(async (cacheDir) => {
    const config = makeConfig(cacheDir);
    const poisonDecrypt = (event: BufferedEvent): Change => {
      if (event.id === 'chg-0001') throw new DecryptError('undecryptable');
      return Change.fromApi(event, { typeForSlug: () => 'text', decryptValue: (w) => decrypt(w as EncWrapper, privateKey) });
    };
    const source = new FakeSource([makePoisonEvent('chg-0001')]);
    const pump = new Pump(config, { fetchChanges: source.fetch, decrypt: poisonDecrypt, sleep: noSleep });
    await assert.rejects(() => pump.processChanges(() => {}, { onError: 'halt' }), /undecryptable/);
    const buf = new FileBuffer(cacheDir);
    assert.deepEqual(buf.pending().map((e) => e.id), ['chg-0001']);
  });
});
