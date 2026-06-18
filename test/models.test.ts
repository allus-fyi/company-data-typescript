/**
 * Output-model tests. Ports test_models.py.
 *
 * Drives the model factories with hardened API JSON shaped exactly like the live
 * company-data API output (slug-keyed values; NO person source field). The
 * ciphertext fields reuse the shared decryption vector's real wrapper, decrypted
 * through the crypto core via an injected decryptValue closure.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { BinaryHandle, Change, Connection, LogEntry, RequestField, Value, decrypt } from '../src/index.js';
import type { EncWrapper } from '../src/index.js';
import { encryptForKey, loadVector, loadVectorPrivateKey } from './helpers.js';

const vector = loadVector();
const privateKey = loadVectorPrivateKey(vector);
const decryptValue = (w: EncWrapper | string): string => decrypt(w, privateKey);

// ── RequestField definitions ─────────────────────────────────────────────────

test('request fields parsed and mandatory folded', () => {
  const body = {
    request_fields: [
      { slug: 'work_email', label: 'Work email', type: 'email', one_time: false, mandatory_provide: true, mandatory_connected: false },
      { slug: 'logo', label: 'Logo', type: 'photo', one_time: true, mandatory_provide: false, mandatory_connected: false },
      { slug: 'ref', label: 'Ref', type: 'text', one_time: false, mandatory_provide: false, mandatory_connected: true },
    ],
  };
  const fields = RequestField.listFromApi(body);
  assert.deepEqual(fields.map((f) => f.slug), ['work_email', 'logo', 'ref']);
  assert.equal(fields[0].mandatory, true); // mandatory_provide
  assert.equal(fields[1].mandatory, false);
  assert.equal(fields[1].oneTime, true);
  assert.equal(fields[2].mandatory, true); // mandatory_connected folds in
  assert.equal(fields[0].raw, body.request_fields[0]);
});

test('request field coerces XML bool strings', () => {
  const body = {
    request_fields: [{ slug: 'x', label: 'X', type: 'text', one_time: 'false', mandatory_provide: 'true', mandatory_connected: 'false' }],
  };
  const f = RequestField.listFromApi(body)[0];
  assert.equal(f.oneTime, false);
  assert.equal(f.mandatory, true);
});

// ── Connection detail → typed, slug-keyed values ─────────────────────────────

function typeResolver(): (slug: string) => string | null {
  const types: Record<string, string> = { work_email: 'email', billing_address: 'address', dob: 'date', logo: 'photo' };
  return (slug) => types[slug] ?? null;
}

test('connection detail typed + slug-keyed', () => {
  const detail = {
    connection_id: 'csc-1',
    user_id: 'person-1',
    values: {
      work_email: { value: vector.text.wrapper, live: true, updatedAt: '2026-06-17T10:00:00Z' },
      billing_address: { value: encryptForKey(vector, JSON.stringify({ city: 'Utrecht', country: 'NL' })), live: false, updatedAt: '2026-06-16T09:00:00Z' },
      dob: { value: encryptForKey(vector, '1990-04-23'), live: true, updatedAt: '2026-06-15T08:00:00Z' },
      logo: { value_url: 'https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file', live: true, updatedAt: '2026-06-14T07:00:00Z' },
    },
  };
  const identity = { display_name: 'Anna', connected_at: '2026-06-10T00:00:00Z' };

  const conn = Connection.fromApi(detail, { typeForSlug: typeResolver(), decryptValue, identity });

  assert.equal(conn.id, 'csc-1');
  assert.equal(conn.personId, 'person-1');
  assert.equal(conn.displayName, 'Anna');
  assert.ok(conn.connectedAt instanceof Date);
  assert.equal(conn.raw, detail);

  const email = conn.values.work_email;
  assert.ok(email instanceof Value);
  assert.equal(email.value, vector.text.plaintext);
  assert.equal(email.live, true);
  assert.ok(email.updatedAt instanceof Date);

  const addr = conn.values.billing_address;
  assert.deepEqual(addr.value, { city: 'Utrecht', country: 'NL' });
  assert.equal(addr.live, false);

  const dob = conn.values.dob;
  assert.ok(dob.value instanceof Date);
  assert.equal((dob.value as Date).toISOString().slice(0, 10), '1990-04-23');

  const logo = conn.values.logo;
  assert.ok(logo.value instanceof BinaryHandle);
  assert.ok((logo.value as BinaryHandle).valueUrl?.endsWith('/slots/sf-9/file'));
});

test('binary handle lazy fetch and decrypt', async () => {
  const captured: { url?: string } = {};
  const fetch = (url: string): EncWrapper => {
    captured.url = url;
    return vector.binary.wrapper;
  };
  const detail = {
    connection_id: 'csc-1',
    user_id: 'person-1',
    values: { logo: { value_url: 'https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file', live: true, updatedAt: '2026-06-14T07:00:00Z' } },
  };
  const conn = Connection.fromApi(detail, { typeForSlug: () => 'photo', decryptValue, binaryFetch: fetch });
  const handle = conn.values.logo.value as BinaryHandle;
  assert.ok(handle instanceof BinaryHandle);
  assert.equal(captured.url, undefined); // not fetched until .bytes()

  const data = await handle.bytes();
  assert.ok(captured.url?.endsWith('/slots/sf-9/file'));
  assert.equal(createHash('sha256').update(data).digest('hex'), vector.binary.inner_full_sha256);

  // cached — a second call does not re-fetch (still one fetch).
  await handle.bytes();
});

test('connection has no person source field', () => {
  const detail = {
    connection_id: 'csc-1',
    user_id: 'person-1',
    values: { work_email: { value: vector.text.wrapper, live: true } },
  };
  const conn = Connection.fromApi(detail, { typeForSlug: () => 'email', decryptValue });
  const serialized = JSON.stringify(conn.raw);
  assert.ok(!serialized.includes('field_id'));
  assert.deepEqual(Object.keys(conn.values), ['work_email']);
});

// ── Change events ────────────────────────────────────────────────────────────

test('change field_updated typed and id populated', () => {
  const body = {
    changes: [
      { id: 'chg-42', event: 'field_updated', person_user_id: 'person-1', slug: 'work_email', value: vector.text.wrapper, live: true, at: '2026-06-17T12:00:00Z' },
      { id: 'chg-43', event: 'connection_created', person_user_id: 'person-2', at: '2026-06-17T12:05:00Z' },
    ],
  };
  const changes = Change.listFromApi(body, { typeForSlug: () => 'email', decryptValue });

  const f = changes[0];
  assert.equal(f.id, 'chg-42'); // stable dedup key
  assert.equal(f.event, 'field_updated');
  assert.equal(f.personId, 'person-1');
  assert.equal(f.slug, 'work_email');
  assert.equal(f.value, vector.text.plaintext); // decrypted
  assert.equal(f.live, true);
  assert.ok(f.at instanceof Date);
  assert.equal(f.raw, body.changes[0]);

  const c = changes[1];
  assert.equal(c.id, 'chg-43');
  assert.equal(c.event, 'connection_created');
  assert.equal(c.slug, null);
  assert.equal(c.value, null);
  assert.equal(c.live, null);
});

test('change field_updated binary is a lazy handle', async () => {
  const body = {
    changes: [
      { id: 'chg-50', event: 'field_updated', person_user_id: 'person-1', slug: 'logo', value_url: 'https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file', live: true, at: '2026-06-17T12:00:00Z' },
    ],
  };
  const fetch = (): EncWrapper => vector.binary.wrapper;
  const [chg] = Change.listFromApi(body, { typeForSlug: () => 'photo', decryptValue, binaryFetch: fetch });
  assert.ok(chg.value instanceof BinaryHandle);
  const data = await (chg.value as BinaryHandle).bytes();
  assert.equal(createHash('sha256').update(data).digest('hex'), vector.binary.inner_full_sha256);
});

test('change consent event has slug, no value', () => {
  const body = { changes: [{ id: 'chg-9', event: 'consent_accepted', person_user_id: 'p', slug: 'work_email', at: '2026-06-17T00:00:00Z' }] };
  const [chg] = Change.listFromApi(body, { typeForSlug: () => 'email', decryptValue: () => '' });
  assert.equal(chg.event, 'consent_accepted');
  assert.equal(chg.slug, 'work_email');
  assert.equal(chg.value, null); // consent events carry no value
});

// ── LogEntry ─────────────────────────────────────────────────────────────────

test('log entries parsed', () => {
  const body = {
    total: 2,
    items: [
      { type: 'email', message: 'stale-queue alert', metadata: { days: 3 }, at: '2026-06-17T06:00:00Z' },
      { type: 'purge', message: 'purged 4 changes', metadata: { count: 4 }, created_at: '2026-06-17T07:00:00Z' },
    ],
  };
  const logs = LogEntry.listFromApi(body);
  assert.equal(logs.length, 2);
  assert.equal(logs[0].type, 'email');
  assert.deepEqual(logs[0].metadata, { days: 3 });
  assert.ok(logs[0].at instanceof Date);
  // 'created_at' fallback for 'at'
  assert.ok(logs[1].at instanceof Date);
  assert.equal(logs[1].raw, body.items[1]);
});

test('change includes share_code', () => {
  // Every change event carries the person's profile share_code (nullable).
  const body = {
    changes: [
      { id: 'chg-1', event: 'connection_created', person_user_id: 'person-1', share_code: 'ABC123', at: '2026-06-17T12:00:00Z' },
      { id: 'chg-2', event: 'connection_created', person_user_id: 'person-2', at: '2026-06-17T12:00:00Z' }, // no share_code -> null
    ],
  };
  const changes = Change.listFromApi(body, { typeForSlug: () => null, decryptValue });
  assert.equal(changes[0].shareCode, 'ABC123');
  assert.equal(changes[1].shareCode, null);
});
