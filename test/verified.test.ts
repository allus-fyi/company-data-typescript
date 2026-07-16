import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Value, Change } from '../src/models.js';

const h = (salt: string, pt: string) => createHash('sha256').update(salt + pt, 'utf8').digest('hex');
const decryptPlain = (pt: string) => () => pt;

test('#311 Value.verified true on match', () => {
  const pt = 'alice@example.com', salt = '0011223344556677';
  const v = Value.fromApi({ value: pt, live: true, verified_hash: h(salt, pt), verified_salt: salt } as any,
    { fieldType: 'email', decryptValue: decryptPlain(pt) as any });
  assert.equal(v.verified, true);
});

test('#311 Value.verified false on mismatch', () => {
  const pt = 'alice@example.com', salt = '0011223344556677';
  const v = Value.fromApi({ value: pt, live: true, verified_hash: 'deadbeef'.repeat(8), verified_salt: salt } as any,
    { fieldType: 'email', decryptValue: decryptPlain(pt) as any });
  assert.equal(v.verified, false);
});

test('#311 Value.verified false when absent', () => {
  const pt = 'alice@example.com';
  const v = Value.fromApi({ value: pt, live: true } as any, { fieldType: 'email', decryptValue: decryptPlain(pt) as any });
  assert.equal(v.verified, false);
});

test('#311 Change field_updated verified', () => {
  const pt = 'bob@example.com', salt = 'aabbccddeeff0011';
  const ch = Change.fromApi({ id: 'c1', event: 'field_updated', person_user_id: 'u1', slug: 'email_personal',
    value: pt, verified_hash: h(salt, pt), verified_salt: salt } as any,
    { typeForSlug: () => 'email', decryptValue: decryptPlain(pt) as any } as any);
  assert.equal(ch.verified, true);
});
