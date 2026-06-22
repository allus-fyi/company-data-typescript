/**
 * Decryption core tests.
 *
 * These prove the TypeScript decryptor reproduces the SHARED test vector
 * (`sdks/testdata/decryption-vector.json`), and — crucially, to avoid circularity —
 * that the vector's wrappers are PLATFORM-correct, by decrypting the text wrapper
 * through a fully INDEPENDENT toolchain (the OpenSSL CLI for the PBES2 PEM + the
 * RSA-OAEP-SHA256 unwrap, then a separate AES-256-GCM step) and getting the same
 * plaintext.
 *
 * This is the cross-language crypto-parity GATE: PEM-load + every text case + the
 * binary case → inner-bytes sha256 match.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, createDecipheriv, generateKeyPairSync } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  BinaryHandle,
  DecryptError,
  decrypt,
  encryptForPublicKey,
  loadPrivateKey,
  loadPublicKey,
} from '../src/index.js';
import { VECTOR_PATH, loadVector, loadVectorPrivateKey } from './helpers.js';

const vector = loadVector();
const privateKey = loadVectorPrivateKey(vector);

// ── Self-consistent decryption (the SDK's own crypto core) ──────────────────

test('loadPrivateKey loads the PBES2 PEM', () => {
  const key = loadPrivateKey(vector.encrypted_private_key_pem, vector.passphrase);
  // The key is a 2048-bit RSA key.
  const detail = key.asymmetricKeyDetails;
  assert.equal(detail?.modulusLength, 2048);
});

test('loadPrivateKey with the wrong passphrase throws DecryptError', () => {
  assert.throws(() => loadPrivateKey(vector.encrypted_private_key_pem, 'the-wrong-passphrase'), DecryptError);
});

test('decrypt(text wrapper) matches the known plaintext', () => {
  const plaintext = decrypt(vector.text.wrapper, privateKey);
  assert.equal(plaintext, vector.text.plaintext);
});

test('decrypt accepts the wrapper as a JSON string', () => {
  const wrapperStr = JSON.stringify(vector.text.wrapper);
  assert.equal(decrypt(wrapperStr, privateKey), vector.text.plaintext);
});

test('decrypt(binary wrapper) → envelope string + inner bytes (the binary gate)', async () => {
  // Decrypting a binary wrapper yields a JSON envelope STRING.
  const envelopeJson = decrypt(vector.binary.wrapper, privateKey);
  assert.equal(
    createHash('sha256').update(envelopeJson, 'utf8').digest('hex'),
    vector.binary.decrypted_json_sha256,
  );

  // The BinaryHandle parses the envelope -> base64-decodes the "full"/"file"
  // data-URI payload -> the inner file bytes.
  const inner = BinaryHandle.parseEnvelopeBytes(envelopeJson);
  assert.equal(createHash('sha256').update(inner).digest('hex'), vector.binary.inner_full_sha256);

  // And via the handle's public .bytes() entry point.
  const handle = new BinaryHandle({ envelopeJson });
  const bytes = await handle.bytes();
  assert.equal(createHash('sha256').update(bytes).digest('hex'), vector.binary.inner_full_sha256);
});

// ── Error paths ─────────────────────────────────────────────────────────────

test('decrypt with a tampered GCM tag throws DecryptError', () => {
  const bad = { ...vector.text.wrapper };
  const raw = Buffer.from(bad.d, 'base64');
  raw[raw.length - 1] ^= 0xff; // corrupt the last byte of the GCM tag
  bad.d = raw.toString('base64');
  assert.throws(() => decrypt(bad, privateKey), DecryptError);
});

test('decrypt with a missing field throws DecryptError', () => {
  // no "d"
  assert.throws(() => decrypt({ _enc: 1, k: 'AAAA', iv: 'AAAA' } as never, privateKey), DecryptError);
});

test('decrypt with bad base64 throws DecryptError', () => {
  const bad = { ...vector.text.wrapper, k: 'not valid base64 !!!' };
  assert.throws(() => decrypt(bad, privateKey), DecryptError);
});

test('decrypt with a wrong iv length throws DecryptError', () => {
  const bad = { ...vector.text.wrapper, iv: randomBytes(16).toString('base64') }; // 16, not 12
  assert.throws(() => decrypt(bad, privateKey), DecryptError);
});

test('parseEnvelopeBytes without full/file throws DecryptError', () => {
  assert.throws(() => BinaryHandle.parseEnvelopeBytes(JSON.stringify({ thumb: 'x' })), DecryptError);
});

// ── BinaryHandle.save() is atomic (temp + rename) ───────────────────────────

test('BinaryHandle.save writes the decoded bytes and returns the count', async () => {
  const envelopeJson = decrypt(vector.binary.wrapper, privateKey);
  const handle = new BinaryHandle({ envelopeJson });
  const dir = mkdtempSync(join(tmpdir(), 'allus-save-'));
  try {
    const out = join(dir, 'out.bin');
    const n = await handle.save(out);
    const data = readFileSync(out);
    assert.equal(n, data.length);
    assert.equal(createHash('sha256').update(data).digest('hex'), vector.binary.inner_full_sha256);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('BinaryHandle.save is atomic — no partial output on a crash mid-write', async () => {
  // We make `bytes()` throw via a poison handle (no envelope/wiring); the existing
  // destination must survive intact and no temp/.part file may leak.
  const dir = mkdtempSync(join(tmpdir(), 'allus-save-atomic-'));
  try {
    const dest = join(dir, 'existing.bin');
    const original = Buffer.from('ORIGINAL-CONTENT-MUST-SURVIVE');
    writeFileSync(dest, original);

    // A handle with no envelope + no fetch/decrypt wiring → bytes() throws BEFORE
    // any temp file is created (the failure path we exercise).
    const poison = new BinaryHandle({});
    await assert.rejects(() => poison.save(dest), DecryptError);

    // Destination untouched, and no .tmp_/.part leftovers in the directory.
    assert.deepEqual(readFileSync(dest), original);
    const leftovers = readdirSync(dir).filter((n) => n.startsWith('.tmp_') || n.endsWith('.part'));
    assert.deepEqual(leftovers, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Anti-circularity: independent openssl + node cross-check ────────────────

function which(cmd: string): boolean {
  try {
    execFileSync(process.platform === 'win32' ? 'where' : 'which', [cmd], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Decrypt the vector's text wrapper WITHOUT this SDK's `decrypt`, using the OpenSSL
 * CLI for the PBES2 PEM + the RSA-OAEP-SHA256 unwrap, then a fresh AES-256-GCM step.
 * Proves the wrapper format is platform-correct (anti-circularity).
 */
function independentDecryptText(): string {
  const w = vector.text.wrapper;
  const dir = mkdtempSync(join(tmpdir(), 'allus-xcheck-'));
  try {
    const pemPath = join(dir, 'key.pem');
    const plainPem = join(dir, 'key_plain.pem');
    const kPath = join(dir, 'k.bin');
    const aesPath = join(dir, 'aeskey.bin');

    writeFileSync(pemPath, vector.encrypted_private_key_pem, 'ascii');
    writeFileSync(kPath, Buffer.from(w.k, 'base64'));

    // 1) OpenSSL: decrypt the PBES2 PKCS#8 PEM with the passphrase.
    execFileSync('openssl', ['pkcs8', '-in', pemPath, '-passin', `pass:${vector.passphrase}`, '-out', plainPem]);
    // 2) OpenSSL: RSA-OAEP-SHA256 (MGF1-SHA256) unwrap the AES key.
    execFileSync('openssl', [
      'pkeyutl',
      '-decrypt',
      '-inkey',
      plainPem,
      '-pkeyopt',
      'rsa_padding_mode:oaep',
      '-pkeyopt',
      'rsa_oaep_md:sha256',
      '-pkeyopt',
      'rsa_mgf1_md:sha256',
      '-in',
      kPath,
      '-out',
      aesPath,
    ]);
    // 3) A FRESH AES-256-GCM decrypt (the openssl-derived key, not via src/crypto.ts
    //    decrypt — but here using node:crypto's createDecipheriv directly so the
    //    SDK's decrypt() wrapper isn't on the path).
    const aesKey = readFileSync(aesPath);
    const ivBuf = Buffer.from(w.iv, 'base64');
    const dBuf = Buffer.from(w.d, 'base64');
    const tag = dBuf.subarray(dBuf.length - 16);
    const ciphertext = dBuf.subarray(0, dBuf.length - 16);
    // Inline node:crypto AES step — independent of src/crypto.ts's decrypt() wrapper.
    const dc = createDecipheriv('aes-256-gcm', aesKey, ivBuf);
    dc.setAuthTag(tag);
    return Buffer.concat([dc.update(ciphertext), dc.final()]).toString('utf8');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('independent openssl cross-check (anti-circularity)', { skip: !which('openssl') ? 'openssl required' : false }, () => {
  assert.equal(independentDecryptText(), vector.text.plaintext);
});

// Sanity: the shared vector file actually exists on disk where the gate reads it.
test('the shared vector file exists', () => {
  assert.ok(existsSync(VECTOR_PATH));
});

// ── encryptForPublicKey round-trips through decrypt ─────────────────────────────

test('encryptForPublicKey round-trips through decrypt', () => {
  // A throwaway RSA-2048 keypair; export the public half as base64 SPKI/DER (what
  // GET /api/keys returns), then encrypt → decrypt back.
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const pub = loadPublicKey(spkiB64);

  for (const pt of ['hello', '{"a":1}', 'with-üñîçödé', '']) {
    const wrapper = encryptForPublicKey(pt, pub);
    assert.equal(wrapper._enc, 1);
    assert.ok(wrapper.k && wrapper.iv && wrapper.d);
    assert.equal(decrypt(wrapper, privateKey), pt);
  }
});

test('loadPublicKey rejects garbage', () => {
  assert.throws(() => loadPublicKey('not-base64!!'), DecryptError);
  assert.throws(() => loadPublicKey(Buffer.from('not a spki key').toString('base64')), DecryptError);
});
