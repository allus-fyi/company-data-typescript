/**
 * XXE-safe XML parser tests.
 *
 * The parser must invert the API's XML output AND reject the XXE /
 * entity-expansion vectors (DOCTYPE/DTD, custom/external entities). It supports
 * only elements/text/comments/CDATA/XML-decl + the five built-in entities.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseXml, XmlParseError } from '../src/index.js';

test('parses the <response> object shape', () => {
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>' +
    '<response><a>1</a><b>two</b></response>';
  assert.deepEqual(parseXml(xml), { a: '1', b: 'two' });
});

test('parses an <item> list as an array', () => {
  const xml = '<response><xs><item>a</item><item>b</item></xs></response>';
  assert.deepEqual(parseXml(xml), { xs: ['a', 'b'] });
});

test('repeated named tags collapse to a list', () => {
  const xml = '<response><x>1</x><x>2</x></response>';
  assert.deepEqual(parseXml(xml), { x: ['1', '2'] });
});

test('booleans come over as the "true"/"false" strings', () => {
  const xml = '<response><flag>true</flag></response>';
  assert.deepEqual(parseXml(xml), { flag: 'true' });
});

test('decodes the five built-in entities', () => {
  const xml = '<response><t>a&lt;b&gt;c&amp;d&quot;e&apos;f</t></response>';
  assert.deepEqual(parseXml(xml), { t: 'a<b>c&d"e\'f' });
});

test('decodes numeric character references', () => {
  const xml = '<response><t>&#65;&#x42;</t></response>';
  assert.deepEqual(parseXml(xml), { t: 'AB' });
});

test('handles CDATA without entity decode', () => {
  const xml = '<response><t><![CDATA[<not> & parsed]]></t></response>';
  assert.deepEqual(parseXml(xml), { t: '<not> & parsed' });
});

// ── XXE-safety: the vectors that MUST be rejected ──────────────────────────────

test('rejects a DOCTYPE (no DTD processing)', () => {
  const xml = '<?xml version="1.0"?><!DOCTYPE foo><response><a>1</a></response>';
  assert.throws(() => parseXml(xml), XmlParseError);
});

test('rejects the billion-laughs / custom-entity expansion vector', () => {
  // A classic entity-expansion DoS shape — must be rejected, never expanded.
  const xml =
    '<?xml version="1.0"?>' +
    '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>' +
    '<response><t>&lol2;</t></response>';
  assert.throws(() => parseXml(xml), XmlParseError);
});

test('rejects an external-entity (classic XXE) reference', () => {
  // Even without a DOCTYPE, an unknown entity reference is rejected (never resolved).
  const xml = '<response><t>&xxe;</t></response>';
  assert.throws(() => parseXml(xml), XmlParseError);
});

test('rejects a processing instruction', () => {
  const xml = '<response><?php echo 1; ?><a>1</a></response>';
  assert.throws(() => parseXml(xml), XmlParseError);
});

test('rejects a mismatched end tag', () => {
  const xml = '<response><a>1</b></response>';
  assert.throws(() => parseXml(xml), XmlParseError);
});

test('reconstructs an _enc wrapper from XML (nested object)', () => {
  const xml = '<response><value><_enc>1</_enc><k>AA</k><iv>BB</iv><d>CC</d></value></response>';
  assert.deepEqual(parseXml(xml), { value: { _enc: '1', k: 'AA', iv: 'BB', d: 'CC' } });
});
