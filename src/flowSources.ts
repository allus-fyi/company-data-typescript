/**
 * A document leaf's participant PDF sources and the generation inputs they need.
 *
 * A leaf output rule's PDF is a company template (`asset_key`), a flow field's answer
 * (`source_field: slug` → source key `field:<slug>`) or what a bound customer shared on its
 * connection (`source_connection: {party, request_slug}` → `conn:<party>:<request_slug>`). The
 * generating party uploads its own copy of every HELD source of the run's current leaf, sealed under
 * the call's one-time key, before it calls `/generate`; the server refuses a generate whose inputs
 * are not exactly the held set.
 */

import { newOneTimeKey, oneTimeKeyBundle, oneTimeKeySeal } from './crypto.js';
import { ApiError } from './errors.js';

type Json = Record<string, unknown>;

function isObject(v: unknown): v is Json {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * The file a plaintext `{"_enc_file": file, …}` answer value names, else null.
 *
 * A captured, uploaded or frozen-linked file answer is that plaintext reference, never a ciphertext
 * wrapper; every other answer value is a wrapper and answers null.
 */
export function fileRef(value: unknown): string | null {
  let v = value;
  if (typeof v === 'string') {
    try {
      v = JSON.parse(v);
    } catch {
      return null;
    }
  }
  if (isObject(v)) {
    const f = v['_enc_file'];
    if (typeof f === 'string' && f !== '') return f;
  }
  return null;
}

/**
 * One held participant source of the current leaf. `kind` `field`: `slug` is the flow field and
 * `file` the generating party's own answer file; `conn`: `file` is the generating party's own copy
 * made at run start.
 */
export interface HeldSource {
  sourceKey: string;
  kind: 'field' | 'conn';
  slug: string | null;
  file: string;
}

/**
 * The held set of the leaf `nodeKey`, in rule order, each source key once.
 *
 * Reads every rule of every output of the leaf (a leaf with the older `pdfs` list carries template
 * rules only). `field:<slug>` is held when the generating party's own answer copy for the slug
 * (`for_user_id === ownUserId`) is a file reference; `conn:<party>:<slug>` when `sourceFiles` (the
 * run read's own copies) names it.
 */
export function heldSources(
  definition: Json,
  nodeKey: string | null,
  answers: Json[],
  ownUserId: string | null,
  sourceFiles: Record<string, string>,
): HeldSource[] {
  const nodes = Array.isArray(definition['nodes']) ? (definition['nodes'] as unknown[]) : [];
  const node = nodes.find((n): n is Json => isObject(n) && n['key'] === nodeKey);
  if (node === undefined || !Array.isArray(node['outputs'])) return [];
  const ownFiles = new Map<string, string>();
  for (const row of answers) {
    if (ownUserId === null || row['for_user_id'] !== ownUserId || typeof row['slug'] !== 'string') continue;
    const f = fileRef(row['value']);
    if (f !== null) ownFiles.set(row['slug'], f);
  }
  const out: HeldSource[] = [];
  const seen = new Set<string>();
  for (const output of node['outputs'] as unknown[]) {
    const rules = isObject(output) && Array.isArray(output['rules']) ? (output['rules'] as unknown[]) : [];
    for (const rule of rules) {
      if (!isObject(rule)) continue;
      const field = rule['source_field'];
      const conn = rule['source_connection'];
      if (typeof field === 'string' && field !== '') {
        const key = `field:${field}`;
        const f = ownFiles.get(field);
        if (!seen.has(key) && f !== undefined) {
          seen.add(key);
          out.push({ sourceKey: key, kind: 'field', slug: field, file: f });
        }
      } else if (isObject(conn) && typeof conn['party'] === 'string' && typeof conn['request_slug'] === 'string') {
        const key = `conn:${conn['party']}:${conn['request_slug']}`;
        const f = sourceFiles[key];
        if (!seen.has(key) && typeof f === 'string' && f !== '') {
          seen.add(key);
          out.push({ sourceKey: key, kind: 'conn', slug: null, file: f });
        }
      }
    }
  }
  return out;
}

/**
 * Upload each held source, then POST `generatePath` with `{otk, values, inputs}`.
 *
 * `envelopeOf` fetches and decrypts the generating party's own copy of one source to its envelope
 * JSON string. Each envelope is sealed under the SAME one-time key as `values` and POSTed to
 * `{generatePath}/inputs` as `{source_key, value}` → `{input}`; `inputs` is `[]` when nothing is
 * held.
 */
export async function generateWithInputs(
  post: (path: string, body: Json) => Promise<unknown>,
  generatePath: string,
  answers: Record<string, unknown>,
  held: HeldSource[],
  envelopeOf: (src: HeldSource) => Promise<string>,
): Promise<unknown> {
  const otk = newOneTimeKey();
  const inputs: { source_key: string; input: string }[] = [];
  for (const src of held) {
    const res = await post(`${generatePath}/inputs`, {
      source_key: src.sourceKey,
      value: oneTimeKeySeal(otk, await envelopeOf(src)),
    });
    const ident = isObject(res) ? res['input'] : undefined;
    if (typeof ident !== 'string' || ident === '') {
      throw new ApiError(0, null, `generate/inputs answered no input for ${src.sourceKey}`);
    }
    inputs.push({ source_key: src.sourceKey, input: ident });
  }
  return post(generatePath, { ...oneTimeKeyBundle(answers, otk), inputs });
}
