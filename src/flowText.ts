/**
 * The value tags a contract-flow TEXT element names, read by the platform's text grammar: HTML
 * tags are removed first, `\[` `\]` `\{` `\\` are escapes, and a `{{…}}` an escape breaks is not a
 * tag. A tag inside a link address (`[a href=X]`) is a tag too. A starter compiles the values of
 * the definition's non-owner PARTY tags before it starts a run ({@link AllusClient.triggerFlowRun}).
 */

type Json = Record<string, unknown>;

const HTML_TAG = /<\/?[a-zA-Z][^<>]*>/g;
const TAG_AT = /\{\{\s*([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,2})\s*\}\}/iy;
const ESCAPABLE = '[]{\\';

/** Whether an address starting at `from` has an unescaped `]` closing it. */
function addressCloses(s: string, from: number): boolean {
  for (let i = from; i < s.length; i++) {
    if (s[i] === '\\' && i + 1 < s.length && ESCAPABLE.includes(s[i + 1])) {
      i++;
      continue;
    }
    if (s[i] === ']') return true;
  }
  return false;
}

/** Every value-tag key a text body names — in its text and its link addresses — lower-cased, first use first. */
export function flowTextTags(body: string): string[] {
  const s = String(body ?? '').replace(HTML_TAG, '');
  const out: string[] = [];
  let inAddress = false;
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '\\' && i + 1 < s.length && ESCAPABLE.includes(s[i + 1])) {
      i += 2;
      continue;
    }
    if (c === '{') {
      TAG_AT.lastIndex = i;
      const m = TAG_AT.exec(s);
      if (m) {
        const k = m[1].toLowerCase();
        if (!out.includes(k)) out.push(k);
        i += m[0].length;
        continue;
      }
    }
    if (inAddress && c === ']') {
      inAddress = false;
      i++;
      continue;
    }
    if (!inAddress && c === '[' && s.slice(i, i + 8).toLowerCase() === '[a href=' && addressCloses(s, i + 8)) {
      inAddress = true;
      i += 8;
      continue;
    }
    i++;
  }
  return out;
}

/** The body a text element renders: its `body`, else `text`, else `label`. */
function bodyOf(el: Json): string {
  for (const k of ['body', 'text', 'label']) {
    const v = el[k];
    if (typeof v === 'string' && v !== '') return v;
  }
  return '';
}

/** One non-owner party tag of a definition: the tag, its party key and its field (request slug). */
export interface PartyTag {
  tag: string;
  party: string;
  field: string;
}

/**
 * The definition's NON-OWNER party tags — the tags whose values a starter compiles and seals —
 * lower-cased, first use first.
 */
export function nonOwnerPartyTags(definition: Json): PartyTag[] {
  const types = new Map<string, string | null>();
  for (const p of Array.isArray(definition['parties']) ? (definition['parties'] as unknown[]) : []) {
    if (p !== null && typeof p === 'object' && typeof (p as Json)['key'] === 'string') {
      const t = (p as Json)['type'];
      types.set(String((p as Json)['key']).toLowerCase(), typeof t === 'string' && t !== '' ? t : null);
    }
  }
  const out: PartyTag[] = [];
  for (const n of Array.isArray(definition['nodes']) ? (definition['nodes'] as unknown[]) : []) {
    const els = n !== null && typeof n === 'object' ? (n as Json)['elements'] : null;
    for (const el of Array.isArray(els) ? els : []) {
      if (el === null || typeof el !== 'object' || (el as Json)['kind'] !== 'text') continue;
      for (const tag of flowTextTags(bodyOf(el as Json))) {
        const dot = tag.indexOf('.');
        if (dot < 0) continue;
        const party = tag.slice(0, dot);
        if (!types.has(party) || types.get(party) === 'owner') continue;
        if (!out.some((x) => x.tag === tag)) out.push({ tag, party, field: tag.slice(dot + 1) });
      }
    }
  }
  return out;
}
