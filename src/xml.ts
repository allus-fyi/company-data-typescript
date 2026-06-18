/**
 * Minimal, XXE-safe XML parser for the platform's wire serialization.
 *
 * The company-data API can serve XML (`Accept: application/xml` / `format: "xml"`).
 * The platform serializer renders:
 *
 *   - a `<response>` document root;
 *   - a list (int keys) as repeated `<item>` children — so an element whose
 *     every child is `<item>` becomes an array;
 *   - an associative array as named child tags — an object;
 *   - scalars as element text (booleans were written as `"true"`/`"false"`).
 *
 * **XXE-safe by construction.** This is a hand-written recursive-descent parser
 * (NOT a general XML library). It supports ONLY elements, text, comments, the XML
 * declaration, CDATA, and the five built-in entities. It does NOT process a DOCTYPE
 * / DTD, does NOT define or expand custom/general entities, and never resolves
 * external entities or system identifiers — the classic XXE / billion-laughs
 * vectors cannot occur because the machinery for them is simply absent. A DOCTYPE,
 * a processing instruction other than the XML decl, or an unknown `&entity;`
 * reference is rejected — entity expansion and external entity resolution don't
 * exist here at all. HMAC verification is always computed over the raw bytes,
 * never the parsed tree.
 *
 * This is intentionally small — JSON is the default wire format; XML is the opt-in
 * alternative — and it only needs to invert the company-data payloads (dicts of
 * lists of dicts of scalars).
 */

export class XmlParseError extends Error {}

type XmlValue = string | XmlValue[] | { [key: string]: XmlValue };

interface XmlNode {
  tag: string;
  children: XmlNode[];
  text: string;
}

// The ONLY entities recognized — the five XML built-ins. No custom/general/external
// entity is ever defined or expanded (XXE-safe).
const BUILTIN_ENTITIES: Record<string, string> = {
  lt: '<',
  gt: '>',
  amp: '&',
  quot: '"',
  apos: "'",
};

function decodeEntities(s: string): string {
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (_m, body: string) => {
    if (body[0] === '#') {
      const isHex = body[1] === 'x' || body[1] === 'X';
      const codeStr = isHex ? body.slice(2) : body.slice(1);
      const code = parseInt(codeStr, isHex ? 16 : 10);
      if (Number.isNaN(code) || code < 0 || code > 0x10ffff) {
        throw new XmlParseError(`invalid numeric character reference &${body};`);
      }
      return String.fromCodePoint(code);
    }
    const replacement = BUILTIN_ENTITIES[body];
    if (replacement === undefined) {
      // A non-builtin entity reference — reject rather than expand. This is the
      // XXE / entity-expansion guard: we never define or look up custom entities.
      throw new XmlParseError(`unsupported XML entity &${body}; (custom/external entities are disabled)`);
    }
    return replacement;
  });
}

class Parser {
  private readonly s: string;
  private i = 0;

  constructor(text: string) {
    this.s = text;
  }

  parse(): XmlNode {
    this.skipProlog();
    const root = this.parseElement();
    this.skipMisc();
    if (this.i < this.s.length) {
      throw new XmlParseError('trailing content after the document root element');
    }
    return root;
  }

  private skipWhitespace(): void {
    while (this.i < this.s.length && /\s/.test(this.s[this.i])) this.i++;
  }

  // Skip the XML declaration, comments, and whitespace BEFORE the root element.
  // A DOCTYPE is explicitly rejected (no DTD processing — XXE-safe).
  private skipProlog(): void {
    for (;;) {
      this.skipWhitespace();
      if (this.s.startsWith('<?xml', this.i)) {
        this.skipUntil('?>');
        continue;
      }
      if (this.s.startsWith('<!--', this.i)) {
        this.skipUntil('-->');
        continue;
      }
      if (this.s.startsWith('<!DOCTYPE', this.i) || this.s.startsWith('<!doctype', this.i)) {
        throw new XmlParseError('DOCTYPE / DTD is not allowed (XXE-safe parser)');
      }
      if (this.s.startsWith('<?', this.i)) {
        throw new XmlParseError('processing instructions are not allowed');
      }
      return;
    }
  }

  // Skip comments + whitespace AFTER the root element (epilogue).
  private skipMisc(): void {
    for (;;) {
      this.skipWhitespace();
      if (this.s.startsWith('<!--', this.i)) {
        this.skipUntil('-->');
        continue;
      }
      return;
    }
  }

  private skipUntil(marker: string): void {
    const idx = this.s.indexOf(marker, this.i);
    if (idx === -1) throw new XmlParseError(`unterminated '${marker}'`);
    this.i = idx + marker.length;
  }

  private parseName(): string {
    const start = this.i;
    // XML name chars (a permissive but safe subset): letters, digits, _, -, ., :
    while (this.i < this.s.length && /[A-Za-z0-9_\-.:]/.test(this.s[this.i])) this.i++;
    if (this.i === start) throw new XmlParseError(`expected an element name at offset ${this.i}`);
    return this.s.slice(start, this.i);
  }

  // Skip attributes within a start tag (the platform serializer emits none, but be
  // tolerant). Attribute VALUES are read but never define entities.
  private skipAttributes(): void {
    for (;;) {
      this.skipWhitespace();
      const c = this.s[this.i];
      if (c === '>' || c === '/' || c === undefined) return;
      // name
      this.parseName();
      this.skipWhitespace();
      if (this.s[this.i] !== '=') throw new XmlParseError('malformed attribute (expected =)');
      this.i++; // '='
      this.skipWhitespace();
      const quote = this.s[this.i];
      if (quote !== '"' && quote !== "'") throw new XmlParseError('attribute value must be quoted');
      this.i++;
      const end = this.s.indexOf(quote, this.i);
      if (end === -1) throw new XmlParseError('unterminated attribute value');
      this.i = end + 1;
    }
  }

  private parseElement(): XmlNode {
    if (this.s[this.i] !== '<') throw new XmlParseError(`expected '<' at offset ${this.i}`);
    this.i++; // '<'
    const tag = this.parseName();
    this.skipAttributes();

    if (this.s.startsWith('/>', this.i)) {
      this.i += 2; // self-closing
      return { tag, children: [], text: '' };
    }
    if (this.s[this.i] !== '>') throw new XmlParseError(`malformed start tag <${tag}>`);
    this.i++; // '>'

    const node: XmlNode = { tag, children: [], text: '' };
    const textParts: string[] = [];

    for (;;) {
      if (this.i >= this.s.length) throw new XmlParseError(`unterminated element <${tag}>`);

      if (this.s.startsWith('</', this.i)) {
        this.i += 2;
        const closeName = this.parseName();
        this.skipWhitespace();
        if (this.s[this.i] !== '>') throw new XmlParseError(`malformed end tag </${closeName}>`);
        this.i++; // '>'
        if (closeName !== tag) {
          throw new XmlParseError(`mismatched end tag: </${closeName}> closing <${tag}>`);
        }
        break;
      }

      if (this.s.startsWith('<!--', this.i)) {
        this.skipUntil('-->');
        continue;
      }

      if (this.s.startsWith('<![CDATA[', this.i)) {
        const end = this.s.indexOf(']]>', this.i + 9);
        if (end === -1) throw new XmlParseError('unterminated CDATA section');
        textParts.push(this.s.slice(this.i + 9, end)); // raw — no entity decode in CDATA
        this.i = end + 3;
        continue;
      }

      if (this.s.startsWith('<!DOCTYPE', this.i) || this.s.startsWith('<!doctype', this.i)) {
        throw new XmlParseError('DOCTYPE / DTD is not allowed (XXE-safe parser)');
      }
      if (this.s.startsWith('<?', this.i)) {
        throw new XmlParseError('processing instructions are not allowed');
      }

      if (this.s[this.i] === '<') {
        node.children.push(this.parseElement());
        continue;
      }

      // Text run up to the next '<'.
      const lt = this.s.indexOf('<', this.i);
      const end = lt === -1 ? this.s.length : lt;
      textParts.push(decodeEntities(this.s.slice(this.i, end)));
      this.i = end;
    }

    node.text = textParts.join('');
    return node;
  }
}

function nodeToValue(node: XmlNode): XmlValue {
  if (node.children.length === 0) {
    // A leaf node: its text. Callers coerce types from the known schema; we keep
    // the raw string (booleans came over as "true"/"false").
    return node.text;
  }

  // All children are <item> → an array (PHP int-keyed list).
  if (node.children.every((c) => c.tag === 'item')) {
    return node.children.map(nodeToValue);
  }

  // Otherwise an object: named tags → keys. Repeated tags collapse to a list.
  const result: { [key: string]: XmlValue } = {};
  for (const child of node.children) {
    const value = nodeToValue(child);
    if (child.tag in result) {
      const existing = result[child.tag];
      if (Array.isArray(existing)) {
        existing.push(value);
      } else {
        result[child.tag] = [existing, value];
      }
    } else {
      result[child.tag] = value;
    }
  }
  return result;
}

/**
 * Parse the platform's XML serialization back into JS data (XXE-safe).
 *
 * Mirrors the platform serializer (see the module doc). Returns the document root
 * element's value (a `<response>` element → an object). Throws {@link XmlParseError}
 * on malformed XML, a DOCTYPE/DTD, a processing instruction, or any non-builtin
 * entity reference.
 */
export function parseXml(text: string): XmlValue {
  const root = new Parser(text).parse();
  return nodeToValue(root);
}
