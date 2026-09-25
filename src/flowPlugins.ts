/**
 * Plugin fields on a contract-flow step, from the company party's side.
 *
 * A flow element of kind `plugin` asks a company-configured plugin: its blocks are answered by
 * picks and typed values, its inputs are wired to earlier flow keys, and its outputs come back
 * from the plugin. The SDK talks to the plugin through the platform's forwarder:
 *
 *   1. a PASS from the run's pass route (`{pass, forwarder_url, plugins, specs}`);
 *   2. the request `{field_type, op, block?, query?, picks, values, inputs, reply_key}` sealed to
 *      the plugin's public key with the platform wrapper, `reply_key` being the public half of a
 *      fresh RSA-2048 pair made for the call;
 *   3. `POST {forwarder_url}/call` `{pass, plugin_id, request}` over a PLAIN transport — the API
 *      client attaches the bearer token and rebuilds absolute URLs against the API base, so it
 *      must never carry this call;
 *   4. the reply `{reply}` opened with the private half of the reply pair.
 *
 * Inputs and bounds are read from ONE live answer map: the run's answers this party can read,
 * overlaid with the caller's draft for the current step's slugs, plugin answers expanded, constants
 * computed. Another party's private value is never sent to a plugin.
 */

import type { KeyObject } from 'node:crypto';

import {
  decrypt,
  encryptForPublicKey,
  generateReplyKeyPair,
  loadPublicKey,
} from './crypto.js';
import { ApiError, ConfigError, DecryptError, PluginInputUnavailable, ValidationError } from './errors.js';
import {
  computeConstants,
  evaluateFlowExpression,
  expandPluginAnswers,
  flowDateUtc,
  flowExprRefs,
  flowNumber,
  flowString,
} from './flowCondition.js';

type Json = Record<string, unknown>;

function isObj(v: unknown): v is Json {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// ── the pass and the reply shapes ─────────────────────────────────────────────

/** One plugin a pass unlocks; `publicKey` is null while its description is missing or failed. */
export interface PluginPassPlugin {
  id: string;
  publicKey: string | null;
}

/** A short-lived pass for the plugins of the run's current step. */
export class PluginPass {
  constructor(
    /** The signed pass, posted in the call body. */
    readonly pass: string,
    /** Where calls go: `POST {forwarderUrl}/call`. */
    readonly forwarderUrl: string,
    readonly plugins: PluginPassPlugin[],
    /** slug → the plugin field's spec `{plugin_id, field_type, snapshot, inputs}`. */
    readonly specs: Record<string, Json>,
    readonly raw: Json,
  ) {}

  static fromApi(body: Json): PluginPass {
    const plugins: PluginPassPlugin[] = [];
    for (const p of Array.isArray(body['plugins']) ? (body['plugins'] as unknown[]) : []) {
      if (!isObj(p) || p['id'] == null) continue;
      const key = p['public_key'];
      plugins.push({ id: String(p['id']), publicKey: typeof key === 'string' && key !== '' ? key : null });
    }
    const specs: Record<string, Json> = {};
    if (isObj(body['specs'])) {
      for (const [k, v] of Object.entries(body['specs'] as Json)) if (isObj(v)) specs[k] = v;
    }
    return new PluginPass(
      body['pass'] != null ? String(body['pass']) : '',
      body['forwarder_url'] != null ? String(body['forwarder_url']) : '',
      plugins,
      specs,
      body,
    );
  }

  publicKeyOf(pluginId: string): string | null {
    return this.plugins.find((p) => p.id === pluginId)?.publicKey ?? null;
  }
}

/** One option of a `search_select` block. */
export interface PluginOption {
  id: string;
  label: string;
}

/** A plugin's option list for one block; `more` says the list was cut (keep typing). */
export class PluginOptions {
  constructor(
    readonly options: PluginOption[],
    readonly more: boolean,
    readonly raw: Json,
  ) {}

  static fromReply(reply: Json): PluginOptions {
    const options: PluginOption[] = [];
    for (const o of Array.isArray(reply['options']) ? (reply['options'] as unknown[]) : []) {
      if (!isObj(o) || o['id'] == null) continue;
      options.push({ id: String(o['id']), label: o['label'] != null ? String(o['label']) : '' });
    }
    return new PluginOptions(options, reply['more'] === true, reply);
  }
}

/** A plugin's outputs for the picks and inputs sent, typed as the plugin declared them. */
export class PluginOutputs {
  readonly picksInvalid = false as const;
  constructor(
    readonly outputs: Record<string, unknown>,
    readonly raw: Json,
  ) {}
}

/**
 * The plugin answered that the picks no longer fit the current inputs or each other: clear the
 * picks, pick again, and call `pluginOutputs` again before submitting.
 */
export class PluginPicksInvalid {
  readonly picksInvalid = true as const;
  constructor(readonly raw: Json) {}
}

// ── the party's view of a run ─────────────────────────────────────────────────

/** What a party can read of a run — the inputs to the live answer map and the privacy rules. */
export interface FlowPartyView {
  definition: Json;
  currentNode: string | null;
  referenceDate: string | null;
  /** The run's answers this party can read, decrypted: slug → plaintext. */
  stored: Record<string, unknown>;
  /** The run's `private_slugs`; null = unknown. */
  privateSlugs: string[] | null;
  /** The party keys bound to the caller. */
  ownPartyKeys: Set<string>;
}

function nodesOf(definition: Json): Json[] {
  const nodes = definition['nodes'];
  return Array.isArray(nodes) ? (nodes.filter(isObj) as Json[]) : [];
}

function elementsOf(node: Json): Json[] {
  const els = node['elements'];
  return Array.isArray(els) ? (els.filter(isObj) as Json[]) : [];
}

/** The slugs of every plugin element of the definition. */
export function pluginSlugsOf(definition: Json): string[] {
  const out: string[] = [];
  for (const n of nodesOf(definition)) {
    for (const el of elementsOf(n)) {
      if (el['kind'] === 'plugin' && typeof el['slug'] === 'string') out.push(el['slug'] as string);
    }
  }
  return out;
}

/** The field and plugin elements of one node, by slug. */
function nodeElements(definition: Json, nodeKey: string | null): Map<string, Json> {
  const out = new Map<string, Json>();
  for (const n of nodesOf(definition)) {
    if (n['key'] !== nodeKey) continue;
    for (const el of elementsOf(n)) {
      if ((el['kind'] === 'field' || el['kind'] === 'plugin') && typeof el['slug'] === 'string') {
        out.set(el['slug'] as string, el);
      }
    }
  }
  return out;
}

/** The node an element slug sits on, with the element. */
function elementNode(definition: Json, slug: string): { node: Json; element: Json } | null {
  for (const n of nodesOf(definition)) {
    for (const el of elementsOf(n)) {
      if (el['slug'] === slug && (el['kind'] === 'field' || el['kind'] === 'plugin')) return { node: n, element: el };
    }
  }
  return null;
}

/** The draft entries that belong to the current step; everything else is ignored. */
function currentDraft(view: FlowPartyView, draft: Record<string, unknown> | null | undefined): Record<string, unknown> {
  const own = nodeElements(view.definition, view.currentNode);
  const out: Record<string, unknown> = {};
  for (const [slug, v] of Object.entries(draft ?? {})) if (own.has(slug)) out[slug] = v;
  return out;
}

/**
 * The ONE live answer map: the answers the party can read, overlaid with the draft for the
 * current step's slugs, plugin answers expanded, constants computed at the run's reference date.
 */
export function liveAnswerMap(view: FlowPartyView, draft?: Record<string, unknown> | null): Record<string, unknown> {
  const merged = { ...view.stored, ...currentDraft(view, draft) };
  const expanded = expandPluginAnswers(merged, pluginSlugsOf(view.definition));
  return computeConstants(view.definition['constants'], expanded, view.referenceDate);
}

function constantsByKey(definition: Json): Map<string, Json> {
  const out = new Map<string, Json>();
  const list = definition['constants'];
  for (const c of Array.isArray(list) ? list : []) {
    if (isObj(c) && typeof c['key'] === 'string') out.set(c['key'] as string, c);
  }
  return out;
}

/**
 * The keys a current-step draft value is derived from: a field's `default` refs. A plugin answer
 * derives from nothing here — its outputs are never private, whatever inputs produced them.
 */
function draftSourceRefs(definition: Json, slug: string): string[] {
  const found = elementNode(definition, slug);
  if (found === null || found.element['kind'] !== 'field') return [];
  const dflt = found.element['default'];
  return dflt === undefined || dflt === null ? [] : flowExprRefs(dflt);
}

/**
 * Whether a flow key's value is private to someone else, fail-closed.
 *
 * A constant is private when any key it reads is. A key on the current step taken from the draft
 * is private only when its field's default reads a private source — whatever the draft value is;
 * a plugin answer is never private. Any other key is
 * private when its slug is in `private_slugs`; with no `private_slugs` list, a key another party
 * answered is private.
 */
function isPrivateSource(
  key: string,
  view: FlowPartyView,
  draft: Record<string, unknown>,
  seen: Set<string> = new Set(),
): boolean {
  if (seen.has(key)) return false;
  seen.add(key);
  const constant = constantsByKey(view.definition).get(key);
  if (constant !== undefined) {
    return flowExprRefs(constant['expr']).some((ref) => isPrivateSource(ref, view, draft, seen));
  }
  const base = key.split('.')[0];
  if (Object.prototype.hasOwnProperty.call(draft, base)) {
    return draftSourceRefs(view.definition, base).some((ref) => isPrivateSource(ref, view, draft, seen));
  }
  if (view.privateSlugs !== null) {
    return view.privateSlugs.includes(base) || view.privateSlugs.includes(key);
  }
  const found = elementNode(view.definition, base);
  const party = found !== null && found.node['party'] != null ? String(found.node['party']) : null;
  return party === null || !view.ownPartyKeys.has(party);
}

/**
 * Whether a value the party submits for `slug` is private: its field's default reads a private
 * source. A plugin answer never is. `draft` holds the submitted slugs.
 */
export function isDraftPrivate(view: FlowPartyView, slug: string, draft: Record<string, unknown>): boolean {
  const own = currentDraft(view, draft);
  if (!Object.prototype.hasOwnProperty.call(own, slug)) return false;
  return isPrivateSource(slug, view, own);
}

/** Convert a value to a plugin input's declared type, or undefined when it does not convert. */
function convertInput(type: unknown, value: unknown): unknown {
  switch (type) {
    case 'number':
      return flowNumber(value) ?? undefined;
    case 'date':
      return typeof value === 'string' && flowDateUtc(value) !== null ? value.trim() : undefined;
    case 'boolean':
      if (typeof value === 'boolean') return value;
      if (value === 'true') return true;
      if (value === 'false') return false;
      return undefined;
    case 'text':
      return flowString(value);
    default:
      return undefined;
  }
}

/**
 * The inputs of a plugin call, each converted to its declared type.
 *
 * A REQUIRED input that is unwired, unanswered, another party's private value or not convertible
 * raises {@link PluginInputUnavailable}; an OPTIONAL one is left out of the call.
 */
function resolveInputs(spec: Json, live: Record<string, unknown>, view: FlowPartyView, draft: Record<string, unknown>): Json {
  const snapshot = isObj(spec['snapshot']) ? (spec['snapshot'] as Json) : {};
  const wiring = isObj(spec['inputs']) ? (spec['inputs'] as Json) : {};
  const declared = Array.isArray(snapshot['inputs']) ? (snapshot['inputs'] as unknown[]).filter(isObj) : [];
  const out: Json = {};
  for (const def of declared as Json[]) {
    if (typeof def['key'] !== 'string') continue;
    const key = def['key'] as string;
    const required = def['required'] === true;
    const ref = wiring[key];
    const unavailable = (source: string | null, reason: ConstructorParameters<typeof PluginInputUnavailable>[2]): void => {
      if (required) throw new PluginInputUnavailable(key, source, reason);
    };
    if (typeof ref !== 'string' || ref === '') {
      unavailable(null, 'unwired');
      continue;
    }
    const raw = live[ref];
    if (raw === undefined || raw === null || raw === '') {
      unavailable(ref, 'unanswered');
      continue;
    }
    if (isPrivateSource(ref, view, draft)) {
      unavailable(ref, 'other_party_private');
      continue;
    }
    const converted = convertInput(def['type'], raw);
    if (converted === undefined) {
      unavailable(ref, 'not_convertible');
      continue;
    }
    out[key] = converted;
  }
  return out;
}

/** What one plugin call needs, resolved from the run and its pass. */
export interface PreparedPluginCall {
  pluginId: string;
  fieldType: string;
  inputs: Json;
}

/**
 * Resolve the plugin element `slug` of the current step: its spec (from the pass, else the pinned
 * definition) and its inputs read from the live answer map.
 */
export function preparePluginCall(
  view: FlowPartyView,
  pass: PluginPass,
  slug: string,
  draft?: Record<string, unknown> | null,
): PreparedPluginCall {
  const element = nodeElements(view.definition, view.currentNode).get(slug);
  if (element === undefined || element['kind'] !== 'plugin') {
    throw new ConfigError(`'${slug}' is not a plugin field on the run's current step`);
  }
  const spec = pass.specs[slug] ?? (isObj(element['plugin']) ? (element['plugin'] as Json) : null);
  if (spec === null || spec['plugin_id'] == null || spec['field_type'] == null) {
    throw new ConfigError(`plugin field '${slug}' carries no plugin spec`);
  }
  const own = currentDraft(view, draft);
  const inputs = resolveInputs(spec, liveAnswerMap(view, own), view, own);
  return { pluginId: String(spec['plugin_id']), fieldType: String(spec['field_type']), inputs };
}

// ── bounds ────────────────────────────────────────────────────────────────────

/**
 * Refuse a value outside its flow field's `min`/`max`, each computed over the live answer map.
 *
 * A bound that computes to null is no bound. Numbers compare as numbers and dates as dates; a
 * value that is neither is left to type validation.
 *
 * @throws ValidationError naming the bound (`bound`, `boundValue`).
 */
export function checkFlowBounds(
  definition: Json,
  slug: string,
  value: unknown,
  live: Record<string, unknown>,
  referenceDate: string | null,
): void {
  const found = elementNode(definition, slug);
  if (found === null || found.element['kind'] !== 'field') return;
  const element = found.element;
  const fieldType = element['field_type'] != null ? String(element['field_type']) : null;
  for (const which of ['min', 'max'] as const) {
    const expr = element[which];
    if (expr === undefined || expr === null) continue;
    const bound = evaluateFlowExpression(expr, live, referenceDate);
    if (bound === null || bound === undefined || typeof bound === 'boolean') continue;
    let outside: boolean | null = null;
    const bn = flowNumber(bound);
    if (bn !== null) {
      const vn = flowNumber(value);
      if (vn !== null) outside = which === 'min' ? vn < bn : vn > bn;
    } else {
      const bd = flowDateUtc(bound);
      const vd = flowDateUtc(value);
      if (bd !== null && vd !== null) outside = which === 'min' ? vd < bd : vd > bd;
    }
    if (outside === true) throw new ValidationError(slug, fieldType, { bound: which, value: bound });
  }
}

// ── the forwarder call ────────────────────────────────────────────────────────

interface ForwarderResponse {
  status: number;
  body: Json;
}

/**
 * POST to the forwarder with a plain `fetch`: no bearer token, no App Check, no cookie, and the
 * URL exactly as the pass named it.
 */
async function postForwarder(forwarderUrl: string, payload: Json): Promise<ForwarderResponse> {
  let resp: Response;
  try {
    resp = await fetch(`${forwarderUrl}/call`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload),
      redirect: 'error',
      credentials: 'omit',
    });
  } catch (exc) {
    throw new ApiError(0, null, `request to the plugin forwarder failed: ${(exc as Error).message}`);
  }
  const text = await resp.text();
  let body: unknown = null;
  try {
    body = text === '' ? null : JSON.parse(text);
  } catch {
    body = null;
  }
  return { status: resp.status, body: isObj(body) ? body : {} };
}

/**
 * One plugin call: seal, post, open.
 *
 * A `409 plugin.key_changed` reseals once with the key it returns; a 401 or 403 fetches a new pass
 * once. Every other refusal surfaces as an {@link ApiError} carrying the forwarder's status and
 * key (`plugin.not_responding`, `plugin.busy`, `plugin.rate_limited`, `plugin.unavailable`, …).
 */
export async function callPlugin(
  firstPass: PluginPass,
  renewPass: () => Promise<PluginPass>,
  call: PreparedPluginCall,
  request: Json,
): Promise<Json> {
  const reply: { privateKey: KeyObject; publicKeySpki: string } = generateReplyKeyPair();
  const plaintext = JSON.stringify({ ...request, field_type: call.fieldType, inputs: call.inputs, reply_key: reply.publicKeySpki });
  let pass = firstPass;
  let publicKey = pass.publicKeyOf(call.pluginId);
  let resealed = false;
  let renewed = false;
  for (;;) {
    if (publicKey === null) {
      throw new ApiError(0, 'plugin.not_responding', `plugin ${call.pluginId} publishes no usable key`);
    }
    const sealed = JSON.stringify(encryptForPublicKey(plaintext, loadPublicKey(publicKey)));
    const resp = await postForwarder(pass.forwarderUrl, { pass: pass.pass, plugin_id: call.pluginId, request: sealed });
    const errorKey = typeof resp.body['error_key'] === 'string' ? (resp.body['error_key'] as string) : null;
    if (resp.status === 200) {
      const wrapper = resp.body['reply'];
      if (typeof wrapper !== 'string' && !isObj(wrapper)) {
        throw new DecryptError('plugin reply carries no sealed reply');
      }
      let opened: unknown;
      try {
        opened = JSON.parse(decrypt(wrapper as string, reply.privateKey));
      } catch (exc) {
        if (exc instanceof DecryptError) throw exc;
        throw new DecryptError('plugin reply plaintext is not valid JSON');
      }
      if (!isObj(opened)) throw new DecryptError('plugin reply plaintext must be a JSON object');
      return opened;
    }
    if (resp.status === 409 && errorKey === 'plugin.key_changed' && !resealed && typeof resp.body['public_key'] === 'string') {
      publicKey = resp.body['public_key'] as string;
      resealed = true;
      continue;
    }
    if ((resp.status === 401 || resp.status === 403) && !renewed) {
      pass = await renewPass();
      publicKey = pass.publicKeyOf(call.pluginId);
      renewed = true;
      continue;
    }
    const { error, error_key: _key, ...details } = resp.body;
    void _key;
    throw new ApiError(resp.status, errorKey, error != null ? String(error) : null, details);
  }
}

/** Turn an `outputs` reply into its result. */
export function outputsResult(reply: Json): PluginOutputs | PluginPicksInvalid {
  if (reply['picks_invalid'] === true) return new PluginPicksInvalid(reply);
  return new PluginOutputs(isObj(reply['outputs']) ? { ...(reply['outputs'] as Json) } : {}, reply);
}
