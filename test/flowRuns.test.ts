/**
 * Company-side contract-flow run methods — fully mocked (no live API).
 * Mirrors the Python test_flow_runs.py: trigger/list/get, decrypt-only-company,
 * per-party fan-out + local routing, generate one-time-key shape, and the
 * processFlowRun company-leaf document chain.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDecipheriv, createPublicKey } from 'node:crypto';

import { Client, Config, FlowRun, HttpClient, decrypt, loadPrivateKey } from '../src/index.js';
import type { HttpResponse, HttpTransport, RequestBody } from '../src/index.js';
import { encryptForKey, loadVector } from './helpers.js';

const vector = loadVector();
const COMPANY_UID = 'company-1';
const PERSON_UID = 'person-1';

class FakeResponse implements HttpResponse {
  readonly status: number;
  private readonly bodyText: string;
  constructor(status: number, jsonBody?: unknown) {
    this.status = status;
    this.bodyText = jsonBody !== undefined ? JSON.stringify(jsonBody) : '';
  }
  async text(): Promise<string> {
    return this.bodyText;
  }
  get headers(): { get(name: string): string | null } {
    return { get: () => null };
  }
}

type Router = (url: string, params: Record<string, string | number> | undefined) => FakeResponse;
type WriteRouter = (method: string, url: string, body: RequestBody | undefined) => FakeResponse;

class RoutedTransport implements HttpTransport {
  constructor(
    private readonly router: Router,
    private readonly writeRouter?: WriteRouter,
  ) {}
  async post(url: string): Promise<HttpResponse> {
    return new FakeResponse(200, { access_token: 'tok-1', token_type: 'Bearer', expires_in: 3600 });
  }
  async get(url: string, params: Record<string, string | number> | undefined): Promise<HttpResponse> {
    return this.router(url, params);
  }
  async request(
    method: string,
    url: string,
    _params: Record<string, string | number> | undefined,
    _headers: Record<string, string>,
    body: RequestBody | undefined,
  ): Promise<HttpResponse> {
    if (this.writeRouter === undefined) return new FakeResponse(200, {});
    return this.writeRouter(method, url, body);
  }
}

function withTmp<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), 'allus-flow-'));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function makeConfig(dir: string): Config {
  const pem = join(dir, 'service-key.pem');
  writeFileSync(pem, vector.encrypted_private_key_pem, 'ascii');
  return new Config({
    apiUrl: 'https://api.allme.fyi',
    clientId: 'svc_abc',
    clientSecret: 'topsecret',
    servicePrivateKey: pem,
    keyPassphrase: vector.passphrase,
    cacheDir: join(dir, 'cache'),
  });
}

function makeClientRw(config: Config, router: Router, writeRouter: WriteRouter): Client {
  const http = new HttpClient(config, { transport: new RoutedTransport(router, writeRouter) });
  return new Client(config, { http });
}

const NO_GET: Router = (url) => {
  throw new Error('unexpected GET ' + url);
};

function vectorPubSpkiB64(): string {
  const priv = loadPrivateKey(vector.encrypted_private_key_pem, vector.passphrase);
  return createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64');
}

const DEF = {
  output_mode: 'data_only',
  parties: [{ key: 'company' }, { key: 'person' }],
  nodes: [
    { key: 'n1', party: 'company' },
    { key: 'n2', party: 'person' },
    { key: 'n_end', party: 'person' },
  ],
  edges: [
    { from: 'n1', to: 'n_end', sort: 0, condition: { field: 'tier', op: 'eq', value: 'vip' } },
    { from: 'n1', to: 'n2', sort: 1, condition: null },
  ],
};

function runObj(o: { status?: string; current?: string; answers?: unknown[]; definition?: unknown; outputMode?: string; documentId?: string | null } = {}): Record<string, unknown> {
  const def = { ...(o.definition ?? DEF) } as Record<string, unknown>;
  if (o.outputMode !== undefined) def['output_mode'] = o.outputMode;
  return {
    id: 'run-1',
    flow_id: 'flow-1',
    flow_version: 3,
    service_id: 'svc-1',
    connection_id: 'csc-1',
    company_user_id: COMPANY_UID,
    bindings: { company: COMPANY_UID, person: PERSON_UID },
    status: o.status ?? 'awaiting_company',
    current_node: o.current ?? 'n1',
    document_id: o.documentId ?? null,
    output_mode: def['output_mode'],
    definition: def,
    answers: o.answers ?? [],
    created_at: null,
    updated_at: null,
  };
}

// ── trigger / list / get ──────────────────────────────────────────────────────

test('triggerFlowRun posts target+bindings, parses FlowRun', async () => {
  await withTmp(async (dir) => {
    const captured: { url?: string; body?: unknown } = {};
    const writeRouter: WriteRouter = (method, url, body) => {
      captured.url = url;
      captured.body = body?.json;
      return new FakeResponse(201, runObj());
    };
    const client = makeClientRw(makeConfig(dir), NO_GET, writeRouter);
    const run = await client.triggerFlowRun('flow-1', {
      connectionId: 'csc-1',
      bindings: { company: COMPANY_UID, person: PERSON_UID },
    });
    assert.ok((captured.url as string).endsWith('/company-data/flows/flow-1/runs'));
    assert.deepEqual((captured.body as any).target, { connection_id: 'csc-1' });
    assert.ok(run instanceof FlowRun);
    assert.equal(run.companyPartyKey, 'company');
    assert.equal(run.serviceUserId, COMPANY_UID);
  });
});

test('flowRuns defaults to awaiting_company', async () => {
  await withTmp(async (dir) => {
    const router: Router = (url, params) => {
      assert.ok(url.endsWith('/company-data/flow-runs'));
      assert.deepEqual(params, { status: 'awaiting_company' });
      return new FakeResponse(200, { total: 1, items: [runObj()] });
    };
    const client = makeClientRw(makeConfig(dir), router, () => new FakeResponse(200, {}));
    const runs = await client.flowRuns();
    assert.equal(runs.length, 1);
    assert.equal(runs[0].status, 'awaiting_company');
  });
});

test('flowRun by id', async () => {
  await withTmp(async (dir) => {
    const router: Router = (url) => {
      assert.ok(url.endsWith('/company-data/flow-runs/run-1'));
      return new FakeResponse(200, runObj());
    };
    const client = makeClientRw(makeConfig(dir), router, () => new FakeResponse(200, {}));
    const run = await client.flowRun('run-1');
    assert.equal(run.currentNode, 'n1');
  });
});

// ── decrypt only the company's copies ─────────────────────────────────────────

test('decryptRunAnswers decrypts only the company copies', async () => {
  await withTmp(async (dir) => {
    const wrapper = encryptForKey(vector, 'ACME BV');
    const answers = [
      { slug: 'company_name', for_user_id: COMPANY_UID, value: wrapper },
      { slug: 'company_name', for_user_id: PERSON_UID, value: wrapper },
      { slug: 'other', for_user_id: 'stranger', value: wrapper },
    ];
    const client = makeClientRw(makeConfig(dir), NO_GET, () => new FakeResponse(200, {}));
    const run = FlowRun.fromApi(runObj({ answers }));
    const decoded = (client as any).decryptRunAnswers(run);
    assert.deepEqual(decoded, { company_name: 'ACME BV' });
  });
});

// ── submit: per-party fan-out + local routing ─────────────────────────────────

test('submitFlowAnswers fans out per party + routes fallthrough', async () => {
  await withTmp(async (dir) => {
    const spki = vectorPubSpkiB64();
    const router: Router = (url) => {
      if (url.endsWith('/company-data/connections/csc-1')) {
        return new FakeResponse(200, { connection_id: 'csc-1', share_code: 'ABC123' });
      }
      if (url.endsWith('/api/keys/ABC123')) return new FakeResponse(200, { public_key: spki });
      throw new Error('unexpected GET ' + url);
    };
    const captured: { url?: string; body?: any } = {};
    const writeRouter: WriteRouter = (method, url, body) => {
      captured.url = url;
      captured.body = body?.json;
      return new FakeResponse(200, runObj({ status: 'awaiting_person', current: 'n2' }));
    };
    const client = makeClientRw(makeConfig(dir), router, writeRouter);
    const run = FlowRun.fromApi(runObj());
    const out = await client.submitFlowAnswers(run, { company_name: 'ACME BV' });

    const body = captured.body;
    assert.ok((captured.url as string).endsWith('/company-data/flow-runs/run-1/answers'));
    assert.equal(body.answers.length, 1);
    const vals = body.answers[0].values as { for_user_id: string; value: any }[];
    assert.deepEqual(new Set(vals.map((v) => v.for_user_id)), new Set([COMPANY_UID, PERSON_UID]));
    for (const v of vals) assert.equal(v.value._enc, 1);
    // company copy round-trips with the service private key
    const priv = loadPrivateKey(vector.encrypted_private_key_pem, vector.passphrase);
    const companyCopy = vals.find((v) => v.for_user_id === COMPANY_UID)!;
    assert.equal(decrypt(companyCopy.value, priv), 'ACME BV');
    // local routing: no 'tier' → fallthrough to n2
    assert.equal(body.next_node, 'n2');
    assert.equal(body.next_party, 'person');
    assert.equal(body.leaf, undefined);
    assert.equal(out.status, 'awaiting_person');
  });
});

test('submitFlowAnswers routes guarded edge when condition true', async () => {
  await withTmp(async (dir) => {
    const spki = vectorPubSpkiB64();
    const router: Router = (url) => {
      if (url.endsWith('/company-data/connections/csc-1')) {
        return new FakeResponse(200, { connection_id: 'csc-1', share_code: 'ABC123' });
      }
      if (url.endsWith('/api/keys/ABC123')) return new FakeResponse(200, { public_key: spki });
      throw new Error('unexpected GET ' + url);
    };
    const captured: { body?: any } = {};
    const writeRouter: WriteRouter = (method, url, body) => {
      captured.body = body?.json;
      return new FakeResponse(200, runObj({ status: 'awaiting_person', current: 'n_end' }));
    };
    const client = makeClientRw(makeConfig(dir), router, writeRouter);
    const run = FlowRun.fromApi(runObj());
    await client.submitFlowAnswers(run, { tier: 'vip' });
    // guarded n1→n_end edge matches first; the current node n1 still has edges → not a leaf submit
    assert.equal(captured.body.next_node, 'n_end');
    assert.equal(captured.body.leaf, undefined);
  });
});

test('submitFlowAnswers uses supplied partyPubKeys without fetch', async () => {
  await withTmp(async (dir) => {
    const priv = loadPrivateKey(vector.encrypted_private_key_pem, vector.passphrase);
    const personPub = createPublicKey(priv);
    const router: Router = (url) => {
      throw new Error('no GET expected when partyPubKeys supplied: ' + url);
    };
    const captured: { body?: any } = {};
    const writeRouter: WriteRouter = (method, url, body) => {
      captured.body = body?.json;
      return new FakeResponse(200, runObj({ status: 'awaiting_person', current: 'n2' }));
    };
    const client = makeClientRw(makeConfig(dir), router, writeRouter);
    const run = FlowRun.fromApi(runObj());
    await client.submitFlowAnswers(run, { company_name: 'X' }, { partyPubKeys: { [PERSON_UID]: personPub } });
    const vals = captured.body.answers[0].values as { for_user_id: string }[];
    assert.deepEqual(new Set(vals.map((v) => v.for_user_id)), new Set([COMPANY_UID, PERSON_UID]));
  });
});

// ── generate (document leaf) ──────────────────────────────────────────────────

test('generateFlowDocument posts otk + iv||ct||tag blob', async () => {
  await withTmp(async (dir) => {
    const wrapper = encryptForKey(vector, 'ACME BV');
    const answers = [{ slug: 'company_name', for_user_id: COMPANY_UID, value: wrapper }];
    const captured: { url?: string; body?: any } = {};
    const writeRouter: WriteRouter = (method, url, body) => {
      captured.url = url;
      captured.body = body?.json;
      return new FakeResponse(200, { document_id: 'doc-9', status: 'awaiting_signature' });
    };
    const client = makeClientRw(makeConfig(dir), NO_GET, writeRouter);
    const run = FlowRun.fromApi(runObj({ status: 'generating', current: 'n1', answers, outputMode: 'document' }));
    const res = (await client.generateFlowDocument(run)) as any;
    assert.deepEqual(res, { document_id: 'doc-9', status: 'awaiting_signature' });
    assert.ok((captured.url as string).endsWith('/company-data/flow-runs/run-1/generate'));

    const otk = Buffer.from(captured.body.otk, 'base64');
    const blob = Buffer.from(captured.body.values, 'base64');
    assert.equal(otk.length, 32);
    assert.ok(blob.length >= 12 + 16);
    // reproduce the server's read: iv(12) || ct || tag(16)
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(blob.length - 16);
    const ct = blob.subarray(12, blob.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', otk, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
    assert.deepEqual(JSON.parse(plain), { company_name: 'ACME BV' });
  });
});

// ── processFlowRun: chains submit + generate on a company-leaf document flow ───

test('processFlowRun company-leaf document chains generate', async () => {
  await withTmp(async (dir) => {
    const spki = vectorPubSpkiB64();
    const single = {
      output_mode: 'document',
      parties: [{ key: 'company' }, { key: 'person' }],
      nodes: [{ key: 'n1', party: 'company' }],
      edges: [],
    };
    const state = { posts: [] as string[] };
    const router: Router = (url) => {
      if (url.endsWith('/company-data/flow-runs/run-1')) {
        const status = state.posts.length > 0 ? 'awaiting_signature' : 'awaiting_company';
        const docId = state.posts.length > 0 ? 'doc-9' : null;
        const r = runObj({ status, current: 'n1', definition: single, outputMode: 'document', documentId: docId });
        return new FakeResponse(200, r);
      }
      if (url.endsWith('/company-data/connections/csc-1')) {
        return new FakeResponse(200, { connection_id: 'csc-1', share_code: 'ABC123' });
      }
      if (url.endsWith('/api/keys/ABC123')) return new FakeResponse(200, { public_key: spki });
      throw new Error('unexpected GET ' + url);
    };
    const writeRouter: WriteRouter = (method, url) => {
      state.posts.push(url);
      if (url.endsWith('/answers')) {
        return new FakeResponse(200, runObj({ status: 'generating', current: 'n1', definition: single, outputMode: 'document' }));
      }
      assert.ok(url.endsWith('/generate'));
      return new FakeResponse(200, { document_id: 'doc-9', status: 'awaiting_signature' });
    };
    const client = makeClientRw(makeConfig(dir), router, writeRouter);
    const run = await client.processFlowRun('run-1', () => ({ company_name: 'ACME BV' }));
    assert.ok(state.posts.some((u) => u.endsWith('/answers')));
    assert.ok(state.posts.some((u) => u.endsWith('/generate')));
    assert.equal(run.status, 'awaiting_signature');
    assert.equal(run.documentId, 'doc-9');
  });
});

test('processFlowRun not our turn returns untouched, no fill', async () => {
  await withTmp(async (dir) => {
    const router: Router = () => new FakeResponse(200, runObj({ status: 'awaiting_person', current: 'n2' }));
    let calls = 0;
    const client = makeClientRw(makeConfig(dir), router, () => new FakeResponse(200, {}));
    const run = await client.processFlowRun('run-1', () => {
      calls += 1;
      return { x: 'y' };
    });
    assert.equal(run.status, 'awaiting_person');
    assert.equal(calls, 0);
  });
});
