import type { HttpResponse, HttpTransport, RequestBody } from '@allus-fyi/company-data';

/**
 * A short-timeout {@link HttpTransport} for the webhook feed-fallback client.
 *
 * `GET /api/runs` does ONE `Client.drainBatch()` raw feed fetch per poll on the active webhook run. A
 * single-worker server must not be pinned by one blackholed feed fetch, so the fallback client gets this
 * transport, which aborts each request via `AbortSignal.timeout`. It mirrors the SDK's default
 * `FetchTransport` otherwise (an injected transport is the SDK's intended seam).
 */
export class TimeoutTransport implements HttpTransport {
  constructor(private readonly timeoutMs: number) {}

  async post(url: string, form: Record<string, string>, headers: Record<string, string>): Promise<HttpResponse> {
    return fetch(url, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form).toString(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
  }

  async get(
    url: string,
    params: Record<string, string | number> | undefined,
    headers: Record<string, string>,
  ): Promise<HttpResponse> {
    return fetch(this.withParams(url, params), {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
  }

  async request(
    method: string,
    url: string,
    params: Record<string, string | number> | undefined,
    headers: Record<string, string>,
    body: RequestBody | undefined,
  ): Promise<HttpResponse> {
    const init: RequestInit = { method, headers: { ...headers }, signal: AbortSignal.timeout(this.timeoutMs) };
    const h = init.headers as Record<string, string>;
    if (body?.raw !== undefined) {
      h['Content-Type'] = body.contentType ?? 'application/octet-stream';
      init.body = typeof body.raw === 'string' ? body.raw : Buffer.from(body.raw);
    } else if (body?.json !== undefined) {
      h['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body.json);
    }
    return fetch(this.withParams(url, params), init);
  }

  private withParams(url: string, params: Record<string, string | number> | undefined): string {
    if (!params || Object.keys(params).length === 0) return url;
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) qs.set(k, String(v));
    return url + (url.includes('?') ? '&' : '?') + qs.toString();
  }
}
