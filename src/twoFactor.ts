/**
 * 2FA-by-allme — the relying-party challenge API (spec §3), on the SERVICE's data-client
 * credentials (the same auth the {@link Client} uses). A service asks a person — addressed by their
 * `share_code` — to approve a login inside the allme app; it then polls for the outcome.
 *
 * The poll ({@link TwoFactorClient.result}) is the record of the outcome: the first read of a terminal
 * state delivers it and burns it (a later read is `gone`). A webhook (`2fa_challenge_completed`) is the
 * push equivalent — best-effort; the poll remains authoritative.
 */
import { ApiError } from './errors.js';
import type { HttpClient, Sleep } from './http.js';

const defaultSleep: Sleep = (seconds) => new Promise((res) => setTimeout(res, Math.max(0, seconds) * 1000));

export interface TwoFactorChallenge {
  /** Opaque challenge id — pass to {@link TwoFactorClient.result}. */
  challengeId: string;
  /** Always `pending` on creation. */
  status: string;
  /** ISO-8601 expiry (5-minute TTL). */
  expiresAt: string;
  /**
   * Present only when the service has number matching enabled — the two digits to DISPLAY on your
   * login page. The person types them back into the allme app; the SERVER adjudicates them.
   */
  matchingDigits: string | null;
}

export interface TwoFactorResult {
  /** `pending` | `approved` | `denied` | `expired` | `revoked` | `gone` (already consumed / TTL passed). */
  status: string;
  /** Set while `pending`. */
  expiresAt: string | null;
  /** Set on a terminal outcome. */
  completedAt: string | null;
}

export interface ChallengeOptions {
  /** Plain text shown to the person (≤200 chars). */
  context?: string | null;
  /** Required (≤64 chars). A repeat with the same key within the TTL returns the SAME challenge and sends no second push. */
  idempotencyKey: string;
}

export interface WaitForResultOptions {
  /** Seconds to keep polling before giving up (default 600). */
  timeout?: number;
  /** Seconds between polls (default 2). */
  interval?: number;
}

export class TwoFactorClient {
  private readonly sleep: Sleep;

  // `sleep` is injectable so waitForResult is unit-testable without real delays (matches OAuthClient).
  constructor(
    private readonly http: HttpClient,
    opts: { sleep?: Sleep } = {},
  ) {
    this.sleep = opts.sleep ?? defaultSleep;
  }

  /** Initiate a login-approval challenge for the person behind `shareCode`. */
  async challenge(shareCode: string, opts: ChallengeOptions): Promise<TwoFactorChallenge> {
    const body = (await this.http.post('/api/service-2fa/challenges', {
      json: {
        share_code: shareCode,
        context: opts.context ?? null,
        idempotency_key: opts.idempotencyKey,
      },
    })) as Record<string, unknown>;
    return {
      challengeId: String(body.challenge_id ?? ''),
      status: String(body.status ?? ''),
      expiresAt: String(body.expires_at ?? ''),
      matchingDigits: body.matching_digits != null ? String(body.matching_digits) : null,
    };
  }

  /** Poll a challenge. While pending, `status` is `pending`; the first terminal read burns the result. */
  async result(challengeId: string): Promise<TwoFactorResult> {
    const body = (await this.http.get(
      `/api/service-2fa/challenges/${encodeURIComponent(challengeId)}`,
    )) as Record<string, unknown>;
    return {
      status: String(body.status ?? ''),
      expiresAt: body.expires_at != null ? String(body.expires_at) : null,
      completedAt: body.completed_at != null ? String(body.completed_at) : null,
    };
  }

  /**
   * Poll {@link result} until the status is terminal (no longer `pending`) and return that first
   * terminal {@link TwoFactorResult}.
   *
   * Convenience over a manual {@link result} loop (mirrors the OAuth `pollResult` precedent).
   * Because the first terminal read burns the challenge, this returns as soon as the status leaves
   * `pending` — it never re-reads a consumed result. Rejects with {@link ApiError} if `timeout`
   * seconds elapse while still pending; `interval` is the seconds between polls.
   */
  async waitForResult(challengeId: string, opts: WaitForResultOptions = {}): Promise<TwoFactorResult> {
    const timeout = opts.timeout ?? 600;
    const interval = opts.interval ?? 2;
    const deadline = Date.now() + timeout * 1000;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const res = await this.result(challengeId);
      if (res.status !== 'pending') return res;
      if (Date.now() >= deadline) {
        throw new ApiError(0, null, `2FA challenge ${challengeId} not completed within ${timeout}s`);
      }
      await this.sleep(interval);
    }
  }
}
