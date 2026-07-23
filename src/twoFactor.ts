/**
 * #436 2FA-by-allme — the relying-party challenge API (spec §3), on the SERVICE's data-client
 * credentials (the same auth the {@link Client} uses). A service asks a person — addressed by their
 * `share_code` — to approve a login inside the allme app; it then polls for the outcome.
 *
 * The poll ({@link TwoFactorClient.result}) is the record of the outcome: the first read of a terminal
 * state delivers it and burns it (a later read is `gone`). A webhook (`2fa_challenge_completed`) is the
 * push equivalent — best-effort; the poll remains authoritative.
 */
import type { HttpClient } from './http.js';

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

export class TwoFactorClient {
  constructor(private readonly http: HttpClient) {}

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
}
