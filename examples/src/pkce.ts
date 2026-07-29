import { createHash, randomBytes } from 'node:crypto';

/**
 * PKCE (RFC 7636) verifier + S256 challenge. Pure local crypto — no network, no platform HTTP.
 * The SDK takes the code_challenge into {@link OAuthClient.authorizeUrl} and the code_verifier into
 * {@link OAuthClient.completeSignIn}; the demo generates the pair. (Scenario 5 uses openid-client's
 * own PKCE helpers instead — see server.ts.)
 */
export interface Pkce {
  verifier: string;
  challenge: string;
}

export function generatePkce(): Pkce {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

function b64url(bytes: Buffer): string {
  return bytes.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
