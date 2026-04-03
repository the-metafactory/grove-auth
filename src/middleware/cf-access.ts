/**
 * GA-1: CF Access JWT validation helpers.
 * Extracted for reuse by requireRole() — the JWT validation logic itself.
 */

import type { AuthBindings } from "../types";

/** CF Access JWKs include `kid` which standard JsonWebKey does not. */
type CfAccessJwk = JsonWebKey & { kid?: string };

const CF_ACCESS_TEAM = "metafactory";
const CF_CERTS_URL = `https://${CF_ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`;

// Cache the JWK keyset in module scope (warm across requests within same isolate)
let cachedKeys: { keys: CfAccessJwk[]; fetchedAt: number } | null = null;
const KEY_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

async function getCfAccessKeys(): Promise<CfAccessJwk[]> {
  if (cachedKeys && Date.now() - cachedKeys.fetchedAt < KEY_CACHE_TTL_MS) {
    return cachedKeys.keys;
  }
  const res = await fetch(CF_CERTS_URL);
  if (!res.ok) throw new Error(`Failed to fetch CF Access certs: ${res.status}`);
  const data = await res.json() as { keys: CfAccessJwk[] };
  cachedKeys = { keys: data.keys, fetchedAt: Date.now() };
  return data.keys;
}

async function importKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Validate a CF Access JWT.
 * Returns the decoded payload on success, or null on failure.
 */
export async function validateCfAccessJwt(
  token: string,
  audience: string,
): Promise<Record<string, unknown> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  let header: { kid?: string; alg?: string };
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64)));
  } catch (_err: unknown) {
    return null;
  }
  if (header.alg !== "RS256") return null;

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)));
  } catch (_err: unknown) {
    return null;
  }

  const aud = payload.aud;
  if (Array.isArray(aud) ? !aud.includes(audience) : aud !== audience) return null;

  // Reject tokens without expiry — CF Access tokens should always include exp
  const exp = payload.exp as number | undefined;
  if (!exp || exp < Math.floor(Date.now() / 1000)) return null;

  const keys = await getCfAccessKeys();
  const matchingKeys = header.kid
    ? keys.filter((k) => k.kid === header.kid)
    : keys;

  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64urlDecode(signatureB64);

  for (const jwk of matchingKeys) {
    try {
      const cryptoKey = await importKey(jwk);
      const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, signedData);
      if (valid) return payload;
    } catch (_err: unknown) {
      continue; // Try next key
    }
  }

  return null;
}

/**
 * Extract CF Access email from JWT cookie.
 * Returns null if no audience configured (local dev), no cookie, or invalid JWT.
 */
export async function getCfAccessEmail(
  env: AuthBindings,
  req: { header(name: string): string | undefined },
): Promise<string | null> {
  const audience = env.CF_ACCESS_AUD;
  if (!audience) return null;

  const cookie = req.header("Cookie") ?? "";
  const match = cookie.match(/CF_Authorization=([^;]+)/);
  const token = match?.[1];
  if (!token) return null;

  const payload = await validateCfAccessJwt(token, audience);
  return payload ? (payload.email as string) ?? null : null;
}
