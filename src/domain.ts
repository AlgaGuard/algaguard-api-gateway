import { createRemoteJWKSet, jwtVerify } from "jose";

export class TokenBucket {
  private readonly counters = new Map<
    string,
    { count: number; resetAt: number }
  >();
  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}
  take(key: string, now = Date.now()): boolean {
    const current = this.counters.get(key);
    if (!current || current.resetAt <= now) {
      this.counters.set(key, { count: 1, resetAt: now + this.windowMs });
      return true;
    }
    if (current.count >= this.limit) return false;
    current.count += 1;
    return true;
  }
}

export async function validateKeycloakToken(
  token: string,
  issuer: string,
  audience: string,
  jwksUrl = `${issuer}/protocol/openid-connect/certs`,
) {
  const jwks = createRemoteJWKSet(new URL(jwksUrl));
  return jwtVerify(token, jwks, { issuer, audience });
}

export const routes = Object.freeze({
  access: "http://access-service:3000",
  device: "http://device-service:3000",
  profile: "http://profile-service:3000",
  telemetry: "http://telemetry-service:3000",
  command: "http://command-service:3000",
  ota: "http://ota-service:3000",
  realtime: "http://realtime-service:3000",
});
