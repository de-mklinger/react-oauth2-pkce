import jwtDecode from "jwt-decode";

export type AuthTokens = {
  id_token: string;
  access_token?: string;
  refresh_token?: string;
  expires_in: number; // Seconds
  expires_at?: number; // Calculated on login, in millis
  token_type?: string;
  scope?: string;
};

export function isAuthTokens(o: unknown): o is AuthTokens {
  if (!o || typeof o !== "object" || Array.isArray(o)) {
    return false;
  }

  const oo = o as Record<keyof AuthTokens, unknown>;

  return (
    typeof oo.id_token === "string" &&
    (oo.access_token === undefined || typeof oo.access_token === "string") &&
    (oo.refresh_token === undefined || typeof oo.refresh_token === "string") &&
    typeof oo.expires_in === "number" &&
    (oo.expires_at === undefined || typeof oo.expires_at === "number") &&
    (oo.token_type === undefined || typeof oo.token_type === "string") &&
    (oo.scope === undefined || typeof oo.scope === "string")
  );
}

type MinimalIdTokenPayload = Record<string, unknown>;

export type DefaultIdTokenPayload = {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
} & MinimalIdTokenPayload;

function isMinimalIdTokenPayload(x: unknown): x is MinimalIdTokenPayload {
  return Boolean(x) && typeof x === "object" && !Array.isArray(x);
}

export type IdTokenPayloadTypeGuard<IdTokenPayloadT extends MinimalIdTokenPayload> = (idToken: unknown) => idToken is IdTokenPayloadT;

export class IdToken<IdTokenPayloadT extends MinimalIdTokenPayload = DefaultIdTokenPayload> {
  private readonly isIdTokenPayload: IdTokenPayloadTypeGuard<MinimalIdTokenPayload>;
  private payload: IdTokenPayloadT | undefined;

  constructor(readonly token: string, payloadTypeGuard?: IdTokenPayloadTypeGuard<IdTokenPayloadT>) {
    this.isIdTokenPayload = payloadTypeGuard ?? isMinimalIdTokenPayload;
    this.payload = undefined;
  }

  getToken(): string {
    return this.token;
  }

  getPayload(): IdTokenPayloadT {
    if (!this.payload) {
      const payload = jwtDecode(this.token);

      if (!this.isIdTokenPayload(payload)) {
        throw new Error("Invalid token payload");
      }

      this.payload = payload as IdTokenPayloadT;
    }

    return this.payload;
  }
}
