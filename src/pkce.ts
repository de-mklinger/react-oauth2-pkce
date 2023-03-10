import { encode } from "base64-arraybuffer";

export type PkceCodePair = {
  codeVerifier: string;
  codeChallenge: string;
  createdAt: string;
};

export function isPkceCodePair(o: unknown): o is PkceCodePair {
  if (!o || typeof o !== "object" || Array.isArray(o)) {
    return false;
  }

  const oo = o as Record<keyof PkceCodePair, unknown>;

  return (
    typeof oo.codeVerifier === "string" &&
    typeof oo.codeChallenge === "string" &&
    typeof oo.createdAt === "string"
  );
}

const randomBytes = (length: number): Uint8Array => {
  const byteArray = new Uint8Array(length);
  window.crypto.getRandomValues(byteArray);
  return byteArray;
};

const base64UrlEncode = (data: Uint8Array): string =>
  encode(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

const sha256 = async (data: Uint8Array | string): Promise<Uint8Array> => {
  if (typeof data === "string") {
    const textEncoder = new TextEncoder();
    data = textEncoder.encode(data);
  }

  return window.crypto.subtle
    .digest("SHA-256", data)
    .then((arrayBuffer) => new Uint8Array(arrayBuffer));
};

export const createPkceCodes = async (): Promise<PkceCodePair> => {
  const codeVerifier = base64UrlEncode(randomBytes(64));
  const codeChallenge = base64UrlEncode(await sha256(codeVerifier));
  const createdAt = new Date().toISOString();

  return {
    codeVerifier,
    codeChallenge,
    createdAt,
  };
};
