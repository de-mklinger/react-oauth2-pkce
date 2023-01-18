import { encode } from "base64-arraybuffer";

export type PKCECodePair = {
  codeVerifier: string;
  codeChallenge: string;
  createdAt: Date;
};

const randomBytes = (length: number): Uint8Array => {
  const byteArray = new Uint8Array(length);
  window.crypto.getRandomValues(byteArray);
  return byteArray;
};

const base64URLEncode = (data: Uint8Array): string => {
  return encode(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
};

const sha256 = async (data: Uint8Array | string): Promise<Uint8Array> => {
  if (typeof data === "string") {
    const textEncoder = new TextEncoder();
    data = textEncoder.encode(data);
  }

  return window.crypto.subtle
    .digest("SHA-256", data)
    .then((arrayBuffer) => new Uint8Array(arrayBuffer));
};

export const createPKCECodes = async (): Promise<PKCECodePair> => {
  const codeVerifier = base64URLEncode(randomBytes(64));
  const codeChallenge = base64URLEncode(await sha256(codeVerifier));
  const createdAt = new Date();
  return {
    codeVerifier,
    codeChallenge,
    createdAt,
  };
};
