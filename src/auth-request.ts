export const supportedGrantTypes = [
  "authorization_code",
  "refresh_token"
] as const;

export type SupportedGrantType = typeof supportedGrantTypes[number];

export type TokenRequestBody = {
  client_id: string;
  redirect_uri: string | undefined;
  client_secret: string | undefined;
  grant_type: SupportedGrantType;
};

export type AuthorizationCodeRequestBody = {
  grant_type: "authorization_code";
  code: string;
  code_verifier: string;
} & TokenRequestBody;

export type RefreshTokenRequestBody = {
  grant_type: "refresh_token";
  refresh_token: string;
} & TokenRequestBody;
