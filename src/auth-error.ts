
export const errorCodes = [
  /**
   * The request is missing a parameter, contains an invalid parameter,
   * includes a parameter more than once, or is otherwise invalid.
   */
  "invalid_request",
  /**
   * The user or authorization server denied the request.
   */
  "access_denied",
  /**
   * The client is not allowed to request an authorization code using
   * this method, for example if a confidential client attempts to use
   * the implicit grant type.
   */
  "unauthorized_client",
  /**
   * The server does not support obtaining an authorization code using
   * this method, for example if the authorization server never
   * implemented the implicit grant type.
   */
  "unsupported_response_type",
  /**
   * The requested scope is invalid or unknown.
   */
  "invalid_scope",
  /**
   * Instead of displaying a 500 Internal Server Error page to the
   * user, the server can redirect with this error code.
   */
  "server_error",
  /**
   * If the server is undergoing maintenance, or is otherwise
   * unavailable, this error code can be returned instead of
   * responding with a 503 Service Unavailable status code.
   */
  "temporarily_unavailable"
] as const;

export type ErrorCode = typeof errorCodes[number];

export function isErrorCode(x: unknown): x is ErrorCode {
  return typeof x === "string" && errorCodes.includes(x as ErrorCode);
}

export type ErrorDescription = string;

/**
 * The valid characters for this parameter are the ASCII character
 * set except for the double quote and backslash, specifically,
 * hex codes 20-21, 23-5B and 5D-7E.
 */
function isLegalErrorDescriptionCharCode(charCode: number): boolean {
  return (charCode >= 0x20 && charCode <= 0x21)
    || (charCode >= 0x23 && charCode <= 0x5B)
    || (charCode >= 0x5D && charCode <= 0x7E)
}

export function isErrorDescription(x: unknown): x is ErrorDescription {
  if (typeof x !== "string" || x.length === 0 || x.length > 1024) {
    return false;
  }

  for (let idx = 0; idx < x.length; idx++) {
    if (!isLegalErrorDescriptionCharCode(x.charCodeAt(idx))) {
      return false;
    }
  }

  return true;
}

export type AuthError = {
  error: ErrorCode,
  errorDescription?: ErrorDescription
}
