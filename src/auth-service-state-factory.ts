import { type PkceCodePair } from "./pkce";
import { type AuthTokens } from "./auth-tokens";
import { type AuthError } from "./auth-error";
import {
  type AuthServiceStateError,
  type AuthServiceStateInitial,
  type AuthServiceStateLoggedIn,
  type AuthServiceStateLoggingIn,
} from "./auth-service-state";

function initial(): AuthServiceStateInitial {
  return {
    stage: "initial",
  };
}

function loggingIn(
  pkceCodePair: PkceCodePair,
  preLoginUrl?: string
): AuthServiceStateLoggingIn {
  return {
    stage: "logging-in",
    pkceCodePair,
    preLoginUrl,
  };
}

function loggedIn(authTokens: AuthTokens): AuthServiceStateLoggedIn {
  return {
    stage: "logged-in",
    authTokens,
  };
}

function error(error: AuthError): AuthServiceStateError {
  return {
    stage: "error",
    error,
  };
}

export const authServiceStateFactory = {
  initial,
  loggingIn,
  loggedIn,
  error,
};
