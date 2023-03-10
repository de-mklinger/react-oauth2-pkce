import { type AuthError } from "./auth-error";
import { type AuthTokens } from "./auth-tokens";
import { type PkceCodePair } from "./pkce";

export type AuthServiceStage = "initial" | "logging-in" | "logged-in" | "error" | "refreshing"

export type AuthServiceState<StageT extends AuthServiceStage> = {
  stage: StageT
}

export type AuthServiceStateInitial = AuthServiceState<"initial">;

export type AuthServiceStateLoggingIn = {
  pkceCodePair: PkceCodePair,
  preLoginUrl?: string,
  // OAuth state = "state" param?
} & AuthServiceState<"logging-in">

export type AuthServiceStateLoggedIn = {
  authTokens: AuthTokens
  // OAuth state = "state" param?
} & AuthServiceState<"logged-in">

export type AuthServiceStateError = {
  error: AuthError
  // OAuth state = "state" param?
} & AuthServiceState<"error">
