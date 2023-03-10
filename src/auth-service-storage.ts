import { type AuthServiceStage, type AuthServiceState } from "./auth-service-state";

export type AuthServiceStorage = {
  getState<StateT extends AuthServiceStage = AuthServiceStage>(): AuthServiceState<StateT>;

  setState<StateT extends AuthServiceStage = AuthServiceStage>(newState: StateT): AuthServiceState<StateT>;

  removeAuth(): void;

  getAuth(): string | undefined;

  setAuth(auth: string): void;

  removePkce(): void;

  getPkce(): string | undefined;

  setPkce(pkce: string): void;

  removePreAuthUri(): void;

  getPreAuthUri(): string | undefined;

  setPreAuthUri(preAuthUri: string): void;
};
