import { type AuthServiceStorage } from "./auth-service-storage";
import { AuthServiceStage, AuthServiceState } from "./auth-service-state";

export type DebugFn = (...args: unknown[]) => void;

export class AuthServiceLocalStorage implements AuthServiceStorage {
  private readonly prefix: string;
  private readonly debug: DebugFn;

  constructor(prefix?: string, debug?: DebugFn) {
    this.prefix = prefix ?? "";
    this.debug =
      debug ??
      (() => {
        // Do nothing
      });
  }

  removeAuth(): void {
    this.removeItem("auth");
  }

  getAuth(): string | undefined {
    return this.getItem("auth") ?? undefined;
  }

  setAuth(auth: string): void {
    this.setItem("auth", auth);
  }

  removePkce(): void {
    this.removeItem("pkce");
  }

  getPkce(): string | undefined {
    return this.getItem("pkce") ?? undefined;
  }

  setPkce(pkce: string): void {
    this.setItem("pkce", pkce);
  }

  removePreAuthUri(): void {
    this.removeItem("preAuthUri");
  }

  getPreAuthUri(): string | undefined {
    return this.getItem("preAuthUri") ?? undefined;
  }

  setPreAuthUri(preAuthUri: string): void {
    this.setItem("preAuthUri", preAuthUri);
  }

  protected getItem(key: string): string | undefined {
    const fullKey = this.getFullItemKey(key);
    return window.localStorage.getItem(fullKey) ?? undefined;
  }

  protected removeItem(key: string): void {
    const fullKey = this.getFullItemKey(key);
    this.debug("Remove storage item:", key);
    window.localStorage.removeItem(fullKey);
  }

  protected setItem(key: string, value: string): void {
    const fullKey = this.getFullItemKey(key);
    this.debug("Set storage item:", fullKey);
    window.localStorage.setItem(fullKey, value);
  }

  protected getFullItemKey(key: string): string {
    return this.prefix + key;
  }

  // getState<StateT = AuthServiceStage extends AuthServiceStage>(): AuthServiceState<StateT> {
  //   return undefined;
  // }

  setState<StateT = AuthServiceStage extends AuthServiceStage>(newState: StateT): AuthServiceState<StateT> {
    this.setItem("auth-state", JSON.stringify(newState));
  }
}
