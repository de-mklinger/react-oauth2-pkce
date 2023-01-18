import jwtDecode from "jwt-decode";
import { createPkceCodes, isPkceCodePair, type PKCECodePair } from "./pkce";
import { toUrlEncoded } from "./util";

/* eslint-disable @typescript-eslint/ban-types */
/* eslint-disable @typescript-eslint/naming-convention */

export type AuthServiceProps = {
  clientId: string;
  clientSecret?: string;
  provider: string;
  authorizeEndpoint?: string;
  tokenEndpoint?: string;
  logoutEndpoint?: string;
  audience?: string;
  redirectUri?: string;
  scopes: string[];
  prompts?: string[];
  autoRefresh?: boolean;
  refreshBeforeExpirationSeconds?: number;
  storage?: AuthStorage;
  debug?: boolean;
};

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

export type TokenRequestBody = {
  client_id: string;
  redirect_uri: string | undefined;
  client_secret: string | undefined;
  grant_type: string;
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

export type IdTokenPayload = {
  [propName: string]: unknown;
  iss?: string;
  sub?: string;
  aud?: string | string[];
  jti?: string;
  nbf?: number;
  exp?: number;
  iat?: number;
};

export type DebugFn = (...args: unknown[]) => void;

export type AuthStorage = {
  removeAuth(): void;

  getAuth(): string | null;

  setAuth(auth: string): void;

  removePkce(): void;

  getPkce(): string | null;

  setPkce(pkce: string): void;

  removePreAuthUri(): void;

  getPreAuthUri(): string | null;

  setPreAuthUri(preAuthUri: string): void;
};

export class AuthLocalStorage implements AuthStorage {
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

  getAuth(): string | null {
    return this.getItem("auth");
  }

  setAuth(auth: string): void {
    this.setItem("auth", auth);
  }

  removePkce(): void {
    this.removeItem("pkce");
  }

  getPkce(): string | null {
    return this.getItem("pkce");
  }

  setPkce(pkce: string): void {
    this.setItem("pkce", pkce);
  }

  removePreAuthUri(): void {
    this.removeItem("preAuthUri");
  }

  getPreAuthUri(): string | null {
    return this.getItem("preAuthUri");
  }

  setPreAuthUri(preAuthUri: string): void {
    this.setItem("preAuthUri", preAuthUri);
  }

  protected getItem(key: string): string | null {
    const fullKey = this.getFullItemKey(key);
    return window.localStorage.getItem(fullKey);
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
}

export class AuthService<IdTokenPayloadType = IdTokenPayload> {
  private readonly storage: AuthStorage;
  private timeout?: number;

  constructor(private readonly props: AuthServiceProps) {
    this.storage = props.storage ?? this.newDefaultStorage();
    const code = this.getCodeFromLocation();
    if (code !== null) {
      this.debug("Found code in location:", code);
      this.handleInitialCode(code);
    } else if (props.autoRefresh) {
      // Maybe after page reload with valid token:
      this.startRefreshTimer();
    }
  }

  getIdTokenPayload(): IdTokenPayloadType {
    if (!this.isLoggedIn()) {
      throw new Error("Not logged-in");
    }

    const authTokens = this.getAuthTokens();

    return jwtDecode(authTokens.id_token);
  }

  getAuthTokens(): AuthTokens {
    const authTokens = this.getOptionalAuthTokens();

    if (authTokens) {
      return authTokens;
    }

    throw new Error("Auth tokens not found in local storage");
  }

  isPending(): boolean {
    return this.storage.getPkce() !== null && !this.isLoggedIn();
  }

  isLoggedIn(): boolean {
    const authTokens = this.getOptionalAuthTokens();

    if (!authTokens) {
      return false;
    }

    if (authTokens.expires_at && Date.now() >= authTokens.expires_at) {
      this.handleExpired();
      return false;
    }

    return true;
  }

  async logout(shouldEndSession = false): Promise<void> {
    this.storage.removePkce();
    this.storage.removeAuth();
    if (shouldEndSession) {
      this.debug("logout: location-replace");
      this.getLocation().replace(this.newLogoutUrl().toString());
    } else {
      this.debug("logout: location-reload");
      this.getLocation().reload();
    }
  }

  async login(): Promise<void> {
    return this.authorize();
  }

  protected handleInitialCode(code: string): void {
    this.fetchToken(code)
      .then(() => {
        this.restoreUri();
      })
      .catch((e) => {
        console.warn("Error fetching initial token:", e);
        this.storage.removePkce();
        this.storage.removeAuth();
        this.removeCodeFromLocation();
      });
  }

  protected getCodeFromLocation(): string | null {
    const location = this.getLocation();
    return new URL(location.href).searchParams.get("code");
  }

  protected removeCodeFromLocation(): void {
    const location = this.getLocation();
    const url = new URL(location.href);
    if (url.searchParams.has("code")) {
      url.searchParams.delete("code");
      this.debug("removeCodeFromLocation: location-replace");
      location.replace(url.toString());
    }
  }

  protected getPkce(): PKCECodePair {
    const pkce = this.storage.getPkce();

    if (pkce === null) {
      throw new Error("PKCE pair not found in storage");
    }

    const pkceCodePair: unknown = JSON.parse(pkce);

    if (!isPkceCodePair(pkceCodePair)) {
      throw new Error("Illegal PKCE pair in storage");
    }

    return pkceCodePair;
  }

  // This will do a full page reload to the OAuth2 provider's login page
  protected async authorize(): Promise<void> {
    const pkce = await this.createPKCECodes();
    this.storage.setPkce(JSON.stringify(pkce));
    this.storage.setPreAuthUri(this.getLocation().href);
    this.storage.removeAuth();

    const { codeChallenge } = pkce;

    this.debug("authorize: location-replace");
    this.getLocation().replace(this.newAuthorizeUrl(codeChallenge).toString());
  }

  protected async createPKCECodes(): Promise<PKCECodePair> {
    return createPkceCodes();
  }

  // This happens after a full page reload. Read the code from localstorage
  protected async fetchToken(
    code: string,
    isRefresh = false
  ): Promise<AuthTokens> {
    this.debug("Fetch token");

    let refreshToken: string | undefined;
    let payload: RefreshTokenRequestBody | AuthorizationCodeRequestBody;
    if (isRefresh) {
      refreshToken = code;
      payload = {
        grant_type: "refresh_token",
        client_id: this.props.clientId,
        client_secret: this.props.clientSecret,
        redirect_uri: this.props.redirectUri,
        refresh_token: refreshToken,
      };
    } else {
      const pkce: PKCECodePair = this.getPkce();
      const { codeVerifier } = pkce;
      payload = {
        grant_type: "authorization_code",
        client_id: this.props.clientId,
        client_secret: this.props.clientSecret,
        redirect_uri: this.props.redirectUri,
        code,
        code_verifier: codeVerifier,
      };
    }

    const response = await fetch(this.newTokenUrl().toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
      body: toUrlEncoded({ ...payload }),
    }).finally(() => {
      this.storage.removePkce();
    });

    if (!response.ok) {
      throw new Error(
        `Error response when trying to fetch token: ${response.status}`
      );
    }

    const newAuthTokens: unknown = await response.json();

    if (!isAuthTokens(newAuthTokens)) {
      throw new Error("Illegal auth tokens response");
    }

    if (isRefresh && !newAuthTokens.refresh_token && refreshToken) {
      newAuthTokens.refresh_token = refreshToken;
    }

    newAuthTokens.expires_at = Date.now() + newAuthTokens.expires_in * 1000;
    this.debugTokenExpiration(newAuthTokens);
    this.setAuthTokens(newAuthTokens);

    if (this.props.autoRefresh) {
      this.startRefreshTimer();
    }

    return this.getAuthTokens();
  }

  protected startRefreshTimer(): void {
    if (this.timeout) {
      clearTimeout(this.timeout);
    }

    const authTokens = this.getOptionalAuthTokens();
    if (!authTokens) {
      return;
    }

    const { refresh_token: refreshToken, expires_at: expiresAt } = authTokens;

    if (!refreshToken) {
      this.debug("No refresh token available, disabling auto-refresh");
      return;
    }

    if (!expiresAt) {
      this.debug("No token expiration date, disabling auto-refresh");
      return;
    }

    let timeoutMillis = expiresAt - Date.now();
    if (timeoutMillis <= 0) {
      // Refresh token may have a much longer TTL than id token
      // Try to refresh, even if token is already expired
      this.debug("Token is expired, still trying refresh");
    }

    this.debug("Starting refresh timer");
    timeoutMillis = this.applyRefreshBeforeExpirationTime(timeoutMillis);
    // Throttle timeout:
    timeoutMillis = Math.max(1000, timeoutMillis);
    this.debugTimer(timeoutMillis, expiresAt);

    this.timeout = window.setTimeout(() => {
      this.debug("Refresh timer execution");
      this.fetchToken(refreshToken, true).catch((e) => {
        console.warn("Error fetching token for refresh:", e);
        this.storage.removeAuth();
        this.removeCodeFromLocation();
      });
    }, timeoutMillis);
  }

  // For better testability:
  protected getLocation(): Location {
    return window.location;
  }

  private newDefaultStorage() {
    return new AuthLocalStorage(undefined, (...args) => {
      this.debug(...args);
    });
  }

  private setAuthTokens(auth: AuthTokens): void {
    this.storage.setAuth(JSON.stringify(auth));
  }

  private getOptionalAuthTokens(): AuthTokens | undefined {
    const auth = this.storage.getAuth();

    if (auth) {
      const authTokens: unknown = JSON.parse(auth);

      if (!isAuthTokens(authTokens)) {
        throw new Error("Illegal auth tokens in storage");
      }

      return authTokens;
    }

    return undefined;
  }

  private newLogoutUrl(): URL {
    const { clientId, provider, logoutEndpoint, redirectUri } = this.props;

    const logoutUrl = new URL(logoutEndpoint ?? `${provider}/logout`);
    logoutUrl.searchParams.set("client_id", clientId);
    if (redirectUri) {
      logoutUrl.searchParams.set("post_logout_redirect_uri", redirectUri);
    }

    return logoutUrl;
  }

  private newAuthorizeUrl(codeChallenge: string): URL {
    const authorizeUrl = new URL(
      this.props.authorizeEndpoint ?? `${this.props.provider}/authorize`
    );

    authorizeUrl.searchParams.set("client_id", this.props.clientId);
    authorizeUrl.searchParams.set("scope", this.props.scopes.join(" "));
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("code_challenge", codeChallenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    if (this.props.audience) {
      authorizeUrl.searchParams.set("audience", this.props.audience);
    }

    if (this.props.prompts) {
      authorizeUrl.searchParams.set("prompt", this.props.prompts.join(" "));
    }

    if (this.props.redirectUri) {
      authorizeUrl.searchParams.set("redirect_uri", this.props.redirectUri);
    }

    return authorizeUrl;
  }

  private newTokenUrl(): URL {
    const { provider, tokenEndpoint } = this.props;
    return new URL(`${tokenEndpoint ?? `${provider}/token`}`);
  }

  private applyRefreshBeforeExpirationTime(timeoutMillis: number): number {
    const { refreshBeforeExpirationSeconds } = this.props;

    if (
      refreshBeforeExpirationSeconds &&
      timeoutMillis > refreshBeforeExpirationSeconds
    ) {
      return timeoutMillis - refreshBeforeExpirationSeconds * 1000;
    }

    return timeoutMillis;
  }

  private debugTokenExpiration(newAuthTokens: AuthTokens) {
    if (this.props.debug) {
      if (newAuthTokens.expires_at) {
        this.debug(
          "Token expires at:",
          this.formatDebugDate(new Date(newAuthTokens.expires_at))
        );
      } else {
        this.debug(
          "Token never expires (or no expiration information provided)"
        );
      }
    }
  }

  private debugTimer(timeoutMillis: number, expiresAt: number): void {
    if (this.props.debug) {
      const refreshDate = this.formatDebugDate(
        new Date(Date.now() + timeoutMillis)
      );
      const expirationDate = this.formatDebugDate(new Date(expiresAt));
      this.debug(
        `Setting timer to refresh at ${refreshDate}, expiration at ${expirationDate}`
      );
    }
  }

  private formatDebugDate(date: Date): string {
    if (Intl?.DateTimeFormat) {
      return new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(date);
    }

    return date.toString();
  }

  private handleExpired(): void {
    this.storage.removeAuth();
    this.removeCodeFromLocation();
  }

  private restoreUri(): void {
    const uri = this.storage.getPreAuthUri();
    this.storage.removePreAuthUri();

    if (uri !== null) {
      const location = this.getLocation();
      this.debug("restoreUri: location-replace");
      location.replace(uri);
    }

    this.removeCodeFromLocation();
  }

  private debug(...args: unknown[]): void {
    if (this.props.debug) {
      console.log(...args);
    }
  }
}
