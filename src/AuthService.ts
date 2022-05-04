import { createPKCECodes, PKCECodePair } from './pkce';
import { toUrlEncoded } from './util';
import jwtDecode from 'jwt-decode';

export interface AuthServiceProps {
    clientId: string;
    clientSecret?: string;
    location: Location;
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
    localStoragePrefix?: string;
}

export interface AuthTokens {
    id_token: string;
    access_token: string; // TODO shouldn't this be optional?
    refresh_token: string; // TODO shouldn't this be optional?
    expires_in: number; // seconds
    expires_at?: number; // calculated on login, in millis
    token_type: string;
}

export interface TokenRequestBody {
    client_id: string;
    redirect_uri: string | undefined;
    client_secret: string | undefined;
    grant_type: string;
}

export interface AuthorizationCodeRequestBody extends TokenRequestBody {
    grant_type: 'authorization_code';
    code: string;
    code_verifier: string;
}

export interface RefreshTokenRequestBody extends TokenRequestBody {
    grant_type: 'refresh_token';
    refresh_token: string;
}

export interface IdTokenPayload {
    iss?: string;
    sub?: string;
    aud?: string | string[];
    jti?: string;
    nbf?: number;
    exp?: number;
    iat?: number;

    [propName: string]: unknown;
}

export class AuthService<IdTokenPayloadType = IdTokenPayload> {
    private readonly props: AuthServiceProps;
    private timeout?: number;

    constructor(props: AuthServiceProps) {
        this.props = props;
        const code = this.getCodeFromLocation();
        if (code !== null) {
            this.handleInitialCode(code);
        } else if (this.props.autoRefresh) {
            // maybe after page reload with valid token:
            this.startRefreshTimer();
        }
    }

    protected handleInitialCode(code: string): void {
        this.fetchToken(code)
            .then(() => {
                this.restoreUri();
            })
            .catch((e) => {
                this.removeItem('pkce');
                this.removeItem('auth');
                this.removeCodeFromLocation();
                console.warn('Error fetching token for refresh', e);
            });
    }

    protected getCodeFromLocation(): string | null {
        location = this.getLocation();
        return new URL(location.href).searchParams.get('code');
    }

    protected removeCodeFromLocation(): void {
        location = this.getLocation();
        const url = new URL(location.href);
        if (url.searchParams.has('code')) {
            url.searchParams.delete('code');
            location.replace(url.toString());
        }
    }

    getIdTokenPayload(): IdTokenPayloadType {
        if (!this.isLoggedIn()) {
            throw new Error('Not logged-in');
        }
        const authTokens = this.getAuthTokens();
        if (!authTokens.id_token) {
            throw new Error('No id token');
        } else {
            return jwtDecode(authTokens.id_token);
        }
    }

    getPkce(): PKCECodePair {
        const pkce = this.getItem('pkce');
        if (null === pkce) {
            throw new Error('PKCE pair not found in local storage');
        } else {
            return JSON.parse(pkce);
        }
    }

    setAuthTokens(auth: AuthTokens): void {
        this.setItem('auth', JSON.stringify(auth));
    }

    getAuthTokens(): AuthTokens {
        const authTokens = this.getOptionalAuthTokens();
        if (!authTokens) {
            throw new Error('Auth tokens not found in local storage');
        } else {
            return authTokens;
        }
    }

    private getOptionalAuthTokens(): AuthTokens | undefined {
        const auth = this.getItem('auth');
        if (auth) {
            return JSON.parse(auth);
        } else {
            return undefined;
        }
    }

    isPending(): boolean {
        return this.haveItem('pkce') && !this.isLoggedIn();
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

    async logout(shouldEndSession = false): Promise<boolean> {
        this.removeItem('pkce');
        this.removeItem('auth');
        if (shouldEndSession) {
            this.getLocation().replace(this.newLogoutUrl().toString());
            return true;
        } else {
            this.getLocation().reload();
            return true;
        }
    }

    private newLogoutUrl(): URL {
        const { clientId, provider, logoutEndpoint, redirectUri } = this.props;
        const logoutUrl = new URL(logoutEndpoint || `${provider}/logout`);
        logoutUrl.searchParams.set('client_id', clientId);
        if (redirectUri) {
            logoutUrl.searchParams.set('post_logout_redirect_uri', redirectUri);
        }
        return logoutUrl;
    }

    async login(): Promise<void> {
        return this.authorize();
    }

    // this will do a full page reload to the OAuth2 provider's login page
    protected async authorize(): Promise<void> {
        const pkce = await this.createPKCECodes();
        this.setItem('pkce', JSON.stringify(pkce));
        this.setItem('preAuthUri', location.href);
        this.removeItem('auth');
        const codeChallenge = pkce.codeChallenge;

        this.getLocation().replace(this.newAuthorizeUrl(codeChallenge).toString());
    }

    protected async createPKCECodes(): Promise<PKCECodePair> {
        return createPKCECodes();
    }

    private newAuthorizeUrl(codeChallenge: string): URL {
        const authorizeUrl = new URL(this.props.authorizeEndpoint || `${this.props.provider}/authorize`);

        authorizeUrl.searchParams.set('client_id', this.props.clientId);
        authorizeUrl.searchParams.set('scope', this.props.scopes.join(' '));
        authorizeUrl.searchParams.set('response_type', 'code');
        authorizeUrl.searchParams.set('code_challenge', codeChallenge);
        authorizeUrl.searchParams.set('code_challenge_method', 'S256');
        if (this.props.audience) {
            authorizeUrl.searchParams.set('audience', this.props.audience);
        }
        if (this.props.prompts) {
            authorizeUrl.searchParams.set('prompt', this.props.prompts.join(' '));
        }
        if (this.props.redirectUri) {
            authorizeUrl.searchParams.set('redirect_uri', this.props.redirectUri);
        }

        return authorizeUrl;
    }

    // this happens after a full page reload. Read the code from localstorage
    protected async fetchToken(code: string, isRefresh = false): Promise<AuthTokens> {
        let refreshToken: string | undefined;
        let payload: RefreshTokenRequestBody | AuthorizationCodeRequestBody;
        if (isRefresh) {
            refreshToken = code;
            payload = {
                grant_type: 'refresh_token',
                client_id: this.props.clientId,
                client_secret: this.props.clientSecret,
                redirect_uri: this.props.redirectUri,
                refresh_token: refreshToken
            };
        } else {
            const pkce: PKCECodePair = this.getPkce();
            const codeVerifier = pkce.codeVerifier;
            payload = {
                grant_type: 'authorization_code',
                client_id: this.props.clientId,
                client_secret: this.props.clientSecret,
                redirect_uri: this.props.redirectUri,
                code,
                code_verifier: codeVerifier
            };
        }

        const response = await fetch(this.newTokenUrl().toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            method: 'POST',
            body: toUrlEncoded({ ...payload })
        });

        this.removeItem('pkce');
        const newAuthTokens: AuthTokens = await response.json();
        if (isRefresh && !newAuthTokens.refresh_token && refreshToken) {
            newAuthTokens.refresh_token = refreshToken;
        }
        newAuthTokens.expires_at = Date.now() + newAuthTokens.expires_in * 1000;
        this.setAuthTokens(newAuthTokens);

        if (this.props.autoRefresh) {
            this.startRefreshTimer();
        }

        return this.getAuthTokens();
    }

    private newTokenUrl(): URL {
        const { provider, tokenEndpoint } = this.props;
        return new URL(`${tokenEndpoint || `${provider}/token`}`);
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
        if (!expiresAt || !refreshToken) {
            return;
        }

        let timeoutMillis = expiresAt - Date.now();
        if (timeoutMillis <= 0) {
            this.handleExpired();
        } else {
            timeoutMillis = this.applyRefreshBeforeExpirationTime(timeoutMillis);
            this.logTimer(timeoutMillis, expiresAt);

            this.timeout = window.setTimeout(() => {
                this.fetchToken(refreshToken, true).catch((e) => {
                    this.removeItem('auth');
                    this.removeCodeFromLocation();
                    console.warn('Error fetching token for refresh', e);
                });
            }, timeoutMillis);
        }
    }

    private applyRefreshBeforeExpirationTime(timeoutMillis: number): number {
        const { refreshBeforeExpirationSeconds } = this.props;
        if (refreshBeforeExpirationSeconds && timeoutMillis > refreshBeforeExpirationSeconds) {
            return timeoutMillis - refreshBeforeExpirationSeconds;
        }
        return timeoutMillis;
    }

    private logTimer(timeoutMillis: number, expiresAt: number) {
        const refreshDate = new Date(Date.now() + timeoutMillis);
        const expirationDate = new Date(expiresAt);
        console.log(`Setting timer to refresh at ${refreshDate}, expiration at ${expirationDate}`);
    }

    private handleExpired() {
        this.removeItem('auth');
        this.removeCodeFromLocation();
    }

    restoreUri(): void {
        const uri = this.getItem('preAuthUri');
        this.removeItem('preAuthUri');
        location = this.getLocation();
        if (uri !== null) {
            location.replace(uri);
        }
        this.removeCodeFromLocation();
    }

    // For better testability:
    protected getLocation(): Location {
        return window.location;
    }

    protected getItem(key: string): string | null {
        const { localStoragePrefix = '' } = this.props;
        return window.localStorage.getItem(localStoragePrefix + key);
    }

    protected haveItem(key: string): boolean {
        return this.getItem(key) !== null;
    }

    protected removeItem(key: string): void {
        const { localStoragePrefix = '' } = this.props;
        window.localStorage.removeItem(localStoragePrefix + key);
    }

    protected setItem(key: string, value: string): void {
        const { localStoragePrefix = '' } = this.props;
        window.localStorage.setItem(localStoragePrefix + key, value);
    }
}
