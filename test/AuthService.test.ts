import {mock} from "jest-mock-extended";
import jwtEncode from "jwt-encode";
import {AuthService, AuthServiceProps, AuthStorage, AuthTokens,} from "../src/AuthService";
import {PKCECodePair} from "../src/pkce";

const props: AuthServiceProps = {
  clientId: "testClientID",
  clientSecret: undefined,
  provider: "http://oauth2provider/",
  redirectUri: "http://localhost/",
  scopes: ["openid", "profile"],
};

const stubPKCECodePair: PKCECodePair = {
  codeVerifier: "codeVerifier",
  codeChallenge: "codeChallenge",
  createdAt: new Date(),
};

function decodeFormUrlEncodedBody(body: string): Record<string, string> {
  const searchParams = new URL(`https://example.com?${body}`).searchParams;
  const obj: Record<string, string> = {};
  searchParams.forEach((value, key) => (obj[key] = value));
  return obj;
}

const testAuthTokens: AuthTokens = {
  id_token: "id_token",
  access_token: "access_token",
  refresh_token: "refresh_token",
  expires_in: 100,
  token_type: "token_type",
};

function newMockFetchWithEmptyResponse(): jest.Mock {
  const fakeResponse = {
    ok: true,
    json: (): unknown => ({}),
  };
  const mockFetch = jest.fn();
  mockFetch.mockReturnValueOnce(Promise.resolve(fakeResponse));
  return mockFetch;
}

function newMockStorage(
  auth?: string | null,
  pkce?: string | null,
  preAuthUri?: string | null
): AuthStorage {
  let _auth: string | null = auth ?? null;
  let _pkce: string | null = pkce ?? null;
  let _preAuthUri: string | null = preAuthUri ?? null;
  return {
    getAuth(): string | null {
      return _auth;
    },
    getPkce(): string | null {
      return _pkce;
    },
    getPreAuthUri(): string | null {
      return _preAuthUri;
    },
    removeAuth(): void {
      _auth = null;
    },
    removePkce(): void {
      _pkce = null;
    },
    removePreAuthUri(): void {
      _preAuthUri = null;
    },
    setAuth(auth: string): void {
      _auth = auth;
    },
    setPkce(pkce: string): void {
      _pkce = pkce;
    },
    setPreAuthUri(preAuthUri: string): void {
      _preAuthUri = preAuthUri;
    },
  };
}

describe("AuthService", () => {
  it("constructor should fetch token with code in location", async () => {
    const testCode = "TESTCODE";
    const mockLocation = mock<Location>();
    mockLocation.href = `https://example.com/something?a=b&code=${testCode}&x=y`;

    let fetchTokenArgs: { code: string; isRefresh: boolean } | undefined = undefined;

    class LocalAuthService extends AuthService {
      protected async fetchToken(
        code: string,
        isRefresh = false
      ): Promise<AuthTokens> {
        fetchTokenArgs = {
          code,
          isRefresh,
        };
        return Promise.resolve(testAuthTokens);
      }

      protected getLocation(): Location {
        return mockLocation;
      }
    }

    new LocalAuthService(props);

    expect(fetchTokenArgs).toBeDefined();
    expect(fetchTokenArgs).toHaveProperty("code", testCode);
    expect(fetchTokenArgs).toHaveProperty("isRefresh", false);
  });

  it("constructor should start timer without code in location and autoRefresh enabled", async () => {
    const mockLocation = mock<Location>();
    mockLocation.href = `https://example.com/something?a=b&x=y`;

    let startRefreshTimerCalled = false;

    class LocalAuthService extends AuthService {
      protected startRefreshTimer() {
        startRefreshTimerCalled = true;
      }

      protected getLocation(): Location {
        return mockLocation;
      }
    }

    new LocalAuthService({
      ...props,
      autoRefresh: true,
    });

    expect(startRefreshTimerCalled).toBe(true);
  });

  it("fetchToken should send request body", async () => {
    const mockFetch = newMockFetchWithEmptyResponse();

    const mockStorage = newMockStorage(null, JSON.stringify(stubPKCECodePair));

    class LocalAuthService extends AuthService {
      public async fetchToken(
        code: string,
        isRefresh = false
      ): Promise<AuthTokens> {
        return super.fetchToken(code, isRefresh);
      }
    }

    const authService = new LocalAuthService({
      ...props,
      storage: mockStorage,
    });

    await withWindowObjects({ fetch: mockFetch }, async () => {
      await authService.fetchToken("authorizationCode");
    });

    const formUrlEncodedBody = mockFetch.mock.calls[0][1].body;
    const bodyProperties = decodeFormUrlEncodedBody(formUrlEncodedBody);

    expect(bodyProperties).toHaveProperty("client_id");
    expect(bodyProperties).toHaveProperty("redirect_uri");
    expect(bodyProperties).toHaveProperty("grant_type");
    expect(bodyProperties).toHaveProperty("code");
    expect(bodyProperties).toHaveProperty("code_verifier");
  });

  it("fetchToken should start timer if autoRefresh enabled", async () => {
    const mockFetch = newMockFetchWithEmptyResponse();

    const mockStorage = newMockStorage(null, JSON.stringify(stubPKCECodePair));

    let called = false;

    class LocalAuthService extends AuthService {
      public async fetchToken(
        code: string,
        isRefresh = false
      ): Promise<AuthTokens> {
        return super.fetchToken(code, isRefresh);
      }

      protected startRefreshTimer(): void {
        called = true;
      }
    }

    const authService = new LocalAuthService({
      ...props,
      storage: mockStorage,
      autoRefresh: true,
    });

    await withWindowObjects({ fetch: mockFetch }, async () => {
      await authService.fetchToken("authorizationCode");
    });

    expect(called).toBe(true);
  });

  it("removeCodeFromLocation replaces location", () => {
    let replaceArg: URL | string | undefined;
    const mockLocation = mock<Location>();
    mockLocation.href = "https://example.com/something?a=b&code=123&x=y";
    mockLocation.replace.mockImplementation((...args) => {
      replaceArg = args[0];
    });

    class LocalAuthService extends AuthService {
      protected handleInitialCode() {
        // no initial fetch in this test
      }

      public removeCodeFromLocation(): void {
        super.removeCodeFromLocation();
      }

      protected getLocation(): Location {
        return mockLocation;
      }
    }

    const authService = new LocalAuthService(props);
    authService.removeCodeFromLocation();

    expect(mockLocation.replace).toHaveBeenCalledTimes(1);
    expect(replaceArg).toBeTruthy();
    expect(replaceArg?.toString()).toBe(
      "https://example.com/something?a=b&x=y"
    );
  });

  it("getIdTokenPayload should throw error if not logged in", () => {
    class LocalAuthService extends AuthService {
      isLoggedIn(): boolean {
        return false;
      }
    }

    expect(() => new LocalAuthService(props).getIdTokenPayload()).toThrow(
      "Not logged-in"
    );
  });

  it("getIdTokenPayload should throw error if no auth tokens", () => {
    class LocalAuthService extends AuthService {
      isLoggedIn(): boolean {
        return true;
      }
    }

    const mockStorage = newMockStorage();

    const authService = new LocalAuthService({
      ...props,
      storage: mockStorage,
    });

    expect(() => authService.getIdTokenPayload()).toThrow(
      "Auth tokens not found"
    );
  });

  it("getIdTokenPayload should throw error if no id token", () => {
    class LocalAuthService extends AuthService {
      isLoggedIn(): boolean {
        return true;
      }
    }

    const mockStorage = newMockStorage(
      JSON.stringify({
        ...testAuthTokens,
        id_token: undefined,
      })
    );

    const authService = new LocalAuthService({
      ...props,
      storage: mockStorage,
    });

    expect(() => authService.getIdTokenPayload()).toThrow("No id token");
  });

  it("getIdTokenPayload should return decoded id token", () => {
    const idToken = jwtEncode({ key: "value" }, "secret");

    class LocalAuthService extends AuthService {
      isLoggedIn(): boolean {
        return true;
      }

      getAuthTokens(): AuthTokens {
        return {
          ...testAuthTokens,
          id_token: idToken,
        };
      }
    }

    const idTokenPayload = new LocalAuthService(props).getIdTokenPayload();
    expect(idTokenPayload).toHaveProperty("key", "value");
  });

  it("getAuthTokens should throw error if no tokens in storage", () => {
    const authService = new AuthService({
      ...props,
      storage: newMockStorage(),
    });

    expect(() => authService.getAuthTokens()).toThrow("Auth tokens not found");
  });

  it("getAuthTokens should return parsed tokens", () => {
    const mockStorage = newMockStorage(JSON.stringify(testAuthTokens));

    const authService = new AuthService({
      ...props,
      storage: mockStorage,
    });

    expect(authService.getAuthTokens()).toEqual(testAuthTokens);
  });

  it("isPending should return true if pkce and not logged in", () => {
    const mockStorage = newMockStorage(null, "something-pkce");

    const authService = new AuthService({
      ...props,
      storage: mockStorage,
    });

    expect(authService.isPending()).toBe(true);
  });

  it("isPending should return false if no pkce", () => {
    const mockStorage = newMockStorage();

    const authService = new AuthService({
      ...props,
      storage: mockStorage,
    });

    expect(authService.isPending()).toBe(false);
  });

  it("isPending should return false if pkce but logged in", () => {
    class LocalAuthService extends AuthService {
      isLoggedIn(): boolean {
        return true;
      }
    }

    const mockStorage = newMockStorage();

    const authService = new LocalAuthService({
      ...props,
      storage: mockStorage,
    });

    expect(authService.isPending()).toBe(false);
  });

  it("isLoggedIn should return false if no auth", () => {
    const mockStorage = newMockStorage();

    const authService = new AuthService({
      ...props,
      storage: mockStorage,
    });

    expect(authService.isLoggedIn()).toBe(false);
  });

  it("isLoggedIn should return false if expired", () => {
    const expiredTokens: AuthTokens = {
      ...testAuthTokens,
      expires_at: Date.now() - 1000,
    };

    const mockStorage = newMockStorage(JSON.stringify(expiredTokens));

    const authService = new AuthService({
      ...props,
      storage: mockStorage,
    });

    expect(authService.isLoggedIn()).toBe(false);
  });

  it("isLoggedIn should return true if not expired", () => {
    const unexpiredTokens: AuthTokens = {
      ...testAuthTokens,
      expires_at: Date.now() + 1000,
    };

    const mockStorage = newMockStorage(JSON.stringify(unexpiredTokens));

    const authService = new AuthService({
      ...props,
      storage: mockStorage,
    });

    expect(authService.isLoggedIn()).toBe(true);
  });

  it("isLoggedIn should return true if never expires", () => {
    const neverExpiringTokens: AuthTokens = {
      ...testAuthTokens,
      expires_at: undefined,
    };

    const mockStorage = newMockStorage(JSON.stringify(neverExpiringTokens));

    const authService = new AuthService({
      ...props,
      storage: mockStorage,
    });

    expect(authService.isLoggedIn()).toBe(true);
  });

  it("logout cleans local storage", async () => {
    const mockStorage = newMockStorage("something", "something else");

    const mockLocation = mock<Location>();
    mockLocation.href = "https://example.com";

    class LocalAuthService extends AuthService {
      protected getLocation(): Location {
        return mockLocation;
      }
    }

    const authService = new LocalAuthService({
      ...props,
      storage: mockStorage,
    });

    await authService.logout();

    expect(mockStorage.getPkce()).toBeNull();
    expect(mockStorage.getAuth()).toBeNull();
  });

  it("logout reloads page", async () => {
    const mockStorage = newMockStorage();

    const mockLocation = mock<Location>();
    mockLocation.href = "https://example.com";

    class LocalAuthService extends AuthService {
      protected getLocation(): Location {
        return mockLocation;
      }
    }

    const authService = new LocalAuthService({
      ...props,
      storage: mockStorage,
    });

    await authService.logout();

    expect(mockLocation.reload).toBeCalled();
  });

  it("logout with shouldEndSession redirects", async () => {
    const mockStorage = newMockStorage();

    const mockLocation = mock<Location>();
    mockLocation.href = "https://example.com";

    class LocalAuthService extends AuthService {
      protected getLocation(): Location {
        return mockLocation;
      }
    }

    const authService = new LocalAuthService({
      ...props,
      storage: mockStorage,
    });

    await authService.logout(true);

    expect(mockLocation.replace).toBeCalled();
  });

  it("login calls authorize", async () => {
    let called = false;

    class TestAuthService extends AuthService {
      protected async authorize(): Promise<void> {
        called = true;
        return Promise.resolve();
      }
    }

    await new TestAuthService(props).login();

    expect(called).toBe(true);
  });

  it("authorize initializes storage", async () => {
    const mockStorage = newMockStorage("something");

    const mockLocation = mock<Location>();
    mockLocation.href = "https://example.com/before_auth";

    const pkceCodes: PKCECodePair = {
      codeVerifier: "verifier",
      codeChallenge: "code_challenge",
      createdAt: new Date(),
    };

    class TestAuthService extends AuthService {
      public async authorize(): Promise<void> {
        return super.authorize();
      }

      protected async createPKCECodes(): Promise<PKCECodePair> {
        return pkceCodes;
      }

      protected getLocation(): Location {
        return mockLocation;
      }
    }

    const authService = new TestAuthService({
      ...props,
      storage: mockStorage,
    });

    await authService.authorize();

    expect(mockStorage.getAuth()).toBeNull();
    expect(mockStorage.getPkce()).toBe(JSON.stringify(pkceCodes));
    expect(mockStorage.getPreAuthUri()).toBe("https://example.com/before_auth");
  });
});

function withWindowObjects<T>(
  mocks: { [key: string]: unknown },
  callback: () => Promise<T> | T
): Promise<T> {
  const oldWindowObjects: { [key: string]: unknown } = {};
  for (const key in mocks) {
    if (key in window) {
      // @ts-ignore
      oldWindowObjects[key] = window[key];
    }
    // @ts-ignore
    delete window[key];
    // @ts-ignore
    window[key] = mocks[key];
  }
  return Promise.resolve(callback()).finally(() => {
    for (const key in mocks) {
      // @ts-ignore
      window[key] = oldWindowObjects[key];
    }
  });
}
