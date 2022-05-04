import { AuthService, AuthServiceProps, AuthTokens } from '../src/AuthService';
import { PKCECodePair } from '../src/pkce';
import { mock } from 'jest-mock-extended';
import jwtEncode from 'jwt-encode';

const props: AuthServiceProps = {
    clientId: 'testClientID',
    clientSecret: undefined,
    location,
    provider: 'http://oauth2provider/',
    redirectUri: 'http://localhost/',
    scopes: ['openid', 'profile']
};

const stubPKCECodePair: PKCECodePair = {
    codeVerifier: 'codeVerifier',
    codeChallenge: 'codeChallenge',
    createdAt: new Date()
};

function decodeFormUrlEncodedBody(body: string): { [key: string]: string } {
    const searchParams = new URL(`https://example.com?${body}`).searchParams;
    const obj = {};
    searchParams.forEach((value, key) => (obj[key] = value));
    return obj;
}

// class TestAuthService extends AuthService {
//     public async fetchToken(code: string, isRefresh = false): Promise<AuthTokens> {
//         return super.fetchToken(code, isRefresh);
//     }
//
//     public handleInitialCode(code: string) {
//         super.handleInitialCode(code);
//     }
//
//     public startRefreshTimer() {
//         super.startRefreshTimer();
//     }
//
//     public removeCodeFromLocation() {
//         super.removeCodeFromLocation();
//     }
// }

const testAuthTokens: AuthTokens = {
    id_token: 'id_token',
    access_token: 'access_token',
    refresh_token: 'refresh_token',
    expires_in: 100,
    token_type: 'token_type'
};

function newMockStorage(): Storage {
    const items = new Map<string, string>();
    return {
        key(): string | null {
            throw new Error('Unsupported');
        },
        getItem(key: string): string | null {
            return items.get(key) ?? null;
        },
        clear() {
            throw new Error('Unsupported');
        },
        removeItem(key: string) {
            items.delete(key);
        },
        setItem(key: string, value: string) {
            items.set(key, value);
        },
        length: -1
    };
}

function newMockFetchWithEmptyResponse() {
    const fakeResponse = {
        json: (): unknown => ({})
    };
    const mockFetch = jest.fn();
    mockFetch.mockReturnValueOnce(Promise.resolve(fakeResponse));
    return mockFetch;
}

describe('AuthService', () => {
    it('constructor should fetch token with code in location', async () => {
        const testCode = 'TESTCODE';
        const mockLocation = mock<Location>();
        mockLocation.href = `https://example.com/something?a=b&code=${testCode}&x=y`;

        let fetchTokenArgs: { code: string; isRefresh: boolean } | undefined;

        await withWindowObjects({ location: mockLocation }, () => {
            class LocalAuthService extends AuthService {
                protected async fetchToken(code: string, isRefresh = false): Promise<AuthTokens> {
                    fetchTokenArgs = {
                        code,
                        isRefresh
                    };
                    return Promise.resolve(testAuthTokens);
                }
            }
            new LocalAuthService(props);
        });

        expect(fetchTokenArgs).toHaveProperty('code', testCode);
        expect(fetchTokenArgs).toHaveProperty('isRefresh', false);
    });

    it('constructor should start timer without code in location and autoRefresh enabled', async () => {
        const mockLocation = mock<Location>();
        mockLocation.href = `https://example.com/something?a=b&x=y`;

        let startRefreshTimerCalled = false;

        await withWindowObjects({ location: mockLocation }, () => {
            class LocalAuthService extends AuthService {
                protected startRefreshTimer() {
                    startRefreshTimerCalled = true;
                }
            }
            new LocalAuthService({
                ...props,
                autoRefresh: true
            });
        });

        expect(startRefreshTimerCalled).toBe(true);
    });

    it('fetchToken should send request body', async () => {
        const mockFetch = newMockFetchWithEmptyResponse();

        const mockStorage = newMockStorage();
        mockStorage.setItem('pkce', JSON.stringify(stubPKCECodePair));

        class LocalAuthService extends AuthService {
            public async fetchToken(code: string, isRefresh = false): Promise<AuthTokens> {
                return super.fetchToken(code, isRefresh);
            }
        }
        const authService = new LocalAuthService(props);

        await withWindowObjects({ fetch: mockFetch, localStorage: mockStorage }, async () => {
            await authService.fetchToken('authorizationCode');
        });

        const formUrlEncodedBody = mockFetch.mock.calls[0][1].body;
        const bodyProperties = decodeFormUrlEncodedBody(formUrlEncodedBody);

        expect(bodyProperties).toHaveProperty('client_id');
        expect(bodyProperties).toHaveProperty('redirect_uri');
        expect(bodyProperties).toHaveProperty('grant_type');
        expect(bodyProperties).toHaveProperty('code');
        expect(bodyProperties).toHaveProperty('code_verifier');
    });

    it('fetchToken should start timer if autoRefresh enabled', async () => {
        const mockFetch = newMockFetchWithEmptyResponse();

        const mockStorage = newMockStorage();
        mockStorage.setItem('pkce', JSON.stringify(stubPKCECodePair));

        let called = false;

        class LocalAuthService extends AuthService {
            public async fetchToken(code: string, isRefresh = false): Promise<AuthTokens> {
                return super.fetchToken(code, isRefresh);
            }

            protected startRefreshTimer() {
                called = true;
            }
        }

        const authService = new LocalAuthService({
            ...props,
            autoRefresh: true
        });

        await withWindowObjects({ fetch: mockFetch, localStorage: mockStorage }, async () => {
            await authService.fetchToken('authorizationCode');
        });

        expect(called).toBe(true);
    });

    it('should remove code from location', () => {
        let replaceArg: URL | string | undefined;
        const mockLocation = mock<Location>();
        mockLocation.href = 'https://example.com/something?a=b&code=123&x=y';
        mockLocation.replace.mockImplementation((...args) => {
            replaceArg = args[0];
        });

        class LocalAuthService extends AuthService {
            public removeCodeFromLocation() {
                super.removeCodeFromLocation();
            }
        }
        const authService = new LocalAuthService(props);
        withWindowObjects({ location: mockLocation }, () => {
            authService.removeCodeFromLocation();
        });

        expect(mockLocation.replace).toHaveBeenCalledTimes(1);
        expect(replaceArg).toBeTruthy();
        expect(replaceArg?.toString()).toBe('https://example.com/something?a=b&x=y');
    });

    it('getIdTokenPayload should throw error if not logged in', () => {
        class LocalAuthService extends AuthService {
            isLoggedIn(): boolean {
                return false;
            }
        }
        expect(() => new LocalAuthService(props).getIdTokenPayload()).toThrow('Not logged-in');
    });

    it('getIdTokenPayload should throw error if no auth tokens', () => {
        class LocalAuthService extends AuthService {
            isLoggedIn(): boolean {
                return true;
            }
        }

        const mockStorage = newMockStorage();

        expect(() =>
            withWindowObjects({ localStorage: mockStorage }, () => {
                new LocalAuthService(props).getIdTokenPayload();
            })
        ).toThrow('Auth tokens not found');
    });

    it('getIdTokenPayload should throw error if no id token', () => {
        class LocalAuthService extends AuthService {
            isLoggedIn(): boolean {
                return true;
            }
        }

        const mockStorage = newMockStorage();
        mockStorage.setItem(
            'auth',
            JSON.stringify({
                ...testAuthTokens,
                id_token: undefined
            })
        );

        expect(() =>
            withWindowObjects({ localStorage: mockStorage }, () => {
                new LocalAuthService(props).getIdTokenPayload();
            })
        ).toThrow('No id token');
    });

    it('getIdTokenPayload should return decoded id token', () => {
        const idToken = jwtEncode({ key: 'value' }, 'secret');
        class LocalAuthService extends AuthService {
            getAuthTokens(): AuthTokens {
                return {
                    ...testAuthTokens,
                    id_token: idToken
                };
            }
        }
        const idTokenPayload = new LocalAuthService(props).getIdTokenPayload();
        expect(idTokenPayload).toHaveProperty('key', 'value');
    });

    it('getAuthTokens should throw error if no tokens in storage', () => {
        class LocalAuthService extends AuthService {
            protected getItem(key: string): string | null {
                if (key === 'auth') {
                    return null;
                } else {
                    throw new Error('Unexpected method call');
                }
            }
        }

        expect(() => new LocalAuthService(props).getAuthTokens()).toThrow('Auth tokens not found');
    });

    it('getAuthTokens should return parsed tokens', () => {
        class LocalAuthService extends AuthService {
            protected getItem(key: string): string | null {
                if (key === 'auth') {
                    return JSON.stringify(testAuthTokens);
                } else {
                    throw new Error('Unexpected method call');
                }
            }
        }

        expect(new LocalAuthService(props).getAuthTokens()).toEqual(testAuthTokens);
    });

    it('isPending should return true if pkce and not logged in', () => {
        class LocalAuthService extends AuthService {
            isLoggedIn(): boolean {
                return false;
            }

            protected haveItem(key: string): boolean {
                return key === 'pkce';
            }
        }

        expect(new LocalAuthService(props).isPending()).toBe(true);
    });

    it('isPending should return false if no pkce', () => {
        class LocalAuthService extends AuthService {
            protected haveItem(): boolean {
                return false;
            }
        }

        expect(new LocalAuthService(props).isPending()).toBe(false);
    });

    it('isPending should return false if pkce but logged in', () => {
        class LocalAuthService extends AuthService {
            isLoggedIn(): boolean {
                return true;
            }

            protected haveItem(key: string): boolean {
                return key === 'pkce';
            }
        }

        expect(new LocalAuthService(props).isPending()).toBe(false);
    });

    it('isLoggedIn should return false if no auth', () => {
        class LocalAuthService extends AuthService {
            protected getItem(key: string): string | null {
                if (key === 'auth') {
                    return null;
                } else {
                    throw new Error('Unexpected method call');
                }
            }
        }

        expect(new LocalAuthService(props).isLoggedIn()).toBe(false);
    });

    it('isLoggedIn should return false if expired', () => {
        class LocalAuthService extends AuthService {
            protected getItem(key: string): string | null {
                if (key === 'auth') {
                    const expiredTokens: AuthTokens = {
                        ...testAuthTokens,
                        expires_at: Date.now() - 1000
                    };
                    return JSON.stringify(expiredTokens);
                } else {
                    throw new Error('Unexpected method call');
                }
            }
        }

        expect(new LocalAuthService(props).isLoggedIn()).toBe(false);
    });

    it('isLoggedIn should return true if not expired', () => {
        class LocalAuthService extends AuthService {
            protected getItem(key: string): string | null {
                if (key === 'auth') {
                    const expiredTokens: AuthTokens = {
                        ...testAuthTokens,
                        expires_at: Date.now() + 1000
                    };
                    return JSON.stringify(expiredTokens);
                } else {
                    throw new Error('Unexpected method call');
                }
            }
        }

        expect(new LocalAuthService(props).isLoggedIn()).toBe(true);
    });

    it('isLoggedIn should return true if never expires', () => {
        class LocalAuthService extends AuthService {
            protected getItem(key: string): string | null {
                if (key === 'auth') {
                    const expiredTokens: AuthTokens = {
                        ...testAuthTokens,
                        expires_at: undefined
                    };
                    return JSON.stringify(expiredTokens);
                } else {
                    throw new Error('Unexpected method call');
                }
            }
        }

        expect(new LocalAuthService(props).isLoggedIn()).toBe(true);
    });

    it('logout cleans local storage', async () => {
        const mockStorage = newMockStorage();
        mockStorage.setItem('pkce', 'something');
        mockStorage.setItem('auth', 'something else');

        const mockLocation = mock<Location>();
        mockLocation.href = 'https://example.com';

        await withWindowObjects({ localStorage: mockStorage, location: mockLocation }, () => {
            return new AuthService(props).logout();
        });

        expect(mockStorage.getItem('pkce')).toBeNull();
        expect(mockStorage.getItem('auth')).toBeNull();
    });

    it('logout reloads page', async () => {
        const mockStorage = newMockStorage();

        const mockLocation = mock<Location>();
        mockLocation.href = 'https://example.com';

        await withWindowObjects({ localStorage: mockStorage, location: mockLocation }, () => {
            return new AuthService(props).logout();
        });

        expect(mockLocation.reload).toBeCalled();
    });

    it('logout with shouldEndSession redirects', async () => {
        const mockStorage = newMockStorage();

        const mockLocation = mock<Location>();
        mockLocation.href = 'https://example.com';

        await withWindowObjects({ localStorage: mockStorage, location: mockLocation }, () => {
            return new AuthService(props).logout(true);
        });

        expect(mockLocation.replace).toBeCalled();
    });

    it('login calls authorize', async () => {
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

    it('authorize initializes storage', async () => {
        const mockStorage = newMockStorage();
        mockStorage.setItem('auth', 'something');

        const mockLocation = mock<Location>();
        mockLocation.href = 'https://example.com/before_auth';

        const pkceCodes: PKCECodePair = {
            codeVerifier: 'verifier',
            codeChallenge: 'code_challenge',
            createdAt: new Date()
        };

        class TestAuthService extends AuthService {
            public async authorize(): Promise<void> {
                return super.authorize();
            }

            protected async createPKCECodes(): Promise<PKCECodePair> {
                return pkceCodes;
            }
        }

        await withWindowObjects({ localStorage: mockStorage, location: mockLocation }, () => {
            return new TestAuthService(props).authorize();
        });

        expect(mockStorage.getItem('auth')).toBeNull();
        expect(mockStorage.getItem('pkce')).toBe(JSON.stringify(pkceCodes));
        expect(mockStorage.getItem('preAuthUri')).toBe('https://example.com/before_auth');
    });
});

function withWindowObjects<T>(mocks: { [key: string]: unknown }, callback: () => Promise<T> | T) {
    const oldWindowObjects: { [key: string]: unknown } = {};
    for (const key in mocks) {
        oldWindowObjects[key] = window[key];
        delete window[key];
        window[key] = mocks[key];
    }
    return Promise.resolve(callback()).finally(() => {
        for (const key in mocks) {
            window[key] = oldWindowObjects[key];
        }
    });
}
