import { AuthService, AuthServiceProps } from './AuthService'
import { PKCECodePair } from './pkce'

const props: AuthServiceProps = {
  clientId: 'testClientID',
  clientSecret: undefined,
  location,
  contentType: undefined,
  provider: 'http://oauth2provider/',
  redirectUri: 'http://localhost/',
  scopes: ['openid', 'profile']
}

const stubPKCECodePair: PKCECodePair = {
  codeVerifier: 'codeVerifier',
  codeChallenge: 'codeChallenge',
  createdAt: new Date()
}

function decodeFormUrlEncodedBody(body: string): { [key: string]: string } {
  const searchParams = new URL(`https://example.com?${body}`).searchParams
  const obj = {}
  searchParams.forEach((value, key) => (obj[key] = value))
  return obj
}

const authService = new AuthService(props)

describe('AuthService', () => {
  it('is truthy', () => {
    expect(AuthService).toBeTruthy()
  })

  it('should have request body', async () => {
    const fakeResponse = {
      json: (): unknown => ({})
    }

    const originalFetch = window.fetch
    try {
      const fakeFetch = jest.fn()
      fakeFetch.mockReturnValueOnce(Promise.resolve(fakeResponse))
      window.fetch = fakeFetch

      window.localStorage.setItem('pkce', JSON.stringify(stubPKCECodePair))

      const authorizationCode = 'authorizationCode'
      await authService.fetchToken(authorizationCode)

      const formUrlEncodedBody = fakeFetch.mock.calls[0][1].body
      const bodyProperties = decodeFormUrlEncodedBody(formUrlEncodedBody)

      expect(bodyProperties).toHaveProperty('client_id')
      expect(bodyProperties).toHaveProperty('redirect_uri')
      expect(bodyProperties).toHaveProperty('grant_type')
      expect(bodyProperties).toHaveProperty('code')
      expect(bodyProperties).toHaveProperty('code_verifier')
    } finally {
      window.fetch = originalFetch
    }
  })
})
