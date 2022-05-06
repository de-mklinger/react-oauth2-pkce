# react-oauth2-pkce

Authenticate against generic OAuth2 using PKCE.

[![NPM](https://img.shields.io/npm/v/@de-mklinger/react-oauth2-pkce.svg)](https://www.npmjs.com/package/@de-mklinger/react-oauth2-pkce)

## Install

```bash
npm install --save react-oauth2-pkce
```

## Usage

```tsx
import React from 'react'
import { AuthProvider, AuthService } from 'react-oauth2-pkce'

import { Routes } from './Routes';

const authService = new AuthService({
  clientId: process.env.REACT_APP_CLIENT_ID || 'CHANGEME',
  provider: process.env.REACT_APP_PROVIDER || 'https://auth.example.com',
  redirectUri: process.env.REACT_APP_REDIRECT_URI || window.location.origin,
  scopes: ['openid', 'profile']
});

const App = () => {
  return (
    <AuthProvider authService={authService} >
      <Routes />
    </AuthProvider>
  )
}

export default App
```

## License

MIT

Based on the works of [Gardner Bickford](https://github.com/gardner).
