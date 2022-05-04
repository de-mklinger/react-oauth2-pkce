import * as React from 'react';
import { AuthProvider, AuthService } from '..';
import Home from './Home';

const authService = new AuthService({
    clientId: process.env.REACT_APP_CLIENT_ID || 'CHANGEME',
    provider: process.env.REACT_APP_PROVIDER || 'https://sandbox.auth.ap-southeast-2.amazoncognito.com/oauth2',
    redirectUri: process.env.REACT_APP_REDIRECT_URI || window.location.origin,
    scopes: ['openid', 'profile'],
    debug: true
});

export default function App() {
    return (
        <AuthProvider authService={authService}>
            <Home />
        </AuthProvider>
    );
}
