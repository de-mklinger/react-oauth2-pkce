import React from 'react';
import { AuthProvider, AuthService } from '@mklinger/react-oauth2-pkce';
import Home from './Home';

const authService = new AuthService({
    clientId: process.env.REACT_APP_CLIENT_ID || 'CHANGEME',
    location: window.location,
    provider: process.env.REACT_APP_PROVIDER || 'https://sandbox.auth.ap-southeast-2.amazoncognito.com/oauth2',
    redirectUri: process.env.REACT_APP_REDIRECT_URI || window.location.origin,
    scopes: ['openid', 'profile']
});

export default function App() {
    return (
        <AuthProvider authService={authService}>
            <Home />
        </AuthProvider>
    );
};
