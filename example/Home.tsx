import * as React from 'react';
import { useAuth } from '..';

export default function Home() {
    const { authService } = useAuth();

    const login = async () => {
        return authService.login();
    };
    const logout = async () => {
        return authService.logout();
    };

    if (authService.isPending()) {
        return (
            <div>
                <p>Login pending...</p>
                <button onClick={logout}>Cancel</button>
            </div>
        );
    }

    if (!authService.isLoggedIn()) {
        return (
            <div>
                <p>Not Logged in yet.</p>
                <button onClick={login}>Login</button>
            </div>
        );
    }

    return (
        <div>
            <p>Logged in!</p>
            <code>
                {JSON.stringify(authService.getIdTokenPayload())}
            </code>
            <button onClick={logout}>Logout</button>
        </div>
    );
}
