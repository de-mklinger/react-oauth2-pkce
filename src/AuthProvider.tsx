import React, { ReactElement, PropsWithChildren } from 'react';

import { AuthService } from './AuthService';
import { AuthContext } from './AuthContext';

type AuthProviderProps = PropsWithChildren<{
    authService: AuthService;
}>;

export const AuthProvider = (props: AuthProviderProps): ReactElement => {
    const { authService, children } = props;

    return (
        <AuthContext.Provider value={{ authService }}>
            {children}
        </AuthContext.Provider>
    );
};
