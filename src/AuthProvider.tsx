import React, { type ReactElement, type PropsWithChildren } from "react";
import { type AuthService } from "./AuthService";
import { AuthContext } from "./AuthContext";

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
