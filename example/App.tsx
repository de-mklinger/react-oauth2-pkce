import * as React from "react";
import { AuthProvider, AuthService } from "..";
import Home from "./Home";
import { type AuthServiceProps } from "../src/AuthService";

const testProps: AuthServiceProps = {
  clientId: process.env.REACT_APP_CLIENT_ID ?? "CHANGEME",
  provider: process.env.REACT_APP_PROVIDER ?? "http://localhost:3001",
  redirectUri: process.env.REACT_APP_REDIRECT_URI ?? "http://localhost:3000",
  authorizeEndpoint: process.env.REACT_APP_AUTHORIZE_ENDPOINT ?? undefined,
  logoutEndpoint: process.env.REACT_APP_LOGOUT_ENDPOINT ?? undefined,
  scopes: process.env.REACT_APP_SCOPE
    ? process.env.REACT_APP_SCOPE.split(/\s+/)
    : [
        "openid",
        "offline_access", // 'offline_access' required for refresh token
        "profile",
        "roles",
        "user",
        "other_profiles",
        "omni_organization",
      ],
  prompts: process.env.REACT_APP_PROMPT
    ? process.env.REACT_APP_PROMPT.split(/\s+/)
    : ["consent"], // 'consent' required for refresh token
  autoRefresh: true,
  refreshBeforeExpirationSeconds: 600,
  debug: true,
};

const authService = new AuthService(testProps);

export default function App() {
  return (
    <AuthProvider authService={authService}>
      <Home />
    </AuthProvider>
  );
}
