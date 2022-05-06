This example was bootstrapped with [Create React App](https://github.com/facebook/create-react-app).

It is linked to the react-oauth2-pkce package in the parent directory for development purposes.

You can run `npm install` and then `npm start` to test your package.

Use a local `.env` file to override default settings like this:

```
REACT_APP_CLIENT_ID=my-client-id
REACT_APP_PROVIDER=https://provider.example.com
REACT_APP_REDIRECT_URI=https://app.example.com
REACT_APP_AUTHORIZE_ENDPOINT=https://provider.example.com/auth
REACT_APP_LOGOUT_ENDPOINT=https://provider.example.com/session/end
REACT_APP_SCOPE=openid offline_access profile roles user
REACT_APP_PROMPT=consent
```
