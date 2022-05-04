import React from 'react'
import { useAuth } from '@mklinger/react-oauth2-pkce'

export default function Home() {
  const { authService } = useAuth()

  const login = async () => {
    return authService.authorize()
  }
  const logout = async () => {
    return authService.logout()
  }

  if (authService.isPending()) {
    return <div>Loading...</div>
  }

  if (!authService.isAuthenticated()) {
    return (
      <div>
        <p>Not Logged in yet.</p>
        <button onClick={login}>Login</button>
      </div>
    )
  }

  return (
    <div>
      <p>Logged in! {authService.getUser()}</p>
      <button onClick={logout}>Logout</button>
    </div>
  )
}
