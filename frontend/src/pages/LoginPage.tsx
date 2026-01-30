import { type FormEvent, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { useAuth } from '../context/AuthContext';
import { ApiError, passkeyApi } from '../api';
import { startAuthentication } from '@simplewebauthn/browser';
import './auth.scss';

export function LoginPage() {
  const { login, refresh } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await login(username, password);
      navigate('/');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Login failed');
    }
  }

  async function handlePasskeyLogin() {
    setError('');
    try {
      const opts = await passkeyApi.loginBegin();
      const credential = await startAuthentication({ optionsJSON: opts.publicKey });
      await passkeyApi.loginFinish(opts.session_id, credential);
      await refresh();
      navigate('/');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Passkey login failed');
    }
  }

  return (
    <div className="auth-page">
      <h1>Sign In</h1>
      <form onSubmit={handleSubmit}>
        <label>
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        {error && <p className="error">{error}</p>}
        <button type="submit">Sign in</button>
      </form>
      <button type="button" onClick={handlePasskeyLogin}>
        Sign in with passkey
      </button>
      <div className="links">
        <Link to="/register">Create an account</Link>
        <Link to="/forgot-password">Forgot password?</Link>
      </div>
    </div>
  );
}
