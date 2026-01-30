import { type FormEvent, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router';
import { authApi, ApiError } from '../api';
import './auth.scss';

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get('token') ?? '';
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError('');

    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }

    try {
      await authApi.resetPassword(token, password);
      navigate('/login');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Reset failed');
    }
  }

  if (!token) {
    return (
      <div className="auth-page">
        <h1>Reset Password</h1>
        <p className="error">Missing reset token.</p>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <h1>Reset Password</h1>
      <form onSubmit={handleSubmit}>
        <label>
          New Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            required
          />
        </label>
        <label>
          Confirm Password
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            required
          />
        </label>
        {error && <p className="error">{error}</p>}
        <button type="submit">Reset password</button>
      </form>
    </div>
  );
}
