import { type FormEvent, useState } from 'react';
import { Link } from 'react-router';
import { authApi } from '../api';
import './auth.scss';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    await authApi.forgotPassword(email);
    setSent(true);
  }

  return (
    <div className="auth-page">
      <h1>Forgot Password</h1>
      {sent ? (
        <p className="success">
          If that email is registered, you will receive a reset link.
        </p>
      ) : (
        <form onSubmit={handleSubmit}>
          <label>
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </label>
          <button type="submit">Send reset link</button>
        </form>
      )}
      <div className="links">
        <Link to="/login">Back to sign in</Link>
      </div>
    </div>
  );
}
