import { Link } from 'react-router';
import { useAuth } from '../context/AuthContext';

export function DashboardPage() {
  const { user, logout } = useAuth();

  return (
    <div>
      <h1>Dashboard</h1>
      {user && (
        <dl>
          <dt>Username</dt>
          <dd>{user.username}</dd>
          <dt>Display Name</dt>
          <dd>{user.display_name}</dd>
          <dt>Email</dt>
          <dd>{user.email}</dd>
        </dl>
      )}
      <nav>
        <Link to="/settings">Settings</Link>
      </nav>
      <button type="button" onClick={logout}>
        Sign out
      </button>
    </div>
  );
}
