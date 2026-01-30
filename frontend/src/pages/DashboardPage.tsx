// Copyright (C) 2025 Joseph Sacchini
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
        <Link to="/networks">Networks</Link>
        {' | '}
        <Link to="/settings">Settings</Link>
      </nav>
      <button type="button" onClick={logout}>
        Sign out
      </button>
    </div>
  );
}
