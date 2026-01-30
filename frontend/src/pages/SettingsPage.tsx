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

import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router';
import { passkeyApi, type PasskeyInfo, ApiError } from '../api';
import { startRegistration } from '@simplewebauthn/browser';
import './settings.scss';

export function SettingsPage() {
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [error, setError] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');

  const load = useCallback(async () => {
    try {
      setPasskeys(await passkeyApi.list());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load passkeys');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handleAdd() {
    setError('');
    try {
      const resp = await passkeyApi.registerBegin();
      const credential = await startRegistration({ optionsJSON: resp.publicKey });
      await passkeyApi.registerFinish(credential);
      await load();
    } catch (err) {
      if (err instanceof Error && err.name === 'NotAllowedError') return;
      setError(err instanceof ApiError ? err.message : 'Failed to add passkey');
    }
  }

  async function handleRename(id: string) {
    if (!editName.trim()) return;
    try {
      await passkeyApi.rename(id, editName.trim());
      setEditingId(null);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to rename');
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this passkey?')) return;
    try {
      await passkeyApi.delete(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete');
    }
  }

  return (
    <div className="settings-page">
      <h1>Settings</h1>
      <h2>Passkeys</h2>

      {passkeys.length > 0 ? (
        <ul className="passkey-list">
          {passkeys.map((pk) => (
            <li key={pk.id}>
              {editingId === pk.id ? (
                <>
                  <input
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleRename(pk.id)}
                    autoFocus
                  />
                  <button type="button" onClick={() => handleRename(pk.id)}>
                    Save
                  </button>
                  <button type="button" onClick={() => setEditingId(null)}>
                    Cancel
                  </button>
                </>
              ) : (
                <>
                  <span className="passkey-name">{pk.name}</span>
                  <span className="date">
                    {new Date(pk.created_at).toLocaleDateString()}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setEditingId(pk.id);
                      setEditName(pk.name);
                    }}
                  >
                    Rename
                  </button>
                  <button type="button" onClick={() => handleDelete(pk.id)}>
                    Delete
                  </button>
                </>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p>No passkeys registered.</p>
      )}

      <div className="actions">
        <button type="button" onClick={handleAdd}>
          Add passkey
        </button>
      </div>

      {error && <p className="error">{error}</p>}

      <nav>
        <Link to="/">Back to dashboard</Link>
      </nav>
    </div>
  );
}
