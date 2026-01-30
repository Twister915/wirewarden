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

import { useState } from 'react';

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function isValidIpv4(s: string): boolean {
  if (!IPV4_RE.test(s)) return false;
  return s.split('.').every((octet) => {
    const n = Number(octet);
    return n >= 0 && n <= 255;
  });
}

interface DnsListEditorProps {
  value: string[];
  onChange: (servers: string[]) => void;
}

export function DnsListEditor({ value, onChange }: DnsListEditorProps) {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');

  function handleAdd() {
    const trimmed = input.trim();
    if (!trimmed) return;

    if (!isValidIpv4(trimmed)) {
      setError('Invalid IPv4 address');
      return;
    }
    if (value.includes(trimmed)) {
      setError('Duplicate address');
      return;
    }

    setError('');
    onChange([...value, trimmed]);
    setInput('');
  }

  function handleRemove(index: number) {
    onChange(value.filter((_, i) => i !== index));
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAdd();
    }
  }

  return (
    <div className="dns-list">
      {value.map((server, i) => (
        <div key={server} className="dns-list-entry">
          <span className="dns-list-ip">{server}</span>
          <button type="button" onClick={() => handleRemove(i)}>x</button>
        </div>
      ))}
      <div className="dns-list-input">
        <input
          value={input}
          onChange={(e) => { setInput(e.target.value); setError(''); }}
          onKeyDown={handleKeyDown}
          placeholder="1.1.1.1"
        />
        <button type="button" onClick={handleAdd}>Add</button>
      </div>
      {error && <span className="dns-list-error">{error}</span>}
    </div>
  );
}
