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
import { Link, useParams } from 'react-router';
import QRCode from 'qrcode';
import { vpnApi, type ClientResponse, ApiError } from '../api';
import './vpn.scss';

export function ClientDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [client, setClient] = useState<ClientResponse | null>(null);
  const [config, setConfig] = useState('');
  const [configLoaded, setConfigLoaded] = useState(false);
  const [forwardInternet, setForwardInternet] = useState(false);
  const [error, setError] = useState('');
  const [showQr, setShowQr] = useState(false);
  const [qrDataUrl, setQrDataUrl] = useState('');

  const load = useCallback(async () => {
    if (!id) return;
    try {
      setClient(await vpnApi.getClient(id));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load client');
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  const fetchConfig = useCallback(async (forward: boolean) => {
    if (!id) return;
    setError('');
    try {
      const resp = await vpnApi.clientConfig(id, forward);
      setConfig(resp.config);
      setConfigLoaded(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load config');
    }
  }, [id]);

  useEffect(() => {
    if (!showQr || !config) { setQrDataUrl(''); return; }
    let cancelled = false;
    QRCode.toDataURL(config, { errorCorrectionLevel: 'L', margin: 2, width: 300 })
      .then((url) => { if (!cancelled) setQrDataUrl(url); })
      .catch(() => { if (!cancelled) setError('Failed to generate QR code'); });
    return () => { cancelled = true; };
  }, [showQr, config]);

  function handleToggleForward(checked: boolean) {
    setForwardInternet(checked);
    if (configLoaded) {
      fetchConfig(checked);
    }
  }

  function handleDownload() {
    if (!config || !client) return;
    const blob = new Blob([config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${client.name}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function handleRotatePsk() {
    if (!id) return;
    setError('');
    try {
      await vpnApi.rotatePresharedKeys(id);
      if (configLoaded) fetchConfig(forwardInternet);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to rotate preshared keys');
    }
  }

  if (!client) return <div className="vpn-page"><p>Loading…</p></div>;

  return (
    <div className="vpn-page">
      <h1>{client.name}</h1>
      <dl className="info">
        <dt>Address</dt>
        <dd>{client.address}</dd>
        <dt>Public Key</dt>
        <dd>{client.public_key}</dd>
      </dl>

      <h2>Configuration</h2>
      <div className="form-row">
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={forwardInternet}
            onChange={(e) => handleToggleForward(e.target.checked)}
          />
          Forward internet traffic
        </label>
        <button type="button" onClick={() => fetchConfig(forwardInternet)}>Load config</button>
        <button type="button" onClick={handleRotatePsk}>Rotate Preshared Keys</button>
        {config && <button type="button" onClick={handleDownload}>Download</button>}
        {config && (
          <button type="button" onClick={() => setShowQr((v) => !v)}>
            {showQr ? 'Hide QR code' : 'Show QR code'}
          </button>
        )}
      </div>

      {qrDataUrl && <img src={qrDataUrl} alt="WireGuard config QR code" className="qr-code" />}

      {config && <pre className="config-preview">{config}</pre>}

      {error && <p className="error">{error}</p>}

      <nav>
        <Link to={`/networks/${client.network_id}`}>Back to network</Link>
      </nav>
    </div>
  );
}
