import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router';
import { vpnApi, type ServerResponse, type RouteResponse, ApiError } from '../api';
import './vpn.scss';

export function ServerDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [server, setServer] = useState<ServerResponse | null>(null);
  const [routes, setRoutes] = useState<RouteResponse[]>([]);
  const [error, setError] = useState('');
  const [routeCidr, setRouteCidr] = useState('');

  const load = useCallback(async () => {
    if (!id) return;
    try {
      const [srv, rts] = await Promise.all([
        vpnApi.getServer(id),
        vpnApi.listRoutes(id),
      ]);
      setServer(srv);
      setRoutes(rts);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load server');
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  async function handleAddRoute(e: React.FormEvent) {
    e.preventDefault();
    if (!id) return;
    setError('');
    try {
      await vpnApi.addRoute(id, { route_cidr: routeCidr });
      setRouteCidr('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to add route');
    }
  }

  async function handleDeleteRoute(routeId: string) {
    if (!confirm('Delete this route?')) return;
    try {
      await vpnApi.deleteRoute(routeId);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete route');
    }
  }

  const [copied, setCopied] = useState(false);
  const tokenRef = useRef<HTMLInputElement>(null);

  const connectText = server
    ? server.connect_command
      ?? `wirewarden connect --api-host ${window.location.origin} --api-token ${server.api_token}`
    : '';

  function handleCopy() {
    if (!connectText) return;
    navigator.clipboard.writeText(connectText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (!server) return <div className="vpn-page"><p>Loading…</p></div>;

  return (
    <div className="vpn-page">
      <h1>{server.name}</h1>
      <dl className="info">
        <dt>Address</dt>
        <dd>{server.address}</dd>
        <dt>Endpoint</dt>
        <dd>{server.endpoint_host ? `${server.endpoint_host}:${server.endpoint_port}` : `*:${server.endpoint_port}`}</dd>
        <dt>Public Key</dt>
        <dd>{server.public_key}</dd>
        <dt>Forwards Internet</dt>
        <dd>{server.forwards_internet_traffic ? 'Yes' : 'No'}</dd>
        <dt>Connect Command</dt>
        <dd>
          <div className="copy-field">
            <input ref={tokenRef} readOnly value={connectText} />
            <button type="button" onClick={handleCopy}>
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </dd>
      </dl>

      <h2>Routes</h2>
      {routes.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>CIDR</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {routes.map((r) => (
              <tr key={r.id}>
                <td>{r.route_cidr}</td>
                <td><button type="button" onClick={() => handleDeleteRoute(r.id)}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No routes yet.</p>
      )}

      <form onSubmit={handleAddRoute}>
        <div className="form-row">
          <label>
            CIDR
            <input value={routeCidr} onChange={(e) => setRouteCidr(e.target.value)} placeholder="192.168.1.0/24" required />
          </label>
          <button type="submit">Add route</button>
        </div>
      </form>

      {error && <p className="error">{error}</p>}

      <nav>
        <Link to={`/networks/${server.network_id}`}>Back to network</Link>
      </nav>
    </div>
  );
}
