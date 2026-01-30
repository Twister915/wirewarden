import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router';
import { vpnApi, type NetworkResponse, ApiError } from '../api';
import { DnsListEditor } from '../components/DnsListEditor';
import './vpn.scss';

export function NetworksPage() {
  const [networks, setNetworks] = useState<NetworkResponse[]>([]);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('');
  const [dnsServers, setDnsServers] = useState<string[]>([]);
  const [keepalive, setKeepalive] = useState('25');

  const load = useCallback(async () => {
    try {
      setNetworks(await vpnApi.listNetworks());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load networks');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    try {
      await vpnApi.createNetwork({
        name,
        cidr,
        dns_servers: dnsServers,
        persistent_keepalive: Number(keepalive),
      });
      setName('');
      setCidr('');
      setDnsServers([]);
      setKeepalive('25');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create network');
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this network?')) return;
    try {
      await vpnApi.deleteNetwork(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete network');
    }
  }

  return (
    <div className="vpn-page">
      <h1>Networks</h1>

      {networks.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>CIDR</th>
              <th>DNS</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {networks.map((n) => (
              <tr key={n.id}>
                <td><Link to={`/networks/${n.id}`}>{n.name}</Link></td>
                <td>{n.cidr}</td>
                <td>{n.dns_servers.join(', ')}</td>
                <td>{new Date(n.created_at).toLocaleDateString()}</td>
                <td><button type="button" onClick={() => handleDelete(n.id)}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No networks yet.</p>
      )}

      <h2>Create Network</h2>
      <form onSubmit={handleCreate}>
        <div className="form-row">
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} required />
          </label>
          <label>
            CIDR
            <input value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.0.0.0/24" required />
          </label>
          <label>
            DNS servers
            <DnsListEditor value={dnsServers} onChange={setDnsServers} />
          </label>
          <label>
            Keepalive (s)
            <input type="number" min="0" max="65535" value={keepalive} onChange={(e) => setKeepalive(e.target.value)} />
          </label>
          <button type="submit">Create</button>
        </div>
      </form>

      {error && <p className="error">{error}</p>}

      <nav>
        <Link to="/">Back to dashboard</Link>
      </nav>
    </div>
  );
}
