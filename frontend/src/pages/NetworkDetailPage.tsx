import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router';
import {
  vpnApi,
  type NetworkResponse,
  type ServerResponse,
  type ClientResponse,
  ApiError,
} from '../api';
import { DnsListEditor } from '../components/DnsListEditor';
import './vpn.scss';

export function NetworkDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [network, setNetwork] = useState<NetworkResponse | null>(null);
  const [servers, setServers] = useState<ServerResponse[]>([]);
  const [clients, setClients] = useState<ClientResponse[]>([]);
  const [error, setError] = useState('');

  // DNS editing
  const [editingDns, setEditingDns] = useState(false);
  const [dnsServers, setDnsServers] = useState<string[]>([]);

  // Server form
  const [sName, setSName] = useState('');
  const [sHost, setSHost] = useState('');
  const [sPort, setSPort] = useState('51820');
  const [sForwards, setSForwards] = useState(false);

  // Client form
  const [cName, setCName] = useState('');

  const load = useCallback(async () => {
    if (!id) return;
    try {
      const [net, srvs, cls] = await Promise.all([
        vpnApi.getNetwork(id),
        vpnApi.listServers(id),
        vpnApi.listClients(id),
      ]);
      setNetwork(net);
      setServers(srvs);
      setClients(cls);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load network');
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  function startEditDns() {
    if (!network) return;
    setDnsServers([...network.dns_servers]);
    setEditingDns(true);
  }

  async function handleSaveDns() {
    if (!id) return;
    setError('');
    try {
      const updated = await vpnApi.updateNetworkDns(id, dnsServers);
      setNetwork(updated);
      setEditingDns(false);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update DNS');
    }
  }

  async function handleCreateServer(e: React.FormEvent) {
    e.preventDefault();
    if (!id) return;
    setError('');
    try {
      await vpnApi.createServer({
        network_id: id,
        name: sName,
        endpoint_host: sHost || null,
        endpoint_port: Number(sPort),
        forwards_internet_traffic: sForwards,
      });
      setSName('');
      setSHost('');
      setSPort('51820');
      setSForwards(false);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create server');
    }
  }

  async function handleDeleteServer(serverId: string) {
    if (!confirm('Delete this server?')) return;
    try {
      await vpnApi.deleteServer(serverId);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete server');
    }
  }

  async function handleCreateClient(e: React.FormEvent) {
    e.preventDefault();
    if (!id) return;
    setError('');
    try {
      await vpnApi.createClient({
        network_id: id,
        name: cName,
      });
      setCName('');
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create client');
    }
  }

  async function handleDeleteClient(clientId: string) {
    if (!confirm('Delete this client?')) return;
    try {
      await vpnApi.deleteClient(clientId);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to delete client');
    }
  }

  if (!network) return <div className="vpn-page"><p>Loading…</p></div>;

  return (
    <div className="vpn-page">
      <h1>{network.name}</h1>
      <dl className="info">
        <dt>CIDR</dt>
        <dd>{network.cidr}</dd>
        <dt>DNS</dt>
        <dd>
          {editingDns ? (
            <div>
              <DnsListEditor value={dnsServers} onChange={setDnsServers} />
              <div className="form-row">
                <button type="button" onClick={handleSaveDns}>Save</button>
                <button type="button" onClick={() => setEditingDns(false)}>Cancel</button>
              </div>
            </div>
          ) : (
            <>
              {network.dns_servers.join(', ') || '—'}
              {' '}
              <button type="button" onClick={startEditDns}>Edit</button>
            </>
          )}
        </dd>
      </dl>

      <h2>Servers</h2>
      {servers.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Address</th>
              <th>Endpoint</th>
              <th>Public Key</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {servers.map((s) => (
              <tr key={s.id}>
                <td><Link to={`/servers/${s.id}`}>{s.name}</Link></td>
                <td>{s.address}</td>
                <td>{s.endpoint_host ? `${s.endpoint_host}:${s.endpoint_port}` : `*:${s.endpoint_port}`}</td>
                <td title={s.public_key}>{s.public_key.slice(0, 12)}…</td>
                <td><button type="button" onClick={() => handleDeleteServer(s.id)}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No servers yet.</p>
      )}

      <form onSubmit={handleCreateServer}>
        <div className="form-row">
          <label>
            Name
            <input value={sName} onChange={(e) => setSName(e.target.value)} required />
          </label>
          <label>
            Endpoint host
            <input value={sHost} onChange={(e) => setSHost(e.target.value)} placeholder="vpn.example.com" />
          </label>
          <label>
            Port
            <input type="number" value={sPort} onChange={(e) => setSPort(e.target.value)} required />
          </label>
          <label className="checkbox-label">
            <input type="checkbox" checked={sForwards} onChange={(e) => setSForwards(e.target.checked)} />
            Forwards internet
          </label>
          <button type="submit">Add server</button>
        </div>
      </form>

      <h2>Clients</h2>
      {clients.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Address</th>
              <th>Public Key</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {clients.map((c) => (
              <tr key={c.id}>
                <td><Link to={`/clients/${c.id}`}>{c.name}</Link></td>
                <td>{c.address}</td>
                <td title={c.public_key}>{c.public_key.slice(0, 12)}…</td>
                <td><button type="button" onClick={() => handleDeleteClient(c.id)}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No clients yet.</p>
      )}

      <form onSubmit={handleCreateClient}>
        <div className="form-row">
          <label>
            Name
            <input value={cName} onChange={(e) => setCName(e.target.value)} required />
          </label>
          <button type="submit">Add client</button>
        </div>
      </form>

      {error && <p className="error">{error}</p>}

      <nav>
        <Link to="/networks">Back to networks</Link>
      </nav>
    </div>
  );
}
