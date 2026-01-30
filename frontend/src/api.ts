export class ApiError extends Error {
  status: number;
  body: { error?: string };

  constructor(status: number, body: { error?: string }) {
    super(body.error ?? `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    credentials: 'same-origin',
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

export interface User {
  id: string;
  username: string;
  display_name: string;
  email: string;
  created_at: string;
}

export interface PasskeyInfo {
  id: string;
  name: string;
  created_at: string;
}

export const authApi = {
  register(data: {
    username: string;
    display_name: string;
    email: string;
    password: string;
  }) {
    return api<User>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  login(data: { username: string; password: string }) {
    return api<User>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  logout() {
    return api<{ status: string }>('/auth/logout', { method: 'POST' });
  },

  me() {
    return api<User>('/auth/me');
  },

  forgotPassword(email: string) {
    return api<{ message: string }>('/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  resetPassword(token: string, password: string) {
    return api<{ status: string }>('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, password }),
    });
  },
};

// VPN types

export interface NetworkResponse {
  id: string;
  name: string;
  cidr: string;
  dns_servers: string[];
  persistent_keepalive: number;
  created_at: string;
  updated_at: string;
}

export interface CreateNetworkRequest {
  name: string;
  cidr: string;
  dns_servers: string[];
  persistent_keepalive?: number;
}

export interface ServerResponse {
  id: string;
  network_id: string;
  name: string;
  public_key: string;
  api_token: string;
  address_offset: number;
  address: string;
  forwards_internet_traffic: boolean;
  endpoint_host: string | null;
  endpoint_port: number;
  created_at: string;
  updated_at: string;
  connect_command: string | null;
}

export interface CreateServerRequest {
  network_id: string;
  name: string;
  endpoint_host: string | null;
  endpoint_port: number;
  forwards_internet_traffic: boolean;
}

export interface ClientResponse {
  id: string;
  network_id: string;
  name: string;
  public_key: string;
  address_offset: number;
  address: string;
  created_at: string;
  updated_at: string;
}

export interface CreateClientRequest {
  network_id: string;
  name: string;
}

export interface RouteResponse {
  id: string;
  server_id: string;
  route_cidr: string;
  created_at: string;
  updated_at: string;
}

export interface CreateRouteRequest {
  route_cidr: string;
}

export const vpnApi = {
  listNetworks() {
    return api<NetworkResponse[]>('/networks');
  },
  createNetwork(data: CreateNetworkRequest) {
    return api<NetworkResponse>('/networks', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  getNetwork(id: string) {
    return api<NetworkResponse>(`/networks/${id}`);
  },
  updateNetwork(id: string, data: { dns_servers: string[]; persistent_keepalive: number }) {
    return api<NetworkResponse>(`/networks/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },
  deleteNetwork(id: string) {
    return api<{ status: string }>(`/networks/${id}`, { method: 'DELETE' });
  },

  listServers(networkId: string) {
    return api<ServerResponse[]>(`/networks/${networkId}/servers`);
  },
  createServer(data: CreateServerRequest) {
    return api<ServerResponse>('/servers', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  getServer(id: string) {
    return api<ServerResponse>(`/servers/${id}`);
  },
  deleteServer(id: string) {
    return api<{ status: string }>(`/servers/${id}`, { method: 'DELETE' });
  },

  listClients(networkId: string) {
    return api<ClientResponse[]>(`/networks/${networkId}/clients`);
  },
  createClient(data: CreateClientRequest) {
    return api<ClientResponse>('/clients', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  getClient(id: string) {
    return api<ClientResponse>(`/clients/${id}`);
  },
  deleteClient(id: string) {
    return api<{ status: string }>(`/clients/${id}`, { method: 'DELETE' });
  },
  clientConfig(id: string, forwardInternet: boolean) {
    const q = forwardInternet ? '?forward_internet=true' : '';
    return api<{ config: string }>(`/clients/${id}/config${q}`);
  },

  listRoutes(serverId: string) {
    return api<RouteResponse[]>(`/servers/${serverId}/routes`);
  },
  addRoute(serverId: string, data: CreateRouteRequest) {
    return api<RouteResponse>(`/servers/${serverId}/routes`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  deleteRoute(id: string) {
    return api<{ status: string }>(`/routes/${id}`, { method: 'DELETE' });
  },
};

export const passkeyApi = {
  registerBegin() {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return api<any>('/auth/passkey/register/begin', { method: 'POST' });
  },

  registerFinish(credential: unknown) {
    return api<{ status: string }>('/auth/passkey/register/finish', {
      method: 'POST',
      body: JSON.stringify(credential),
    });
  },

  loginBegin() {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return api<{ publicKey: any; session_id: string }>(
      '/auth/passkey/login/begin',
      { method: 'POST' },
    );
  },

  loginFinish(session_id: string, credential: unknown) {
    return api<User>('/auth/passkey/login/finish', {
      method: 'POST',
      body: JSON.stringify({ session_id, credential }),
    });
  },

  list() {
    return api<PasskeyInfo[]>('/auth/passkeys');
  },

  rename(id: string, name: string) {
    return api<{ status: string }>(`/auth/passkeys/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ name }),
    });
  },

  delete(id: string) {
    return api<{ status: string }>(`/auth/passkeys/${id}`, {
      method: 'DELETE',
    });
  },
};
