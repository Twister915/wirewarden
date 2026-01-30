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

  loginBegin(username: string) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return api<{ publicKey: any; user_id: string }>(
      '/auth/passkey/login/begin',
      {
        method: 'POST',
        body: JSON.stringify({ username }),
      },
    );
  },

  loginFinish(user_id: string, credential: unknown) {
    return api<User>('/auth/passkey/login/finish', {
      method: 'POST',
      body: JSON.stringify({ user_id, credential }),
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
