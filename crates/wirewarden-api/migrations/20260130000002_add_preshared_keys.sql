CREATE TABLE wg_preshared_keys (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id  UUID NOT NULL REFERENCES wg_servers(id) ON DELETE CASCADE,
    client_id  UUID NOT NULL REFERENCES wg_clients(id) ON DELETE CASCADE,
    key_enc    BYTEA NOT NULL,
    key_nonce  BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, client_id)
);
