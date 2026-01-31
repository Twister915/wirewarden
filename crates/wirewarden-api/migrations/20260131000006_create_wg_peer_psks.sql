-- Preshared keys for server <-> client peers
CREATE TABLE wg_peer_psks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id  UUID NOT NULL REFERENCES wg_servers(id) ON DELETE CASCADE,
    client_id  UUID NOT NULL REFERENCES wg_clients(id) ON DELETE CASCADE,
    psk_enc    BYTEA NOT NULL,
    psk_nonce  BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, client_id)
);

CREATE INDEX idx_wg_peer_psks_server ON wg_peer_psks(server_id);
CREATE INDEX idx_wg_peer_psks_client ON wg_peer_psks(client_id);
