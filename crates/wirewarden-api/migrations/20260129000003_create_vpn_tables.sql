-- Networks
CREATE TABLE networks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    cidr_ip     INET NOT NULL,
    cidr_prefix INT  NOT NULL,
    owner_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    dns_servers TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT valid_prefix CHECK (cidr_prefix BETWEEN 8 AND 30)
);

-- Tokenized WireGuard key storage (private keys encrypted at rest)
CREATE TABLE wg_keys (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    private_key_enc   BYTEA  NOT NULL,
    private_key_nonce BYTEA  NOT NULL,
    public_key        TEXT   NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WireGuard servers
CREATE TABLE wg_servers (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id                UUID NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    name                      TEXT NOT NULL,
    key_id                    UUID NOT NULL REFERENCES wg_keys(id),
    api_token                 TEXT NOT NULL UNIQUE,
    address_offset            INT  NOT NULL,
    forwards_internet_traffic BOOL NOT NULL DEFAULT false,
    endpoint_host             TEXT,
    endpoint_port             INT  NOT NULL DEFAULT 51820,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT positive_offset CHECK (address_offset > 0),
    CONSTRAINT valid_port CHECK (endpoint_port BETWEEN 1 AND 65535),
    UNIQUE (network_id, address_offset),
    UNIQUE (network_id, name)
);

-- WireGuard clients
CREATE TABLE wg_clients (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id     UUID NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    key_id         UUID NOT NULL REFERENCES wg_keys(id),
    address_offset INT  NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT positive_offset CHECK (address_offset > 0),
    UNIQUE (network_id, address_offset),
    UNIQUE (network_id, name)
);

-- Server route advertisements
CREATE TABLE wg_server_routes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id  UUID NOT NULL REFERENCES wg_servers(id) ON DELETE CASCADE,
    route_cidr CIDR NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, route_cidr)
);
