CREATE TABLE user_passkeys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    passkey_name    TEXT NOT NULL,
    credential_id   BYTEA NOT NULL UNIQUE,
    public_key      BYTEA NOT NULL,
    sign_count      BIGINT NOT NULL DEFAULT 0,
    transports      JSONB,
    aaguid          UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_user_passkeys_user_id ON user_passkeys(user_id);
CREATE INDEX idx_user_passkeys_credential_id ON user_passkeys(credential_id);
