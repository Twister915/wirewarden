CREATE TABLE webauthn_challenges (
    session_id UUID PRIMARY KEY,
    state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
