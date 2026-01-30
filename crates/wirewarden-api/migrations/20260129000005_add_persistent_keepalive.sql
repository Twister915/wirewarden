ALTER TABLE networks ADD COLUMN persistent_keepalive INT NOT NULL DEFAULT 25;
ALTER TABLE networks ADD CONSTRAINT valid_keepalive CHECK (persistent_keepalive BETWEEN 0 AND 65535);
