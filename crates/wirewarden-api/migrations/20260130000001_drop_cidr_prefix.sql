-- Remove redundant cidr_prefix column; the prefix is already encoded in cidr_ip (INET).
ALTER TABLE networks DROP CONSTRAINT valid_prefix;
ALTER TABLE networks DROP COLUMN cidr_prefix;
ALTER TABLE networks ADD CONSTRAINT valid_prefix
    CHECK (masklen(cidr_ip) BETWEEN 8 AND 30);
