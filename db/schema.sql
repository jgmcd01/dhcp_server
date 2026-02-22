CREATE TABLE IF NOT EXISTS dhcp_leases (
  lease_id BIGSERIAL PRIMARY KEY,
  ip_version SMALLINT NOT NULL CHECK (ip_version IN (4, 6)),
  address INET NOT NULL,
  client_id TEXT NOT NULL,
  mac_address TEXT,
  duid TEXT,
  iaid BIGINT,
  hostname TEXT,
  subnet_cidr CIDR NOT NULL,
  lease_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  lease_end TIMESTAMPTZ NOT NULL,
  state TEXT NOT NULL DEFAULT 'active',
  node_id TEXT NOT NULL,
  user_context JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (ip_version, address)
);

CREATE INDEX IF NOT EXISTS idx_dhcp_leases_client_id ON dhcp_leases (client_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_mac ON dhcp_leases (mac_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_duid ON dhcp_leases (duid);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_time ON dhcp_leases (lease_start, lease_end);

CREATE TABLE IF NOT EXISTS lease_event_log (
  event_id BIGSERIAL PRIMARY KEY,
  event_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  op TEXT NOT NULL,
  lease_pk TEXT NOT NULL,
  source_node TEXT NOT NULL,
  payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS dhcp_subnets (
  subnet_id BIGSERIAL PRIMARY KEY,
  ip_version SMALLINT NOT NULL CHECK (ip_version IN (4, 6)),
  name TEXT NOT NULL UNIQUE,
  subnet_cidr CIDR NOT NULL UNIQUE,
  router INET,
  dns_servers TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  lease_seconds INTEGER NOT NULL DEFAULT 3600,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dhcp_pools (
  pool_id BIGSERIAL PRIMARY KEY,
  subnet_id BIGINT NOT NULL REFERENCES dhcp_subnets(subnet_id) ON DELETE CASCADE,
  pool_start INET NOT NULL,
  pool_end INET NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_users (
  user_id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dhcp_server_status (
  node_id TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  interface TEXT NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb
);
