-- M3: Spamhaus DQS blacklist checks — shared query budget, result cache,
-- and per-domain sending-IP evidence.

-- One row per UTC day. Reservation is an atomic conditional upsert against a
-- ceiling set below the real DQS free-tier limit.
CREATE TABLE dqs_budget (
  day  TEXT    PRIMARY KEY,      -- YYYY-MM-DD (UTC)
  used INTEGER NOT NULL DEFAULT 0
);

-- Keyed by (zone, entity), not by domain: many domains share the same sending
-- IPs, so this cache is also the dedup layer that protects the budget.
CREATE TABLE dnsbl_cache (
  zone       TEXT    NOT NULL,   -- zen | dbl
  entity     TEXT    NOT NULL,   -- ip or domain
  status     TEXT    NOT NULL,   -- ok | listed
  listed     INTEGER NOT NULL,
  lists      TEXT    NOT NULL,   -- JSON array
  checked_at TEXT    NOT NULL,
  expires_at TEXT    NOT NULL,
  PRIMARY KEY (zone, entity)
);
CREATE INDEX idx_dnsbl_cache_expiry ON dnsbl_cache (expires_at);

-- Evidence for which IPs a domain sends from. `spf` IPs are re-discovered each
-- run; `manual` IPs are set via the admin API. Provider/RUA/IMAP sources come
-- in a later milestone.
CREATE TABLE domain_sending_ip (
  domain_id  INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
  ip         TEXT    NOT NULL,
  source     TEXT    NOT NULL,   -- spf | manual | provider | rua
  first_seen TEXT    NOT NULL,
  last_seen  TEXT    NOT NULL,
  PRIMARY KEY (domain_id, ip)
);
