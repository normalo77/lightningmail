-- bmail relay ledger, schema v3 (docs/spec.md §8.1, Etappe 4a).
-- v3 adds: quota_bytes, auth_tokens table, blob_refs table.

CREATE TABLE account (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  name           TEXT    NOT NULL UNIQUE,
  mailbox_pubkey BLOB    NOT NULL,
  recipient_hash BLOB    NOT NULL UNIQUE,
  balance_msat   INTEGER NOT NULL DEFAULT 0 CHECK (balance_msat >= 0),
  quota_bytes    INTEGER NOT NULL DEFAULT 104857600,
  version        INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE TABLE txlog (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES account(id),
  delta_msat INTEGER NOT NULL,
  kind       TEXT    NOT NULL CHECK (kind IN
             ('postage_out','postage_in','topup','withdraw','fee')),
  ref        TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX txlog_account_idx ON txlog(account_id, id);

CREATE TABLE IF NOT EXISTS mailbox (
  msg_id       BLOB    NOT NULL PRIMARY KEY,
  account_id   INTEGER NOT NULL REFERENCES account(id),
  envelope     BLOB    NOT NULL,
  received_msat INTEGER NOT NULL DEFAULT 0,
  seq          INTEGER NOT NULL DEFAULT 0,
  seen         INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mailbox_account_seq_idx ON mailbox(account_id, seq);

CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash   BLOB    NOT NULL PRIMARY KEY,
  account_name TEXT    NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_tokens_account_idx ON auth_tokens(account_name);

CREATE TABLE IF NOT EXISTS blob_refs (
  sha256     BLOB    NOT NULL,
  account_id INTEGER NOT NULL REFERENCES account(id),
  bytes      INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (sha256, account_id)
);
CREATE INDEX IF NOT EXISTS blob_refs_account_idx ON blob_refs(account_id);
