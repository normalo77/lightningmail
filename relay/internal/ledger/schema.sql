-- bmail relay ledger, schema v1 (docs/spec.md §8.1).
-- Applied via PRAGMA user_version; must stay idempotent per step.

CREATE TABLE account (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  name           TEXT    NOT NULL UNIQUE,
  mailbox_pubkey BLOB    NOT NULL,
  recipient_hash BLOB    NOT NULL UNIQUE,
  balance_msat   INTEGER NOT NULL DEFAULT 0 CHECK (balance_msat >= 0),
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
