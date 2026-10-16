-- SPDX-License-Identifier: MIT
--
-- pk-auth backup-code hashes. One row per issued code; plaintext is never stored.

CREATE TABLE backup_codes (
    code_id      TEXT        PRIMARY KEY,
    user_handle  BYTEA       NOT NULL,
    hashed_code  TEXT        NOT NULL,
    consumed     BOOLEAN     NOT NULL DEFAULT FALSE,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX backup_codes_user_handle_idx ON backup_codes (user_handle);
