-- SPDX-License-Identifier: MIT
--
-- pk-auth credential storage. One row per registered passkey.

CREATE TABLE credentials (
    credential_id    BYTEA       PRIMARY KEY,
    user_handle      BYTEA       NOT NULL,
    public_key_cose  BYTEA       NOT NULL,
    sign_count       BIGINT      NOT NULL DEFAULT 0,
    label            TEXT        NOT NULL,
    aaguid           UUID,
    transports       TEXT[]      NOT NULL DEFAULT '{}',
    backup_eligible  BOOLEAN     NOT NULL DEFAULT FALSE,
    backup_state     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL,
    last_used_at     TIMESTAMPTZ
);

CREATE INDEX credentials_user_handle_idx ON credentials (user_handle);
