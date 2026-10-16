-- SPDX-License-Identifier: MIT
--
-- Stateful access-token storage (per ADR 0015). One row per issued JWT JTI; presence on lookup
-- equals "valid". Deletion (logout, admin revoke, user delete) invalidates the bearer
-- immediately, well before its exp claim.
--
-- Hosts that prefer stateless JWT behaviour wire AccessTokenStore.noop() and never INSERT here;
-- the table can stay empty without affecting validation.

CREATE TABLE access_tokens (
    jti          VARCHAR(64)  NOT NULL PRIMARY KEY,
    user_handle  BYTEA        NOT NULL,
    audience     VARCHAR(64)  NOT NULL,
    device_id    VARCHAR(128),
    issued_at    TIMESTAMPTZ  NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL
);

CREATE INDEX access_tokens_user_handle_idx ON access_tokens (user_handle);
CREATE INDEX access_tokens_expires_at_idx  ON access_tokens (expires_at);
