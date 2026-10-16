-- SPDX-License-Identifier: MIT
--
-- Refresh tokens with family-based replay defense (ADR 0013).
--
-- Wire format is "{refreshId}.{secret}" — opaque to the client. token_hash = sha256(secret); the
-- secret itself is NEVER persisted. refresh_id is indexed (primary key) so lookup-on-rotate is
-- O(log n).
--
-- Family model: every rotation chain shares family_id (set equal to the root token's refresh_id
-- when the root is created). parent_refresh_id links a rotated successor back to the previous
-- token in the chain.
--
-- The load-bearing rotation primitive lives in JdbiRefreshTokenRepository.rotateAtomically: a
-- conditional UPDATE on the parent followed by an INSERT for the successor, both inside a single
-- JDBI transaction. The transaction is the single point of atomicity — without it, a concurrent
-- replay-revoker could miss the freshly-inserted successor between mark and insert.

CREATE TABLE refresh_tokens (
    refresh_id         VARCHAR(64)  NOT NULL PRIMARY KEY,
    token_hash         BYTEA        NOT NULL,
    user_handle        BYTEA        NOT NULL,
    audience           VARCHAR(64)  NOT NULL,
    device_id          VARCHAR(128),
    family_id          VARCHAR(64)  NOT NULL,
    parent_refresh_id  VARCHAR(64),
    issued_at          TIMESTAMPTZ  NOT NULL,
    expires_at         TIMESTAMPTZ  NOT NULL,
    used_at            TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    revoked_reason     VARCHAR(32)
);

CREATE INDEX refresh_tokens_user_handle_idx ON refresh_tokens (user_handle);
CREATE INDEX refresh_tokens_family_id_idx   ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_at_idx  ON refresh_tokens (expires_at);
