-- SPDX-License-Identifier: MIT
--
-- pk-auth in-flight challenge storage. Single-use semantics enforced by the takeOnce DELETE … RETURNING query.

CREATE TABLE challenges (
    id           TEXT        PRIMARY KEY,
    challenge    BYTEA       NOT NULL,
    purpose      TEXT        NOT NULL CHECK (purpose IN ('REGISTRATION', 'AUTHENTICATION')),
    user_handle  BYTEA,
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX challenges_expires_at_idx ON challenges (expires_at);
