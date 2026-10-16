-- SPDX-License-Identifier: MIT
--
-- Example `users` table. Per brief §6.6, this schema is documented as host-app data — pk-auth
-- does not own the users table. It ships with the JDBI module so the reference JdbiUserLookup,
-- the demo apps, and the integration tests have a place to read from.
--
-- Numbered V5 to leave V3 / V4 reserved for the Phase 6 backup-code / OTP tables (brief §10).

CREATE TABLE users (
    user_handle      BYTEA       PRIMARY KEY,
    username         TEXT        NOT NULL UNIQUE,
    display_name     TEXT        NOT NULL,
    email_verified   BOOLEAN     NOT NULL DEFAULT FALSE,
    phone_verified   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
