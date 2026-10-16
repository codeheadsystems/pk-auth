-- SPDX-License-Identifier: MIT
--
-- pk-auth SMS-OTP records. Plaintext code never persisted; only the Argon2id hash.

CREATE TABLE otp_codes (
    otp_id        TEXT        PRIMARY KEY,
    user_handle   BYTEA       NOT NULL,
    phone_e164    TEXT        NOT NULL,
    hashed_code   TEXT        NOT NULL,
    attempts      INT         NOT NULL DEFAULT 0,
    max_attempts  INT         NOT NULL,
    consumed      BOOLEAN     NOT NULL DEFAULT FALSE,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX otp_codes_user_phone_created_idx ON otp_codes (user_handle, phone_e164, created_at);
