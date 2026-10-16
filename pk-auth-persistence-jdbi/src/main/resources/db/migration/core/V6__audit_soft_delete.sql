-- SPDX-License-Identifier: MIT
--
-- Audit trail and soft-delete support.
-- Adds revoked_at / revoked_reason to backup_codes and credentials,
-- and introduces pkauth_audit_events for append-only event records.

ALTER TABLE backup_codes
    ADD COLUMN revoked_at     TIMESTAMPTZ,
    ADD COLUMN revoked_reason VARCHAR(64);

ALTER TABLE credentials
    ADD COLUMN revoked_at     TIMESTAMPTZ,
    ADD COLUMN revoked_reason VARCHAR(64);

CREATE TABLE pkauth_audit_events (
    id           BIGSERIAL     PRIMARY KEY,
    occurred_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    event_type   VARCHAR(64)   NOT NULL,
    user_handle  BYTEA,
    subject_id   VARCHAR(255),
    detail       TEXT
);

CREATE INDEX pkauth_audit_events_occurred_at_idx
    ON pkauth_audit_events (occurred_at);

CREATE INDEX pkauth_audit_events_type_occurred_at_idx
    ON pkauth_audit_events (event_type, occurred_at);
