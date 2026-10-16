-- SPDX-License-Identifier: MIT
--
-- Switches credentials from soft-delete to hard-delete.
-- Audit history for credential deletions now lives in the host's structured
-- log pipeline as a `pkauth.credential.deleted` event emitted by the service
-- layer (DefaultAdminService.deleteCredential). The credentials table no
-- longer needs revoked_at / revoked_reason columns.
--
-- This migration does NOT touch the backup_codes columns of the same name:
-- those are still in active use for consume / regenerate-all soft-delete.

ALTER TABLE credentials
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS revoked_reason;
