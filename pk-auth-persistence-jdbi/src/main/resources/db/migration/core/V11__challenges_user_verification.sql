-- SPDX-License-Identifier: MIT
--
-- Persist the user-verification requirement resolved at ceremony start so the finish step can
-- enforce a per-request REQUIRED server-side (rather than silently falling back to the global
-- ceremony config). Nullable: legacy/in-flight rows and callers that record no resolved
-- requirement leave it NULL, in which case the finish step enforces only the global config.

ALTER TABLE challenges
    ADD COLUMN user_verification TEXT
        CHECK (user_verification IN ('REQUIRED', 'PREFERRED', 'DISCOURAGED'));
