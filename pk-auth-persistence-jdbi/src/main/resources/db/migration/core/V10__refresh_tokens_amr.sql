-- SPDX-License-Identifier: MIT
--
-- 1.3.0: carry the original authentication method references (RFC 8176 "amr") through refresh
-- rotation, so an access token minted from a refresh reflects how the session was first
-- established (e.g. "pkauth,webauthn") instead of a generic marker.
--
-- Stored as a comma-separated string of method tokens (amr entries are simple RFC 8176 references
-- and never contain a comma; see RefreshTokenRecord). Rows created before this column existed
-- predate the feature and are defaulted to the generic 'user' marker, matching the legacy behavior
-- of RefreshHandler.

ALTER TABLE refresh_tokens
    ADD COLUMN amr VARCHAR(255) NOT NULL DEFAULT 'user';
