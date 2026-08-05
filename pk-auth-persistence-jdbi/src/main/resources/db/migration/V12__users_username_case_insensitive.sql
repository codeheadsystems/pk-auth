-- SPDX-License-Identifier: MIT
--
-- Make username uniqueness case-insensitive, matching DynamoDbUserLookup.
--
-- Background: DynamoDbUserLookup keys identity on `USERNAME#<lower(username)>`, so on that backend
-- "Admin" and "admin" are one account. The JDBI reference implementation matched usernames exactly
-- against a plain `UNIQUE` constraint, so on Postgres they were two. Same library, same SPI, two
-- identity models — a host that assumed the DynamoDB semantics (or migrated between backends) could
-- end up with look-alike accounts.
--
-- The pre-flight below is the point of this migration being guarded: collapsing the namespace on a
-- database that ALREADY contains case-duplicate usernames is not something a schema change can
-- decide. Which of "Admin" and "admin" is the real account, and what happens to the other one's
-- credentials, is a business call. So we refuse to proceed and name the offending rows rather than
-- failing on an opaque duplicate-key error from the index build, or worse, silently picking one.

DO $$
DECLARE
    conflicts TEXT;
BEGIN
    SELECT string_agg(detail, '; ' ORDER BY detail)
      INTO conflicts
      FROM (
          SELECT lower(username) || ' -> [' || string_agg(username, ', ' ORDER BY username) || ']'
                 AS detail
            FROM users
        GROUP BY lower(username)
          HAVING count(*) > 1
      ) AS dupes;

    IF conflicts IS NOT NULL THEN
        RAISE EXCEPTION
            'pk-auth V12 cannot make username uniqueness case-insensitive: % existing username(s) '
            'differ only by case. Conflicting groups: %. '
            'Resolve these first — decide which row is authoritative, migrate or delete the '
            'credentials belonging to the others (credentials.user_handle references users.'
            'user_handle), then re-run the migration.',
            (SELECT count(*) FROM (
                SELECT 1 FROM users GROUP BY lower(username) HAVING count(*) > 1
            ) AS c),
            conflicts;
    END IF;
END $$;

-- Case-insensitive uniqueness. The original `UNIQUE (username)` constraint from V5 is left in
-- place: it is strictly implied by this index (if lower(a) = lower(b) is unique, so is a = b) and
-- dropping it would buy nothing while adding a rewrite step to the upgrade.
--
-- The stored `username` keeps its original casing so display names round-trip unchanged; only
-- uniqueness and lookup are case-insensitive. This mirrors DynamoDB's UserItem, which stores the
-- username as supplied and lower-cases only the key.
CREATE UNIQUE INDEX users_username_lower_key ON users (lower(username));
