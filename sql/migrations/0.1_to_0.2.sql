-- =============================================================================
-- adk-memshield: upgrade a 0.1.x database to the 0.2.0 schema
-- =============================================================================
-- Idempotent: safe to run more than once. Run as the table owner (or a superuser), in
-- one transaction, for example:
--   psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 --single-transaction -f sql/migrations/0.1_to_0.2.sql
--
-- What changes:
--   * memories.compartments TEXT[] NOT NULL DEFAULT '{}' (existing rows get '{}', so they
--     behave exactly as in 0.1.x) plus a GIN index;
--   * the four RLS policies are recreated with the compartment rules.
-- No data is rewritten and no row becomes visible to anyone who could not read it before.

ALTER TABLE memories ADD COLUMN IF NOT EXISTS compartments TEXT[] NOT NULL DEFAULT '{}';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'memories'::regclass AND conname = 'memories_compartments_check'
  ) THEN
    ALTER TABLE memories
      ADD CONSTRAINT memories_compartments_check CHECK (array_position(compartments, NULL) IS NULL);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_memories_compartments
    ON memories USING GIN (compartments);

ALTER TABLE memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE memories FORCE ROW LEVEL SECURITY;

-- Caller compartments are bound as a comma-separated list in app.agent_compartments.
-- adk-memshield validates names against ^[a-z0-9_-]{1,64}$ before binding, so a comma or
-- brace inside a name can never change how the list is parsed here.

-- Read: own rows (any scope, any compartments), plus tenant-shared rows at or below the
-- agent's clearance that carry no compartments or share one with the caller.
DROP POLICY IF EXISTS memories_isolation_select ON memories;
CREATE POLICY memories_isolation_select ON memories
    FOR SELECT
    TO memshield_app
    USING (
        app_name = current_setting('app.current_app_name', true)
        AND tenant_id = current_setting('app.current_tenant_id', true)
        AND (
            user_id = current_setting('app.current_user_id', true)
            OR (
                scope = 'tenant_shared'
                AND min_clearance <= COALESCE(NULLIF(current_setting('app.agent_clearance', true), '')::int, 1)
                AND (
                    cardinality(compartments) = 0
                    OR compartments && COALESCE(string_to_array(NULLIF(current_setting('app.agent_compartments', true), ''), ','), '{}'::text[])
                )
            )
        )
    );

-- Write: own rows only. A tenant_shared row may not be labelled above the writing
-- agent's clearance ("no write-up"), and no row may carry a compartment the writer does
-- not hold ("no write-across").
DROP POLICY IF EXISTS memories_isolation_insert ON memories;
CREATE POLICY memories_isolation_insert ON memories
    FOR INSERT
    TO memshield_app
    WITH CHECK (
        app_name = current_setting('app.current_app_name', true)
        AND tenant_id = current_setting('app.current_tenant_id', true)
        AND user_id = current_setting('app.current_user_id', true)
        AND (
            scope = 'private'
            OR min_clearance <= COALESCE(NULLIF(current_setting('app.agent_clearance', true), '')::int, 1)
        )
        AND compartments <@ COALESCE(string_to_array(NULLIF(current_setting('app.agent_compartments', true), ''), ','), '{}'::text[])
    );

DROP POLICY IF EXISTS memories_isolation_update ON memories;
CREATE POLICY memories_isolation_update ON memories
    FOR UPDATE
    TO memshield_app
    USING (
        app_name = current_setting('app.current_app_name', true)
        AND tenant_id = current_setting('app.current_tenant_id', true)
        AND user_id = current_setting('app.current_user_id', true)
    )
    WITH CHECK (
        app_name = current_setting('app.current_app_name', true)
        AND tenant_id = current_setting('app.current_tenant_id', true)
        AND user_id = current_setting('app.current_user_id', true)
        AND (
            scope = 'private'
            OR min_clearance <= COALESCE(NULLIF(current_setting('app.agent_clearance', true), '')::int, 1)
        )
        AND compartments <@ COALESCE(string_to_array(NULLIF(current_setting('app.agent_compartments', true), ''), ','), '{}'::text[])
    );

DROP POLICY IF EXISTS memories_isolation_delete ON memories;
CREATE POLICY memories_isolation_delete ON memories
    FOR DELETE
    TO memshield_app
    USING (
        app_name = current_setting('app.current_app_name', true)
        AND tenant_id = current_setting('app.current_tenant_id', true)
        AND user_id = current_setting('app.current_user_id', true)
    );
