-- Drop the legacy account-wide idempotency index (#1170, #1225, #1312).
-- Idempotency keys are scoped per (owner, namespace) by
-- uq_remember_jobs_owner_namespace_idempotency_key (migration 013).
--
-- Own file: DROP INDEX CONCURRENTLY cannot run inside a transaction block
-- and avoids taking ACCESS EXCLUSIVE lock on remember_jobs at boot.
DROP INDEX CONCURRENTLY IF EXISTS uq_remember_jobs_owner_idempotency_key;
