-- Read-only stable-field snapshot: run once after seed and again after migration.
-- psql -q -X -A -t -v ON_ERROR_STOP=1 -v run_id=RUN_ID -f independent-snapshot.sql
-- Redirect stdout to separate before.json / after.json files. Compare
-- stable_fingerprint and each row's stable_hash; mutable timestamps are separate.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL TIME ZONE 'UTC';
WITH catalog AS (
  SELECT * FROM exercise_renewal_memories WHERE run_id = :'run_id'
), rows AS (
  SELECT m.memory_id, v.id,
    md5(jsonb_build_object(
      'id',v.id, 'owner',v.owner, 'namespace',v.namespace, 'blob_id',v.blob_id,
      'embedding',v.embedding::text, 'blob_size_bytes',v.blob_size_bytes,
      'importance',v.importance, 'agent_id',v.agent_id, 'package_id',v.package_id,
      'created_at',v.created_at, 'plaintext',v.plaintext
    )::text) AS stable_hash,
    v.created_at, v.updated_at, v.end_epoch, v.expires_at,
    v.expiry_synced_at, v.metadata_synced_at
  FROM catalog m JOIN vector_entries v ON v.id = m.run_id || ':' || m.memory_id
)
SELECT jsonb_build_object(
  'run_id', :'run_id',
  'expected_count', :'expected_count'::integer,
  'all_passed', count(*)=:'expected_count'::integer AND (SELECT count(*) FROM catalog)=:'expected_count'::integer,
  'catalog_count', (SELECT count(*) FROM catalog),
  'vector_count', count(*),
  'stable_fingerprint', md5(string_agg(id || ':' || stable_hash, E'\n' ORDER BY id)),
  'rows', coalesce(jsonb_agg(to_jsonb(rows) ORDER BY memory_id), '[]'::jsonb)
) FROM rows;
ROLLBACK;
