-- Export only synthetic payload references; no keys or customer data.
-- psql -q -X -A -t -v ON_ERROR_STOP=1 -v run_id=RUN_ID -v expected_count=1000 -f this-file.sql
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT coalesce(jsonb_agg(jsonb_build_object(
  'run_id',run_id, 'memory_id',memory_id, 'owner',owner, 'namespace',namespace,
  'ciphertext_sha256',ciphertext_sha256,
  'ciphertext_bytes',ciphertext_bytes, 'source_metadata',source_metadata,
  'source_blob_id',source_blob_id, 'source_object_id',source_object_id,
  'source_end_epoch',source_end_epoch,
  'current_object_id',current_object_id, 'current_end_epoch',current_end_epoch, 'stage',stage
) ORDER BY memory_id),'[]'::jsonb)
FROM exercise_renewal_memories WHERE run_id=:'run_id';
ROLLBACK;
