-- Public cycle references; original metadata tags and vector IDs are preserved.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT coalesce(jsonb_agg(jsonb_build_object(
 'run_id',run_id,'memory_id',memory_id,'owner',owner,'namespace',namespace,
 'ciphertext_sha256',ciphertext_sha256,'ciphertext_bytes',ciphertext_bytes,
 'source_metadata',source_metadata,'source_blob_id',source_blob_id,'source_object_id',source_object_id,
 'source_end_epoch',source_end_epoch,'current_object_id',current_object_id,'current_end_epoch',current_end_epoch,'stage',stage,
 'vector_entry_id',vector_entry_id,'parent_run_id',parent_run_id,'parent_memory_id',parent_memory_id,
 'origin_run_id',origin_run_id,'origin_memory_id',origin_memory_id,'provenance_run_id',provenance_run_id,'source_provenance',source_provenance
 ) ORDER BY memory_id),'[]'::jsonb) FROM exercise_renewal_memories WHERE run_id=:'run_id';
ROLLBACK;
