-- Original vector identities and immutable original-source provenance before/after a cycle.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL TIME ZONE 'UTC';
WITH m AS (SELECT * FROM exercise_renewal_memories WHERE run_id=:'run_id'), rows AS (
 SELECT m.memory_id,v.id,md5(jsonb_build_object(
 'vector',jsonb_build_object('id',v.id,'owner',v.owner,'namespace',v.namespace,'blob_id',v.blob_id,
 'embedding',v.embedding::text,'blob_size_bytes',v.blob_size_bytes,'importance',v.importance,'agent_id',v.agent_id,
 'package_id',v.package_id,'created_at',v.created_at,'plaintext',v.plaintext),
 'origin',jsonb_build_object('run_id',parent.run_id,'memory_id',parent.memory_id,'owner',parent.owner,'account_id',parent.account_id,
 'namespace',parent.namespace,'source_blob_id',parent.source_blob_id,'source_object_id',parent.source_object_id,
 'source_end_epoch',parent.source_end_epoch,'source_metadata',parent.source_metadata,'plaintext_sha256',parent.plaintext_sha256,
 'ciphertext_sha256',parent.ciphertext_sha256,'created_at',parent.created_at),
 'cycle_source',jsonb_build_object('vector_entry_id',m.vector_entry_id,'parent_run_id',m.parent_run_id,'parent_memory_id',m.parent_memory_id,
 'origin_run_id',m.origin_run_id,'origin_memory_id',m.origin_memory_id,'provenance_run_id',m.provenance_run_id,
 'source_object_id',m.source_object_id,'source_end_epoch',m.source_end_epoch,'source_metadata',m.source_metadata,'source_provenance',m.source_provenance)
 )::text) stable_hash,v.created_at,v.updated_at,v.end_epoch,v.expires_at,v.expiry_synced_at,v.metadata_synced_at
 FROM m JOIN vector_entries v ON v.id=m.vector_entry_id
 JOIN exercise_renewal_memories parent ON parent.run_id=m.parent_run_id AND parent.memory_id=m.parent_memory_id
) SELECT jsonb_build_object('run_id',:'run_id','expected_count',:'expected_count'::integer,
 'catalog_count',(SELECT count(*) FROM m),'vector_count',count(*),'vector_total_count',(SELECT count(*) FROM vector_entries),
 'stable_fingerprint',md5(string_agg(id||':'||stable_hash,E'\n' ORDER BY id)),
 'rows',coalesce(jsonb_agg(to_jsonb(rows) ORDER BY memory_id),'[]'::jsonb)) FROM rows;
ROLLBACK;
