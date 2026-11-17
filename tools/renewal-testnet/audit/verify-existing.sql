-- Read-only migration-only audit. No vector rows are created by a renewal cycle.
\if :{?source_offset}
\else
  \set source_offset 0
\endif
\if :{?renew_mode}
\else
  \set renew_mode fused
\endif
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL TIME ZONE 'UTC';
SELECT to_regclass('delete_blobs_tracking') IS NOT NULL AS has_security_delete \gset
\set delete_filter 'TRUE'
\set hidden_count '(SELECT 0::bigint)'
\if :has_security_delete
 \set delete_filter 'NOT EXISTS (SELECT 1 FROM delete_blobs_tracking d WHERE d.owner=target.owner AND d.blob_id=target.blob_id AND d.state IN ($$deleting$$,$$deleted$$,$$deleted_external$$))'
 \set hidden_count '(SELECT count(*) FROM delete_blobs_tracking d WHERE d.state IN ($$deleting$$,$$deleted$$,$$deleted_external$$) AND EXISTS (SELECT 1 FROM m WHERE d.owner=m.owner AND d.blob_id=m.source_blob_id))'
\endif
WITH cfg AS (
 SELECT :'run_id'::text run_id, :'expected_count'::bigint expected_count,
 :'expected_owners'::bigint expected_owners, :'source_offset'::integer source_offset,
 :'renew_mode'::text renew_mode
), m AS (
 SELECT a.* FROM exercise_renewal_memories a,cfg WHERE a.run_id=cfg.run_id
), v AS (
 SELECT a.* FROM vector_entries a JOIN m ON a.id=m.vector_entry_id
), paired AS (
 SELECT m.*,v.id vector_id,v.owner vector_owner,v.namespace vector_namespace,
 v.blob_id vector_blob_id,v.end_epoch vector_end_epoch,v.blob_size_bytes,
 v.agent_id,v.package_id,v.plaintext,vector_dims(v.embedding) dimensions,
 v.created_at vector_created_at,v.updated_at,v.expiry_synced_at,v.metadata_synced_at,v.expires_at,
 parent.run_id found_parent_run,parent.memory_id found_parent_memory, parent.parent_run_id parent_parent_run,
 parent.current_object_id parent_current_object,parent.current_end_epoch parent_current_end,
 parent.source_object_id parent_original_source_object,parent.source_end_epoch parent_original_source_end,
 parent.ciphertext_sha256 parent_ciphertext_sha256,parent.owner parent_owner,parent.account_id parent_account,
 parent.namespace parent_namespace
 FROM m LEFT JOIN v ON v.id=m.vector_entry_id
 LEFT JOIN exercise_renewal_memories parent ON parent.run_id=m.parent_run_id AND parent.memory_id=m.parent_memory_id
), j AS (
 SELECT a.* FROM exercise_renewal_journal a,cfg WHERE a.run_id=cfg.run_id
), commits AS (SELECT * FROM j WHERE phase='db_commit' AND state='finalized'),
 plans AS (SELECT * FROM j WHERE phase='renew.lease_plan' AND state='planned'),
 unresolved AS (
 SELECT p.* FROM j p WHERE p.state='prepared' AND NOT EXISTS (
 SELECT 1 FROM j d WHERE d.memory_id=p.memory_id AND d.phase=p.phase AND d.state='finalized'
 AND d.payload->>'digest'=p.payload->>'digest')
), checks(name,observed,expected) AS (
SELECT 'catalog_count',(SELECT count(*) FROM m),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'distinct_vector_references',(SELECT count(DISTINCT vector_entry_id) FROM m),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'owner_count',(SELECT count(DISTINCT owner) FROM m),(SELECT expected_owners FROM cfg)
 UNION ALL SELECT 'dense_cycle_memory_ids',(SELECT count(*) FROM m,cfg WHERE memory_id>=0 AND memory_id<expected_count),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'canonical_parent_origin_links',(SELECT count(*) FROM paired,cfg WHERE found_parent_run=parent_run_id AND found_parent_memory=parent_memory_id AND parent_parent_run IS NULL AND origin_run_id=parent_run_id AND origin_memory_id=parent_memory_id AND parent_memory_id=memory_id+source_offset AND vector_entry_id=origin_run_id||':'||origin_memory_id AND provenance_run_id=origin_run_id AND parent_ciphertext_sha256=ciphertext_sha256 AND parent_owner=owner AND parent_account=account_id AND parent_namespace=namespace AND jsonb_typeof(source_provenance)='object'),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'no_child_vector_rows',(SELECT count(*) FROM vector_entries a,cfg WHERE left(a.id,length(cfg.run_id)+1)=cfg.run_id||':'),(SELECT 0)
 UNION ALL SELECT 'encrypted_vector_identity',(SELECT count(*) FROM paired WHERE vector_id=vector_entry_id AND vector_owner=owner AND vector_namespace=namespace AND vector_blob_id=source_blob_id AND blob_size_bytes=ciphertext_bytes AND dimensions=1536 AND plaintext IS NULL),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'metadata_original_provenance',(SELECT count(*) FROM paired WHERE source_metadata->>'memwal_owner'=owner AND source_metadata->>'memwal_namespace'=namespace AND source_metadata->>'memwal_package_id'=package_id AND source_metadata->>'memwal_agent_id'=agent_id AND source_metadata->>'exercise_run'=provenance_run_id AND source_metadata->>'exercise_memory'=origin_memory_id::text),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'source_object_ids_unique',(SELECT count(DISTINCT source_object_id) FROM m),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'source_content_ids_unique',(SELECT count(DISTINCT source_blob_id) FROM m),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'valid_hashes_and_sizes',(SELECT count(*) FROM m WHERE plaintext_sha256~'^[a-f0-9]{64}$' AND ciphertext_sha256~'^[a-f0-9]{64}$' AND plaintext_bytes>0 AND ciphertext_bytes>plaintext_bytes),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'unresolved_prepared_transactions',(SELECT count(*) FROM unresolved),(SELECT 0)
 UNION ALL SELECT 'no_seed_or_setup_transactions',(SELECT count(*) FROM j WHERE state IN ('prepared','finalized') AND (phase LIKE 'seed.%' OR phase IN ('fund_owners','create_account'))),(SELECT 0)
 UNION ALL SELECT 'cohort_tombstones',(SELECT count(*) FROM memory_tombstones t WHERE EXISTS (SELECT 1 FROM m WHERE t.memory_id=m.vector_entry_id OR (t.owner=m.owner AND t.namespace=m.namespace AND t.blob_id=m.source_blob_id))),(SELECT 0)
 UNION ALL SELECT 'all_migrated',(SELECT count(*) FROM m WHERE stage='migrated' AND migrated_at IS NOT NULL AND last_error IS NULL),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'new_objects_and_later_leases',(SELECT count(*) FROM paired WHERE current_object_id<>source_object_id AND current_end_epoch>source_end_epoch AND parent_current_object=current_object_id AND parent_current_end=current_end_epoch AND vector_end_epoch=current_end_epoch),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'unique_output_objects',(SELECT count(DISTINCT current_object_id) FROM m),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'source_output_sets_disjoint',(SELECT count(*) FROM m a JOIN m b ON a.source_object_id=b.current_object_id),(SELECT 0)
 UNION ALL SELECT 'exact_mode_transaction_count',(SELECT count(*) FROM j,cfg WHERE state='finalized' AND (phase='renew.register' OR (renew_mode='fused' AND phase='renew.certify_transfer') OR (renew_mode='unfused' AND phase IN ('renew.certify','renew.metadata_transfer')))),(SELECT expected_count*CASE WHEN renew_mode='fused' THEN 2 ELSE 3 END FROM cfg)
 UNION ALL SELECT 'distinct_mode_memory_phases',(SELECT count(*) FROM (SELECT memory_id,phase FROM j,cfg WHERE state='finalized' AND (phase='renew.register' OR (renew_mode='fused' AND phase='renew.certify_transfer') OR (renew_mode='unfused' AND phase IN ('renew.certify','renew.metadata_transfer'))) GROUP BY memory_id,phase) a),(SELECT expected_count*CASE WHEN renew_mode='fused' THEN 2 ELSE 3 END FROM cfg)
 UNION ALL SELECT 'no_unexpected_chain_phase',(SELECT count(*) FROM j,cfg WHERE state='finalized' AND payload ? 'digest' AND NOT (phase='renew.register' OR (renew_mode='fused' AND phase='renew.certify_transfer') OR (renew_mode='unfused' AND phase IN ('renew.certify','renew.metadata_transfer')))),(SELECT 0)
 UNION ALL SELECT 'commit_count',(SELECT count(*) FROM commits),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'unique_committed_memories',(SELECT count(DISTINCT memory_id) FROM commits),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'commit_maps_to_original_vector',(SELECT count(*) FROM commits c JOIN m ON m.memory_id=c.memory_id WHERE c.payload->>'oldObjectId'=m.source_object_id AND c.payload->>'newObjectId'=m.current_object_id AND c.payload->>'oldBlobId'=m.source_blob_id AND c.payload->>'newBlobId'=m.source_blob_id AND (c.payload->>'oldEpoch')::integer=m.source_end_epoch AND (c.payload->>'newEpoch')::integer=m.current_end_epoch AND c.payload->>'hash'=m.ciphertext_sha256 AND (c.payload->>'memoryRows')::integer=1 AND c.payload->>'vectorEntryId'=m.vector_entry_id AND c.payload->>'parentRunId'=m.parent_run_id AND (c.payload->>'parentMemoryId')::integer=m.parent_memory_id),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'one_lease_plan_per_memory',(SELECT count(*) FROM plans),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'lease_plan_exact_input_target',(SELECT count(*) FROM plans p JOIN m ON p.memory_id=m.memory_id WHERE p.payload->>'inputObjectId'=m.source_object_id AND (p.payload->>'inputEndEpoch')::integer=m.source_end_epoch AND (p.payload->>'requestedEpochs')::integer BETWEEN 1 AND 53 AND (p.payload->>'currentEpoch')::integer+(p.payload->>'requestedEpochs')::integer=(p.payload->>'targetEndEpoch')::integer AND (p.payload->>'targetEndEpoch')::integer>m.source_end_epoch AND m.current_end_epoch>=(p.payload->>'targetEndEpoch')::integer),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'fresh_expiry_sync',(SELECT count(*) FROM paired WHERE expires_at IS NOT NULL AND updated_at>=migrated_at AND expiry_synced_at>=migrated_at AND metadata_synced_at>=migrated_at),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'pg_original_vector_recall',
 (SELECT count(*) FROM m JOIN v query ON query.id=m.vector_entry_id CROSS JOIN LATERAL (
 SELECT target.blob_id FROM vector_entries target WHERE target.owner=query.owner AND target.namespace=query.namespace AND :delete_filter
 ORDER BY target.embedding <=> query.embedding LIMIT 1) result WHERE result.blob_id=m.source_blob_id),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'security_delete_not_hidden',:hidden_count,0

 UNION ALL SELECT 'distinct_lease_planned_memories',(SELECT count(DISTINCT memory_id) FROM plans),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'register_count',(SELECT count(*) FROM j WHERE state='finalized' AND phase='renew.register'),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'fused_or_certify_count',(SELECT count(*) FROM j,cfg WHERE state='finalized' AND phase=CASE WHEN renew_mode='fused' THEN 'renew.certify_transfer' ELSE 'renew.certify' END),(SELECT expected_count FROM cfg)
 UNION ALL SELECT 'unfused_transfer_count',(SELECT count(*) FROM j WHERE state='finalized' AND phase='renew.metadata_transfer'),(SELECT CASE WHEN renew_mode='unfused' THEN expected_count ELSE 0 END FROM cfg)
 UNION ALL SELECT 'unknown_receipt_memory',(SELECT count(*) FROM j LEFT JOIN m ON m.memory_id=j.memory_id WHERE j.state='finalized' AND j.payload ? 'digest' AND m.memory_id IS NULL),0

 UNION ALL SELECT 'one_canonical_root',(SELECT count(DISTINCT parent_run_id) FROM m),1
 UNION ALL SELECT 'canonical_root_inventory_complete',(SELECT count(*) FROM exercise_renewal_memories p WHERE p.run_id IN (SELECT DISTINCT parent_run_id FROM m) AND (p.parent_run_id IS NOT NULL OR p.stage<>'migrated')),0
) SELECT jsonb_build_object('run_id',:'run_id','scope','migration-only cycle; original vector identities and parent CAS','all_passed',bool_and(observed=expected),'checks',jsonb_agg(jsonb_build_object('name',name,'observed',observed,'expected',expected,'passed',observed=expected) ORDER BY name)) FROM checks;
ROLLBACK;
