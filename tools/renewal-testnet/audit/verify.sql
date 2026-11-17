-- Read-only assertions after migration. All checks must pass; preserve JSON output.
-- psql -q -X -A -t -v ON_ERROR_STOP=1 -v run_id=RUN_ID \
--   -v expected_count=1000 -v expected_owners=2 -f independent-verify.sql
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL TIME ZONE 'UTC';
-- The security-delete feature creates its table outside the 28 base migrations.
-- Match the feature-off production search when that optional table is absent.
SELECT to_regclass('delete_blobs_tracking') IS NOT NULL AS has_security_delete \gset
\set delete_filter 'TRUE'
\set hidden_count '(SELECT 0::bigint)'
\if :has_security_delete
  \set delete_filter 'NOT EXISTS (SELECT 1 FROM delete_blobs_tracking d WHERE d.owner=target.owner AND d.blob_id=target.blob_id AND d.state IN ($$deleting$$,$$deleted$$,$$deleted_external$$))'
  \set hidden_count '(SELECT count(*) FROM delete_blobs_tracking d WHERE d.state IN ($$deleting$$,$$deleted$$,$$deleted_external$$) AND EXISTS (SELECT 1 FROM m WHERE d.owner=m.owner AND d.blob_id=m.source_blob_id))'
\endif
WITH cfg AS (
  SELECT :'run_id'::text run_id, :'expected_count'::bigint expected_count,
    :'expected_owners'::bigint expected_owners
), m AS (
  SELECT a.* FROM exercise_renewal_memories a, cfg WHERE a.run_id = cfg.run_id
), v AS (
  SELECT a.* FROM vector_entries a, cfg
  WHERE left(a.id, length(cfg.run_id) + 1) = cfg.run_id || ':'
), paired AS (
  SELECT m.*, v.id vector_id, v.owner vector_owner, v.namespace vector_namespace,
    v.blob_id vector_blob_id, v.end_epoch vector_end_epoch,
    v.blob_size_bytes, v.agent_id, v.package_id, v.plaintext,
    vector_dims(v.embedding) dimensions, v.created_at vector_created_at,
    v.updated_at, v.expiry_synced_at, v.metadata_synced_at, v.expires_at
  FROM m LEFT JOIN v ON v.id = m.run_id || ':' || m.memory_id
), j AS (
  SELECT a.* FROM exercise_renewal_journal a, cfg WHERE a.run_id = cfg.run_id
), commits AS (
  SELECT * FROM j WHERE phase = 'db_commit' AND state = 'finalized'
), unresolved AS (
  SELECT p.* FROM j p WHERE p.state = 'prepared'
    AND NOT EXISTS (
      SELECT 1 FROM j d WHERE d.memory_id = p.memory_id AND d.phase = p.phase
        AND d.state = 'finalized' AND d.payload->>'digest' = p.payload->>'digest'
    )
), checks(name, observed, expected) AS (
  SELECT 'catalog_count', count(*), (SELECT expected_count FROM cfg) FROM m
  UNION ALL SELECT 'vector_count', count(*), (SELECT expected_count FROM cfg) FROM v
  UNION ALL SELECT 'owner_count', count(DISTINCT owner), (SELECT expected_owners FROM cfg) FROM m
  UNION ALL SELECT 'source_blob_ids_unique', count(DISTINCT source_blob_id), (SELECT expected_count FROM cfg) FROM m
  UNION ALL SELECT 'source_object_ids_unique', count(DISTINCT source_object_id), (SELECT expected_count FROM cfg) FROM m
  UNION ALL SELECT 'current_object_ids_unique', count(DISTINCT current_object_id), (SELECT expected_count FROM cfg) FROM m
  UNION ALL SELECT 'migrated_rows', count(*), (SELECT expected_count FROM cfg)
    FROM m WHERE stage='migrated' AND migrated_at IS NOT NULL AND last_error IS NULL
  UNION ALL SELECT 'new_objects_and_longer_lease', count(*), (SELECT expected_count FROM cfg)
    FROM m WHERE current_object_id <> source_object_id AND current_end_epoch > source_end_epoch
  UNION ALL SELECT 'valid_hashes_and_sizes', count(*), (SELECT expected_count FROM cfg)
    FROM m WHERE plaintext_sha256 ~ '^[a-f0-9]{64}$' AND ciphertext_sha256 ~ '^[a-f0-9]{64}$'
      AND plaintext_bytes > 0 AND ciphertext_bytes > plaintext_bytes
  UNION ALL SELECT 'vector_ref_owner_namespace_epoch_size_match', count(*), (SELECT expected_count FROM cfg)
    FROM paired WHERE vector_id IS NOT NULL AND vector_owner=owner AND vector_namespace=namespace
      AND vector_blob_id=source_blob_id AND vector_end_epoch=current_end_epoch
      AND blob_size_bytes=ciphertext_bytes
  UNION ALL SELECT 'encrypted_vector_shape', count(*), (SELECT expected_count FROM cfg)
    FROM paired WHERE vector_id IS NOT NULL AND dimensions=1536 AND plaintext IS NULL
  UNION ALL SELECT 'pg_recall_self_vector_returns_original_blob_id', count(*), (SELECT expected_count FROM cfg)
    FROM m JOIN v query ON query.id=m.run_id || ':' || m.memory_id
    CROSS JOIN LATERAL (
      SELECT target.blob_id FROM vector_entries target
      WHERE target.owner=query.owner AND target.namespace=query.namespace
        AND :delete_filter
      ORDER BY target.embedding <=> query.embedding LIMIT 1
    ) result
    WHERE result.blob_id=m.source_blob_id
  UNION ALL SELECT 'metadata_provenance_matches_index', count(*), (SELECT expected_count FROM cfg)
    FROM paired WHERE source_metadata->>'memwal_owner'=owner
      AND source_metadata->>'memwal_namespace'=namespace
      AND source_metadata->>'memwal_package_id'=package_id
      AND source_metadata->>'memwal_agent_id'=agent_id
      AND source_metadata->>'exercise_run'=run_id
      AND source_metadata->>'exercise_memory'=memory_id::text
  UNION ALL SELECT 'fresh_sync_timestamps', count(*), (SELECT expected_count FROM cfg)
    FROM paired WHERE updated_at >= migrated_at AND expiry_synced_at >= migrated_at
      AND metadata_synced_at >= migrated_at AND vector_created_at < updated_at
  UNION ALL SELECT 'computed_expiry_present', count(*), (SELECT expected_count FROM cfg)
    FROM paired WHERE expires_at IS NOT NULL
  UNION ALL SELECT 'commit_receipt_count', count(*), (SELECT expected_count FROM cfg) FROM commits
  UNION ALL SELECT 'distinct_committed_memories', count(DISTINCT memory_id), (SELECT expected_count FROM cfg) FROM commits
  UNION ALL SELECT 'six_finalized_chain_phases_per_memory', count(*), (SELECT expected_count*6 FROM cfg)
    FROM j WHERE state='finalized' AND phase IN (
      'seed.register','seed.certify','seed.metadata_transfer',
      'renew.register','renew.certify','renew.metadata_transfer')
  UNION ALL SELECT 'distinct_memory_chain_phases', count(*), (SELECT expected_count*6 FROM cfg)
    FROM (SELECT memory_id,phase FROM j WHERE state='finalized' AND phase IN (
      'seed.register','seed.certify','seed.metadata_transfer',
      'renew.register','renew.certify','renew.metadata_transfer') GROUP BY memory_id,phase) d
  UNION ALL SELECT 'commit_receipts_match_mapping', count(*), (SELECT expected_count FROM cfg)
    FROM commits c JOIN m ON m.memory_id=c.memory_id
    WHERE c.payload->>'oldObjectId'=m.source_object_id AND c.payload->>'newObjectId'=m.current_object_id
      AND c.payload->>'oldBlobId'=m.source_blob_id AND c.payload->>'newBlobId'=m.source_blob_id
      AND (c.payload->>'oldEpoch')::integer=m.source_end_epoch
      AND (c.payload->>'newEpoch')::integer=m.current_end_epoch
      AND c.payload->>'hash'=m.ciphertext_sha256 AND (c.payload->>'memoryRows')::integer=1
  UNION ALL SELECT 'unresolved_prepared_transactions', count(*), 0 FROM unresolved
  UNION ALL SELECT 'missing_transaction_digests', count(*), 0 FROM j
    WHERE state IN ('prepared','finalized') AND phase <> 'db_commit'
      AND coalesce(payload->>'digest','')=''
  UNION ALL SELECT 'duplicate_vectors_for_blob_owner_namespace', count(*), 0
    FROM (SELECT owner,namespace,blob_id FROM v GROUP BY owner,namespace,blob_id HAVING count(*)<>1) d
  UNION ALL SELECT 'unexpected_or_missing_cohort_ids', count(*), 0
    FROM v FULL JOIN m ON v.id=m.run_id || ':' || m.memory_id
    WHERE v.id IS NULL OR m.memory_id IS NULL
  UNION ALL SELECT 'cohort_tombstones', count(*), 0 FROM memory_tombstones t
    WHERE EXISTS (SELECT 1 FROM m WHERE t.memory_id=m.run_id || ':' || m.memory_id
      OR (t.owner=m.owner AND t.namespace=m.namespace AND t.blob_id=m.source_blob_id))
  UNION ALL SELECT 'cohort_hidden_by_security_delete', :hidden_count, 0
)
SELECT jsonb_build_object(
  'run_id', (SELECT run_id FROM cfg),
  'security_delete_table_present', :'has_security_delete'::boolean,
  'all_passed', bool_and(observed=expected),
  'checks', jsonb_agg(jsonb_build_object('name',name,'observed',observed,'expected',expected,
    'passed',observed=expected) ORDER BY name),
  'owners', (SELECT jsonb_agg(x ORDER BY owner) FROM (
    SELECT owner,count(*) count FROM m GROUP BY owner
  ) x),
  'journal_finalized_counts', (SELECT jsonb_agg(x ORDER BY phase) FROM (
    SELECT phase,count(*) count FROM j WHERE state='finalized' GROUP BY phase
  ) x)
) FROM checks;
ROLLBACK;
