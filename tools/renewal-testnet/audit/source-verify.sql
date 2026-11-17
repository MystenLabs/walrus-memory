-- Read-only source-complete gate; deliberately does not assert migration completion.
-- psql -qXAt -v ON_ERROR_STOP=1 -v run_id=RUN_ID -v expected_count=1000 -v expected_owners=2 -f this-file.sql
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH cfg AS (
  SELECT :'run_id'::text run_id, :'expected_count'::bigint expected_count,
    :'expected_owners'::bigint expected_owners
), m AS (
  SELECT a.* FROM exercise_renewal_memories a,cfg WHERE a.run_id=cfg.run_id
), v AS (
  SELECT a.* FROM vector_entries a,cfg
  WHERE left(a.id,length(cfg.run_id)+1)=cfg.run_id || ':'
), paired AS (
  SELECT m.*,v.id vector_id,v.owner vector_owner,v.namespace vector_namespace,
    v.blob_id,v.blob_size_bytes,v.end_epoch,v.expires_at,v.plaintext,
    v.agent_id,v.package_id,v.embedding,v.expiry_synced_at,v.metadata_synced_at
  FROM m LEFT JOIN v ON v.id=m.run_id || ':' || m.memory_id
), j AS (
  SELECT a.* FROM exercise_renewal_journal a,cfg WHERE a.run_id=cfg.run_id
), checks(name,observed,expected) AS (
  SELECT 'catalog_count',count(*),(SELECT expected_count FROM cfg) FROM m
  UNION ALL SELECT 'vector_count',count(*),(SELECT expected_count FROM cfg) FROM v
  UNION ALL SELECT 'owner_count',count(DISTINCT owner),(SELECT expected_owners FROM cfg) FROM m
  UNION ALL SELECT 'unique_source_blob_ids',count(DISTINCT source_blob_id),(SELECT expected_count FROM cfg) FROM m
  UNION ALL SELECT 'unique_source_object_ids',count(DISTINCT source_object_id),(SELECT expected_count FROM cfg) FROM m
  UNION ALL SELECT 'all_seeded_unmigrated',count(*),(SELECT expected_count FROM cfg)
    FROM m WHERE stage='seeded' AND migrated_at IS NULL AND last_error IS NULL
      AND current_object_id=source_object_id AND current_end_epoch=source_end_epoch
  UNION ALL SELECT 'matching_existing_vector_rows',count(*),(SELECT expected_count FROM cfg)
    FROM paired WHERE vector_id IS NOT NULL AND vector_owner=owner AND vector_namespace=namespace
      AND blob_id=source_blob_id AND blob_size_bytes=ciphertext_bytes AND end_epoch=source_end_epoch
  UNION ALL SELECT 'valid_encrypted_vector_shape',count(*),(SELECT expected_count FROM cfg)
    FROM paired WHERE plaintext IS NULL AND vector_dims(embedding)=1536
      AND expires_at IS NOT NULL AND expiry_synced_at IS NOT NULL AND metadata_synced_at IS NOT NULL
  UNION ALL SELECT 'metadata_provenance_agrees',count(*),(SELECT expected_count FROM cfg)
    FROM paired WHERE source_metadata->>'memwal_owner'=owner
      AND source_metadata->>'memwal_namespace'=namespace
      AND source_metadata->>'memwal_agent_id'=agent_id
      AND source_metadata->>'memwal_package_id'=package_id
      AND source_metadata->>'exercise_run'=run_id
      AND source_metadata->>'exercise_memory'=memory_id::text
  UNION ALL SELECT 'source_self_vector_recall',count(*),(SELECT expected_count FROM cfg)
    FROM paired query CROSS JOIN LATERAL (
      SELECT target.blob_id FROM vector_entries target
      WHERE target.owner=query.owner AND target.namespace=query.namespace
      ORDER BY target.embedding <=> query.embedding LIMIT 1
    ) result WHERE result.blob_id=query.source_blob_id
  UNION ALL SELECT 'source_finalized_chain_transactions',count(*),(SELECT expected_count*3 FROM cfg)
    FROM j WHERE state='finalized' AND phase IN ('seed.register','seed.certify','seed.metadata_transfer')
  UNION ALL SELECT 'source_distinct_memory_phases',count(*),(SELECT expected_count*3 FROM cfg)
    FROM (SELECT memory_id,phase FROM j WHERE state='finalized'
      AND phase IN ('seed.register','seed.certify','seed.metadata_transfer') GROUP BY memory_id,phase) d
  UNION ALL SELECT 'unresolved_prepared_transactions',count(*),0 FROM j p WHERE p.state='prepared'
    AND NOT EXISTS (SELECT 1 FROM j d WHERE d.memory_id=p.memory_id AND d.phase=p.phase
      AND d.state='finalized' AND d.payload->>'digest'=p.payload->>'digest')
  UNION ALL SELECT 'premature_db_commit_receipts',count(*),0 FROM j WHERE phase='db_commit'
  UNION ALL SELECT 'cohort_tombstones',count(*),0 FROM memory_tombstones t
    WHERE EXISTS (SELECT 1 FROM m WHERE t.memory_id=m.run_id || ':' || m.memory_id
      OR (t.owner=m.owner AND t.namespace=m.namespace AND t.blob_id=m.source_blob_id))
)
SELECT jsonb_build_object('run_id',(SELECT run_id FROM cfg),'scope','source complete before migration',
  'all_passed',bool_and(observed=expected),
  'checks',jsonb_agg(jsonb_build_object('name',name,'observed',observed,'expected',expected,
    'passed',observed=expected) ORDER BY name)) FROM checks;
ROLLBACK;
