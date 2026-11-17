"""Offline checks for spending-stage resume and the public one-click entry."""
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'renewal_orchestrate', Path(__file__).resolve().parents[1] / 'orchestrate.py')
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


SYNTHETIC_PUBLIC_KEY = base64.b64encode(bytes([0]) + bytes.fromhex(
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')).decode('ascii')
SYNTHETIC_ADDRESS = '0x304af458e90e97c841685b8cbbc59b909f3e2cf150df590ada4c81452c29737d'


class OneClickTests(unittest.TestCase):
    def test_operator_public_key_derives_sdk_verified_address(self):
        operator = tool.operator_from_values('synthetic-operator', SYNTHETIC_PUBLIC_KEY)
        self.assertEqual(operator['fundingAddress'], SYNTHETIC_ADDRESS)
        self.assertEqual(operator['fundingPublicKey'], SYNTHETIC_PUBLIC_KEY)
        for invalid in ('not-base64!', base64.b64encode(bytes(32)).decode('ascii'),
                        base64.b64encode(bytes([1]) + bytes(32)).decode('ascii')):
            with self.assertRaises(tool.Failure):
                tool.operator_from_values('synthetic-operator', invalid)
        with self.assertRaises(tool.Failure):
            tool.operator_from_values('--not-an-alias', SYNTHETIC_PUBLIC_KEY)

    def test_first_live_use_requires_both_public_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory) / 'local-state'
            with patch.object(tool, 'STATE_ROOT', state_root):
                for args in (SimpleNamespace(), SimpleNamespace(funding_alias='synthetic-operator'),
                             SimpleNamespace(funding_public_key=SYNTHETIC_PUBLIC_KEY)):
                    with self.assertRaises(tool.Failure):
                        tool.resolve_operator(args)
            self.assertFalse(state_root.exists())

    def test_local_operator_metadata_is_private_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            operator = tool.operator_from_values('synthetic-operator', SYNTHETIC_PUBLIC_KEY)
            tool.atomic_json(state_root / 'operator.json', dict(operator, schemaVersion=1))
            self.assertEqual((state_root / 'operator.json').stat().st_mode & 0o777, 0o600)
            with patch.object(tool, 'STATE_ROOT', state_root):
                self.assertEqual(tool.resolve_operator(SimpleNamespace()), operator)
                bad = dict(operator, fundingAddress='0x' + '00' * 32)
                tool.atomic_json(state_root / 'operator.json', bad)
                with self.assertRaises(tool.Failure):
                    tool.resolve_operator(SimpleNamespace())

    def test_resume_cannot_switch_bound_operator(self):
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            run = state_root / 'runs' / 'pending'
            original = tool.operator_from_values('synthetic-operator', SYNTHETIC_PUBLIC_KEY)
            changed = tool.operator_from_values('different-alias', SYNTHETIC_PUBLIC_KEY)
            state = {'runId': 'pending', 'mode': 'full', 'status': 'failed',
                     'runtimeHash': 'same-code', 'sourceCommit': tool.SOURCE_COMMIT,
                     'operatorFingerprint': tool.operator_fingerprint(original)}
            tool.atomic_json(run / 'state.json', state)
            args = SimpleNamespace(run_id='pending', new_run=False, full=True)
            with patch.object(tool, 'STATE_ROOT', state_root):
                with self.assertRaisesRegex(tool.Failure, 'bound to another operator'):
                    tool.select_run(args, 'same-code', operator=changed)
            self.assertEqual(tool.load_json(run / 'state.json'), state)
            self.assertFalse((state_root / 'operator.json').exists())

    def test_fresh_config_contains_bound_operator_before_runtime(self):
        for mode in ('full', 'migration-only'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state_root = root / 'state'
                database_url = 'postgresql://renewal:local-test-password@127.0.0.1:54321/renewal_e2e'
                if mode == 'migration-only':
                    parent = state_root / 'runs' / 'source'
                    data = parent / 'data'
                    (data / 'ciphertext').mkdir(parents=True)
                    keys = data / 'owners.private.json'
                    keys.write_text('OPAQUE: configuration assembly must not read keys')
                    tool.atomic_json(parent / 'state.json', {
                        'runId': 'source', 'count': 6, 'mode': 'full', 'status': 'complete',
                        'sourceCommit': tool.SOURCE_COMMIT, 'benchmarkConcurrency': False})
                    tool.atomic_json(parent / 'config.json', {
                        'databaseUrl': database_url, 'ownerFile': str(keys), 'scratch': str(data)})
                args = SimpleNamespace(run_id=None, new_run=False, full=mode == 'full',
                    migration_only=mode == 'migration-only', count=6, workers=16, chain_concurrency=8,
                    benchmark_concurrency=False, unfused=False,
                    source_run_id='source' if mode == 'migration-only' else None,
                    source_offset=0 if mode == 'migration-only' else None,
                    funding_alias='synthetic-operator', funding_public_key=SYNTHETIC_PUBLIC_KEY)
                reached = []

                def inspect_before_runtime(state, name, _command, run_dir, **_kwargs):
                    self.assertEqual(name, 'preflight')
                    configuration = tool.load_json(run_dir / 'config.json')
                    expected = tool.operator_from_values('synthetic-operator', SYNTHETIC_PUBLIC_KEY)
                    self.assertEqual({key: configuration[key] for key in expected}, expected)
                    self.assertEqual(tool.operator_fingerprint(configuration), state['operatorFingerprint'])
                    self.assertEqual(configuration['mode'], mode)
                    self.assertEqual((run_dir / 'config.json').stat().st_mode & 0o777, 0o600)
                    reached.append(name)
                    raise tool.Failure('intentional stop before runtime')

                with patch.object(tool, 'STATE_ROOT', state_root), \
                        patch.object(tool, 'runtime_hash', return_value=('new-runtime', {})), \
                        patch.object(tool, 'require_tools'), \
                        patch.object(tool, 'ensure_source_and_dependencies', return_value=(root, root, root)), \
                        patch.object(tool, 'ensure_docker'), patch.object(tool, 'ensure_image'), \
                        patch.object(tool, 'ensure_database', return_value={'password': 'local-test-password', 'port': 54321}), \
                        patch.object(tool, 'run_stage', side_effect=inspect_before_runtime), \
                        patch.object(tool, 'invoke', side_effect=AssertionError('external tool')), \
                        patch.object(tool.subprocess, 'Popen', side_effect=AssertionError('runtime process')), \
                        contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(tool.Failure, 'intentional stop before runtime'):
                        tool.run_pipeline(args)
                self.assertEqual(reached, ['preflight'])
                self.assertEqual((state_root / 'operator.json').stat().st_mode & 0o777, 0o600)

    def test_offline_modes_never_resolve_operator(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(tool, 'STATE_ROOT', Path(directory)), \
                    patch.object(tool, 'resolve_operator', side_effect=AssertionError('operator read')), \
                    contextlib.redirect_stdout(io.StringIO()):
                for argv in (['entry', '--plan', '--full', '--count', '6'], ['entry', '--self-test']):
                    with patch.object(sys, 'argv', argv):
                        self.assertEqual(tool.main(), 0)
                run = Path(directory) / 'runs' / 'old-complete'
                tool.atomic_json(run / 'state.json', {'status': 'complete'})
                (run / 'report.md').write_text('Historical result.\n')
                self.assertEqual(tool.run_pipeline(SimpleNamespace(run_id='old-complete')), run / 'report.md')

    def test_plan_cannot_start_tools_or_create_run_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory) / 'never-created'
            output = io.StringIO()
            with patch.object(tool, 'STATE_ROOT', state_root), \
                    patch.object(tool, 'invoke', side_effect=AssertionError('external command')), \
                    patch.object(tool.subprocess, 'run', side_effect=AssertionError('external command')), \
                    patch.object(sys, 'argv', ['one-click', '--plan', '--count', '6',
                                             '--workers', '16', '--chain-concurrency', '8']), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(tool.main(), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result['network'], 'testnet')
            self.assertFalse(result['sideEffects'])
            self.assertEqual(result['operation'], 'migration-only')
            self.assertFalse(result['createsSourceData'])
            self.assertFalse(result['setupFunding'])
            self.assertEqual(result['renewMode'], 'fused')
            self.assertEqual(result['metadataThreads'], 4)
            self.assertNotIn('setup synthetic owners/accounts', result['stages'])
            self.assertFalse(any(stage.startswith('seed') for stage in result['stages']))
            self.assertFalse(state_root.exists())

    def test_source_creation_requires_explicit_full_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory) / 'never-created'
            output = io.StringIO()
            with patch.object(tool, 'STATE_ROOT', state_root), \
                    patch.object(tool, 'invoke', side_effect=AssertionError('external command')), \
                    patch.object(tool.subprocess, 'run', side_effect=AssertionError('external command')), \
                    patch.object(sys, 'argv', ['one-click', '--plan', '--full', '--count', '6']), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(tool.main(), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result['operation'], 'full')
            self.assertTrue(result['createsSourceData'])
            self.assertTrue(result['setupFunding'])
            self.assertEqual(result['metadataThreads'], 0)
            self.assertTrue(any(stage.startswith('seed') for stage in result['stages']))
            self.assertFalse(state_root.exists())

    def test_source_selection_preserves_canonical_dataset(self):
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            for name, count, mode, benchmark, date in [
                    ('canonical-1000', 1000, 'full', False, '2026-11-17T01:00:00Z'),
                    ('new-small', 6, 'full', False, '2026-11-17T02:00:00Z'),
                    ('benchmark', 180, 'full', True, '2026-11-17T03:00:00Z'),
                    ('child-cycle', 1000, 'migration-only', False, '2026-11-17T04:00:00Z')]:
                run = state_root / 'runs' / name
                (run / 'data' / 'ciphertext').mkdir(parents=True)
                owner_file = run / 'data' / 'owners.private.json'
                owner_file.write_text('OPAQUE-NOT-JSON: plan must not read private keys')
                tool.atomic_json(run / 'state.json', {
                    'runId': name, 'count': count, 'mode': mode, 'status': 'complete',
                    'sourceCommit': tool.SOURCE_COMMIT, 'createdAt': date,
                    'benchmarkConcurrency': benchmark,
                    'stages': {'seed': {'status': 'complete'}}})
                tool.atomic_json(run / 'config.json', {
                    'ownerFile': str(owner_file), 'scratch': str(run / 'data')})
            with patch.object(tool, 'STATE_ROOT', state_root):
                _, selected, _ = tool.source_run(SimpleNamespace(source_run_id=None))
                self.assertEqual(selected['runId'], 'canonical-1000')
                with self.assertRaises(tool.Failure):
                    tool.source_run(SimpleNamespace(source_run_id='child-cycle'))

    def test_old_completed_report_needs_no_runtime_or_wallet_access(self):
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            run = state_root / 'runs' / 'old-complete'
            run.mkdir(parents=True)
            tool.atomic_json(run / 'state.json', {
                'status': 'complete', 'runtimeHash': 'previous-version'})
            report = run / 'report.md'
            report.write_text('Historical result, unchanged.\n')
            with patch.object(tool, 'STATE_ROOT', state_root), \
                    patch.object(tool, 'runtime_hash', side_effect=AssertionError('loaded new runtime')), \
                    patch.object(tool, 'require_tools', side_effect=AssertionError('wallet access')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(tool.run_pipeline(SimpleNamespace(run_id='old-complete')), report)

    def test_changing_encoder_asset_blocks_resume_before_payments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / 'assets'
            runtime = assets / 'runtime'
            runtime.mkdir(parents=True)
            for name in tool.RUNTIME_FILES:
                (runtime / name).write_text('original ' + name)
            state_root = root / 'state'
            run = state_root / 'runs' / 'pending'
            with patch.object(tool, 'ASSETS', assets):
                original_hash, _ = tool.runtime_hash()
                tool.atomic_json(run / 'state.json', {
                    'runId': 'pending', 'mode': 'migration-only', 'status': 'running',
                    'runtimeHash': original_hash, 'sourceCommit': tool.SOURCE_COMMIT})
                (runtime / 'metadata-worker.mjs').write_text('changed encoding implementation')
                changed_hash, _ = tool.runtime_hash()
                args = SimpleNamespace(run_id='pending', new_run=False,
                                       full=False, migration_only=True)
                with patch.object(tool, 'STATE_ROOT', state_root):
                    with self.assertRaisesRegex(tool.Failure, 'Runtime changed'):
                        tool.select_run(args, changed_hash)

    def test_completed_payment_stage_never_runs_again(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'original.log'
            log.write_text('completed payment receipt\n')
            prior = {'status': 'complete', 'attempts': [{'log': str(log)}],
                     'artifacts': [{'path': str(log), 'sha256': tool.sha(log)}]}
            state = {'stages': {'seed': prior}}
            with patch.object(tool.subprocess, 'Popen', side_effect=AssertionError('double payment')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(tool.run_stage(state, 'seed', ['must-not-run'], root), prior)
                log.write_text('tampered receipt\n')
                with self.assertRaises(tool.Failure):
                    tool.run_stage(state, 'seed', ['must-not-run'], root)
            self.assertEqual(len(state['stages']['seed']['attempts']), 1)

    def test_failed_attempt_log_survives_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / 'logs'
            logs.mkdir()
            old = logs / 'seed.attempt-1.log'
            old.write_text('prior partial upload receipt\n')
            state = {'stages': {'seed': {'status': 'failed', 'attempts': [
                {'log': str(old), 'wallSeconds': 1.0, 'exitCode': 1}]}}}
            command = [sys.executable, '-c',
                       'import json; print(json.dumps({"event":"complete","command":"seed"}))']
            with contextlib.redirect_stdout(io.StringIO()):
                result = tool.run_stage(state, 'seed', command, root, expect_complete=True)
            self.assertEqual(old.read_text(), 'prior partial upload receipt\n')
            self.assertEqual(result['status'], 'complete')
            self.assertEqual(len(result['attempts']), 2)
            self.assertNotEqual(result['attempts'][0]['log'], result['attempts'][1]['log'])
            self.assertEqual((root / 'state.json').stat().st_mode & 0o777, 0o600)
            with patch.object(tool.subprocess, 'Popen', side_effect=AssertionError('third payment')), \
                    contextlib.redirect_stdout(io.StringIO()):
                tool.run_stage(state, 'seed', command, root, expect_complete=True)
            self.assertEqual(len(state['stages']['seed']['attempts']), 2)

    def test_failed_source_audit_cannot_be_marked_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = {'stages': {}}
            with patch.object(tool, 'psql', return_value='{"all_passed":false}'):
                with self.assertRaises(tool.Failure):
                    tool.capture_sql(state, 'source-verify', 'not-a-real-container',
                                     root / 'unused.sql', root / 'source.json', root, {})
            self.assertNotEqual(state['stages'].get('source-verify', {}).get('status'), 'complete')

    def test_global_lock_blocks_a_second_spending_process(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            with (state_root / 'tool.lock').open('a+') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(tool, 'STATE_ROOT', state_root), \
                        patch.object(tool, 'runtime_hash', return_value=('fixture', {})), \
                        patch.object(tool, 'require_tools', side_effect=AssertionError('entered pipeline')):
                    with self.assertRaises(tool.Failure):
                        tool.run_pipeline(None)

    def test_drop_index_concurrently_is_not_wrapped_in_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for number in range(28):
                text = ('DROP INDEX CONCURRENTLY IF EXISTS synthetic_index;'
                        if number == 26 else 'SELECT 1;')
                (root / ('%03d_fixture.sql' % number)).write_text(text)
            queries = []

            def fake_psql(_container, query=None, **_kwargs):
                queries.append(query)
                if 'json_object_agg' in query:
                    return '{}'
                if 'NOT indisvalid' in query:
                    return '0'
                return ''

            with patch.object(tool, 'psql', side_effect=fake_psql), \
                    contextlib.redirect_stdout(io.StringIO()):
                tool.migrate_database('not-a-real-container', root)
            drop = [q for q in queries if 'DROP INDEX CONCURRENTLY' in q]
            self.assertEqual(len(drop), 1)
            self.assertNotIn('BEGIN;', drop[0])


if __name__ == '__main__':
    unittest.main()
