#!/usr/bin/env python3
"""One entry point for the synthetic, testnet-only MemWal renewal exercise."""
import argparse
import base64
import binascii
import csv
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote

SOURCE_COMMIT = '856fb01793fdb4301cc1b1a9c8673c4c55595f08'
IMAGE = 'local/pgvector:0.8.2-pg17.12-bookworm'
CONTAINER = 'memwal-renewal-tool-pg-v1'
VOLUME = CONTAINER + '-data'
DB_NAME = 'renewal_e2e'
DB_USER = 'renewal'
LABEL = 'com.memwal.renewal-tool'
ROOT = Path(__file__).resolve().parents[2]
ASSETS = Path(__file__).resolve().parent
STATE_ROOT = ROOT / '.grok' / 'renewal-testnet'
PINNED = {'@mysten/sui': '2.17.0', '@mysten/walrus': '1.1.7', '@mysten/walrus-wasm': '0.2.2',
          '@mysten/seal': '1.1.0', '@noble/hashes': '2.4.0', 'tsx': '4.21.0', 'postgres': '3.4.8'}
PUBLIC_CONFIG = {
    'network': 'testnet',
    'suiGrpcUrl': 'https://mysten-rpc.testnet.sui.io',
    'immutablePackageId': '0x0a625e2db2af6f591a4c80a3d8551ddf11656089cc3a20c5e9e7f8fb75b9265c',
    'policyPackageId': '0x0a625e2db2af6f591a4c80a3d8551ddf11656089cc3a20c5e9e7f8fb75b9265c',
    'policyVerified': True,
    'registryId': '0x736aef9906798fca4460490ccdf8e8502ef170122dc26ecae32111b78c6b42dd',
    'walrusPackageId': '0xd84704c17fc870b8764832c535aa6b11f21a95cd6f5bb38a9b07d2cf42220c66',
    'relayUrl': 'https://upload-relay.testnet.walrus.space',
    'walrusAggregatorUrl': 'https://aggregator.walrus-testnet.walrus.space',
    'aggregatorUrl': 'https://seal-aggregator-testnet.mystenlabs.com',
    'committeeId': '0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98',
    'sourceEpochs': 2, 'renewalEpochs': 4, 'payloadBytes': 4096,
}
RUNTIME_FILES = ('run.ts', 'cli-signer.ts', 'metadata-cache.ts', 'metadata-worker.mjs', 'package.json')
LOCK_FD = None


class Failure(RuntimeError):
    pass


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def say(message):
    print('[renewal] ' + message, flush=True)


def load_json(path):
    return json.loads(Path(path).read_text())


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def operator_from_values(alias, public_key):
    """Validate public operator metadata; never read or export a keystore."""
    if not isinstance(alias, str) or not alias.strip() or len(alias.strip()) > 128:
        raise Failure('Funding alias must be a nonempty Sui CLI alias (up to 128 characters).')
    alias = alias.strip()
    if alias.startswith('-') or any(ord(character) < 32 or ord(character) == 127 for character in alias):
        raise Failure('Funding alias must not contain control characters or start with a flag prefix.')
    if not isinstance(public_key, str):
        raise Failure('Funding public key must be flagged Ed25519 base64.')
    try:
        flagged = base64.b64decode(public_key.strip(), validate=True)
    except (ValueError, binascii.Error):
        raise Failure('Funding public key must be valid flagged Ed25519 base64.') from None
    if len(flagged) != 33 or flagged[0] != 0:
        raise Failure('Funding public key must contain Ed25519 flag 0 followed by 32 public-key bytes.')
    canonical_key = base64.b64encode(flagged).decode('ascii')
    address = '0x' + hashlib.blake2b(flagged, digest_size=32).hexdigest()
    return {'fundingAlias': alias, 'fundingPublicKey': canonical_key, 'fundingAddress': address}


def operator_fingerprint(operator):
    normalized = operator_from_values(operator.get('fundingAlias'), operator.get('fundingPublicKey'))
    if operator.get('fundingAddress') != normalized['fundingAddress']:
        raise Failure('Configured funding address does not match its public key.')
    return hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def resolve_operator(args):
    alias, public_key = getattr(args, 'funding_alias', None), getattr(args, 'funding_public_key', None)
    if (alias is None) != (public_key is None):
        raise Failure('Provide --funding-alias and --funding-public-key together.')
    if alias is not None:
        return operator_from_values(alias, public_key)
    file = STATE_ROOT / 'operator.json'
    if not file.is_file():
        raise Failure('First live use requires --funding-alias ALIAS --funding-public-key FLAGGED_ED25519_BASE64; public metadata is then saved locally for future clicks.')
    try:
        saved = load_json(file)
        operator = operator_from_values(saved.get('fundingAlias'), saved.get('fundingPublicKey'))
    except (OSError, ValueError, AttributeError):
        raise Failure('Invalid local operator.json; provide both public funding flags to replace it.') from None
    if saved.get('fundingAddress', operator['fundingAddress']) != operator['fundingAddress']:
        raise Failure('Local operator funding address does not match its public key.')
    return operator


def bind_operator(state, operator):
    if operator is None:
        raise Failure('Live runs require explicit public operator configuration.')
    fingerprint = operator_fingerprint(operator)
    if state.get('operatorFingerprint') != fingerprint:
        raise Failure('This run is bound to another operator. Resume with its original alias/public key or use --new-run for a distinct experiment.')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def runtime_hash():
    values = {}
    for name in RUNTIME_FILES:
        path = ASSETS / 'runtime' / name
        if not path.is_file():
            raise Failure('Runtime asset missing: ' + str(path))
        values[name] = sha(path)
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest(), values


def invoke(command, cwd=None, input_text=None, check=True, quiet=False, env=None):
    result = subprocess.run(command, cwd=str(cwd) if cwd else None,
                            input=input_text, text=True, capture_output=True, env=env)
    if result.returncode and check:
        detail = (result.stderr or result.stdout).strip()[-2500:]
        raise Failure('%s failed (%s): %s' % (Path(command[0]).name, result.returncode, detail))
    if not quiet and result.stdout.strip():
        print(result.stdout.rstrip(), flush=True)
    return result


def require_tools():
    for name in ('git', 'node', 'npm', 'docker', 'sui'):
        if not shutil.which(name):
            raise Failure('Required local tool not found: ' + name)
    major = int(invoke(['node', '--version'], quiet=True).stdout.lstrip('v').split('.')[0])
    if major < 22:
        raise Failure('Node.js 22 or newer is required.')
    active = invoke(['sui', 'client', 'active-env'], quiet=True).stdout.strip()
    if active != 'testnet':
        raise Failure('Sui active environment must already be testnet; this script will not change it.')


def ensure_docker():
    if invoke(['docker', 'info', '--format', '{{.ServerVersion}}'], check=False, quiet=True).returncode == 0:
        return
    if sys.platform == 'darwin':
        for app in ('OrbStack', 'Docker'):
            if (Path('/Applications') / (app + '.app')).exists():
                say('Starting ' + app + '...')
                invoke(['open', '-a', app], quiet=True)
                break
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if invoke(['docker', 'info', '--format', '{{.ServerVersion}}'], check=False, quiet=True).returncode == 0:
            return
        time.sleep(2)
    raise Failure('Docker did not become ready; no testnet transaction was started.')


def ensure_image(cache):
    if invoke(['docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}'], check=False, quiet=True).returncode == 0:
        return
    say('Building the pinned PostgreSQL 17.12 + pgvector 0.8.2 image...')
    build = cache / 'postgres-image'
    build.mkdir(parents=True, exist_ok=True)
    dockerfile = '''FROM postgres:17.12-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates git postgresql-server-dev-17 && \\
    git clone --depth 1 --branch v0.8.2 https://github.com/pgvector/pgvector.git /tmp/pgvector && \\
    cd /tmp/pgvector && make && make install && cd / && rm -rf /tmp/pgvector /var/lib/apt/lists/*
'''
    (build / 'Dockerfile').write_text(dockerfile)
    result = subprocess.run(['docker', 'build', '--tag', IMAGE, str(build)])
    if result.returncode:
        raise Failure('Could not build the pinned local PostgreSQL image.')


def sql_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def psql(container, query=None, file=None, variables=None):
    command = ['docker', 'exec', '-i', container, 'psql', '-X', '-q', '-A', '-t',
               '-v', 'ON_ERROR_STOP=1', '-U', DB_USER, '-d', DB_NAME]
    for key, value in (variables or {}).items():
        command.extend(['-v', '%s=%s' % (key, value)])
    source = Path(file).read_text() if file else query
    return invoke(command, input_text=source, quiet=True).stdout.strip()


def ensure_database(cache, source):
    database_file = STATE_ROOT / 'database.json'
    existing = invoke(['docker', 'container', 'inspect', CONTAINER], check=False, quiet=True)
    if existing.returncode == 0:
        container = json.loads(existing.stdout)[0]
        if container.get('Config', {}).get('Labels', {}).get(LABEL) != '1':
            raise Failure('Container name belongs to another task; refusing to change it: ' + CONTAINER)
        if not database_file.exists():
            raise Failure('Existing local DB has no credential state; refusing to reset its volume.')
        database = load_json(database_file)
        if not container['State']['Running']:
            invoke(['docker', 'start', CONTAINER], quiet=True)
    else:
        database = load_json(database_file) if database_file.exists() else {'password': secrets.token_urlsafe(30)}
        atomic_json(database_file, database)
        env_file = STATE_ROOT / 'database.env'
        env_file.write_text('POSTGRES_DB=%s\nPOSTGRES_USER=%s\nPOSTGRES_PASSWORD=%s\n' %
                            (DB_NAME, DB_USER, database['password']))
        env_file.chmod(0o600)
        invoke(['docker', 'run', '-d', '--name', CONTAINER, '--label', LABEL + '=1',
                '--label', 'com.memwal.source-commit=' + SOURCE_COMMIT,
                '--env-file', str(env_file), '-p', '127.0.0.1::5432',
                '-v', VOLUME + ':/var/lib/postgresql/data', IMAGE], quiet=True)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        ready = invoke(['docker', 'exec', CONTAINER, 'pg_isready', '-U', DB_USER, '-d', DB_NAME], check=False, quiet=True)
        if ready.returncode == 0:
            break
        time.sleep(1)
    else:
        raise Failure('The isolated PostgreSQL database did not become ready.')
    ports = json.loads(invoke(['docker', 'inspect', CONTAINER, '--format', '{{json .NetworkSettings.Ports}}'], quiet=True).stdout)
    bindings = ports.get('5432/tcp') or []
    if len(bindings) != 1 or bindings[0]['HostIp'] != '127.0.0.1':
        raise Failure('The exercise database must be bound exclusively to 127.0.0.1.')
    version = json.loads(psql(CONTAINER, "SELECT json_build_object('version_num',current_setting('server_version_num')::int,'version',version());"))
    if not 170012 <= int(version['version_num']) < 180000:
        raise Failure('The exercise database must run PostgreSQL 17.12 or newer within major 17.')
    migrate_database(CONTAINER, source / 'services' / 'server' / 'migrations')
    database.update({'container': CONTAINER, 'port': int(bindings[0]['HostPort']), 'version': version})
    atomic_json(database_file, database)
    return database


def requires_autocommit(sql):
    """Concurrent index DDL cannot run inside our migration transaction."""
    executable = re.sub(r'/\*.*?\*/|--[^\n]*', ' ', sql, flags=re.S)
    commands = (r'CREATE\s+(?:UNIQUE\s+)?INDEX|DROP\s+INDEX|'
                r'REINDEX(?:\s+\([^)]*\))?\s+(?:INDEX|TABLE|SCHEMA|DATABASE|SYSTEM)')
    return bool(re.search(r'\b(?:' + commands + r')\s+CONCURRENTLY\b', executable, re.I))


def migrate_database(container, directory):
    files = sorted(directory.glob('*.sql'))
    if len(files) != 28:
        raise Failure('The pinned source must contain exactly 28 product SQL migrations.')
    psql(container, '''CREATE TABLE IF NOT EXISTS _renewal_tool_migrations
        (name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());''')
    existing = json.loads(psql(container, "SELECT coalesce(json_object_agg(name,sha256),'{}'::json) FROM _renewal_tool_migrations;"))
    for file in files:
        digest = sha(file)
        if file.name in existing:
            if existing[file.name] != digest:
                raise Failure('Applied SQL migration checksum changed: ' + file.name)
            continue
        content = file.read_text()
        ledger = "INSERT INTO _renewal_tool_migrations(name,sha256) VALUES(%s,%s);" % (sql_literal(file.name), sql_literal(digest))
        concurrent = requires_autocommit(content)
        if concurrent:
            psql(container, content)
            invalid = int(psql(container, 'SELECT count(*) FROM pg_index WHERE NOT indisvalid;'))
            if invalid:
                raise Failure('Migration left an invalid index; refusing to mark it applied: ' + file.name)
            psql(container, ledger)
        else:
            psql(container, 'BEGIN;\n' + content + '\n' + ledger + '\nCOMMIT;')
        say('Applied migration ' + file.name)


def safe_link(link, target):
    if link.is_symlink():
        if link.resolve() != target.resolve():
            link.unlink()
        else:
            return
    elif link.exists():
        raise Failure('Refusing to replace an existing dependency directory: ' + str(link))
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target, target_is_directory=True)


def ensure_source_and_dependencies(cache):
    source = cache / ('source-' + SOURCE_COMMIT[:8])
    if source.exists():
        head = invoke(['git', '-C', str(source), 'rev-parse', 'HEAD'], quiet=True).stdout.strip()
        if head != SOURCE_COMMIT:
            raise Failure('Cached source is not the pinned commit; refusing to reset it.')
        if invoke(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=no'], quiet=True).stdout.strip():
            raise Failure('Cached source has tracked edits; refusing to overwrite them.')
    else:
        invoke(['git', '-C', str(ROOT), 'cat-file', '-e', SOURCE_COMMIT + '^{commit}'], quiet=True)
        invoke(['git', '-C', str(ROOT), 'worktree', 'add', '--detach', str(source), SOURCE_COMMIT], quiet=True)
    dependencies = dict(load_json(source / 'services' / 'server' / 'scripts' / 'package.json')['dependencies'])
    dependencies.update(PINNED)
    dependencies['zod'] = '3.25.76'
    package = {'name': 'memwal-renewal-local-dependencies', 'private': True, 'type': 'module', 'dependencies': dependencies}
    deps = cache / 'dependencies'
    deps.mkdir(parents=True, exist_ok=True)
    package_file = deps / 'package.json'
    expected = json.dumps(package, sort_keys=True)
    installed = package_file.exists() and json.dumps(load_json(package_file), sort_keys=True) == expected
    if installed:
        for name, version in PINNED.items():
            file = deps / 'node_modules' / name / 'package.json'
            if not file.is_file() or load_json(file).get('version') != version:
                installed = False
                break
    if not installed:
        atomic_json(package_file, package)
        say('Installing pinned public Node dependencies (cached for future runs)...')
        code = subprocess.run(['npm', 'install', '--ignore-scripts', '--no-audit', '--no-fund',
                               '--registry', 'https://registry.npmjs.org'], cwd=str(deps)).returncode
        if code:
            raise Failure('Pinned public dependency installation failed.')
    invoke(['node', '--input-type=module', '-e',
            "await Promise.all(['tsx','postgres','@mysten/sui/grpc','@mysten/walrus','@mysten/seal'].map(x=>import(x)));"], cwd=deps, quiet=True)
    safe_link(source / 'node_modules', deps / 'node_modules')
    safe_link(source / 'services' / 'server' / 'scripts' / 'node_modules', deps / 'node_modules')
    runtime = source / 'tools' / 'renewal-testnet'
    runtime.mkdir(parents=True, exist_ok=True)
    for name in RUNTIME_FILES:
        shutil.copy2(ASSETS / 'runtime' / name, runtime / name)
    audit = runtime / 'audit'
    if (ASSETS / 'audit').is_dir():
        shutil.copytree(str(ASSETS / 'audit'), str(audit), dirs_exist_ok=True)
    return source, runtime, deps


def events(path):
    rows = []
    if not Path(path).exists():
        return rows
    for line in Path(path).read_text().splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict) and 'event' in item:
                rows.append(item)
        except ValueError:
            pass
    return rows


def check_stage_artifacts(stage):
    for item in stage.get('artifacts', []):
        file = Path(item['path'])
        if not file.is_file() or sha(file) != item['sha256']:
            raise Failure('Completed-stage artifact is missing or changed: ' + str(file))


def run_stage(state, name, command, run_dir, cwd=None, output=None, expect_complete=False, artifact_paths=None):
    prior = state.setdefault('stages', {}).get(name, {})
    if prior.get('status') == 'complete':
        check_stage_artifacts(prior)
        say('Resume: ' + name + ' already complete.')
        return prior
    attempts = prior.get('attempts', [])
    log = run_dir / 'logs' / ('%s.attempt-%d.log' % (name, len(attempts) + 1))
    log.parent.mkdir(parents=True, exist_ok=True)
    say('Starting ' + name + '...')
    attempt = {'startedAt': stamp(), 'command': command, 'log': str(log)}
    state['stages'][name] = {'status': 'running', 'attempts': attempts + [attempt]}
    save_state(state, run_dir)
    started = time.monotonic()
    proc = None
    captured = []
    try:
        with log.open('w') as stream:
            proc = subprocess.Popen(command, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True,
                                    pass_fds=(LOCK_FD,) if LOCK_FD is not None else ())
            progress = 0
            last_progress = 0.0
            for line in proc.stdout:
                stream.write(line)
                stream.flush()
                captured.append(line)
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                if event.get('event') in ('seeded', 'migrated', 'owner_decrypt_verified'):
                    progress += 1
                    if time.monotonic() - last_progress >= 15:
                        say('%s: %d completed in this attempt' % (name, progress))
                        last_progress = time.monotonic()
                elif event.get('event') == 'failed':
                    say('%s reported a failed memory; waiting for in-flight work to settle.' % name)
            code = proc.wait()
            proc.stdout.close()
        attempt.update({'completedAt': stamp(), 'wallSeconds': time.monotonic() - started, 'exitCode': code})
        if code:
            raise Failure('%s failed (exit %d). Log: %s' % (name, code, log))
        if expect_complete:
            complete = [row for row in events(log) if row['event'] == 'complete']
            failed = [row for row in events(log) if row['event'] == 'failed']
            if not complete or failed:
                raise Failure('Runner did not produce a clean completion receipt: ' + name)
            attempt['metrics'] = complete[-1]
        artifacts = [{'path': str(log), 'sha256': sha(log)}]
        if output:
            text = ''.join(captured)
            Path(output).write_text(text)
            artifacts.append({'path': str(output), 'sha256': sha(output)})
        for path in artifact_paths or []:
            if not Path(path).is_file():
                raise Failure('Stage output is missing: ' + str(path))
            artifacts.append({'path': str(path), 'sha256': sha(path)})
        result = {'status': 'complete', 'attempts': attempts + [attempt], 'artifacts': artifacts}
        state['stages'][name] = result
        save_state(state, run_dir)
        say('Completed ' + name + ' (%.1fs).' % attempt['wallSeconds'])
        return result
    except BaseException as error:
        if proc and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        attempt.update({'completedAt': stamp(), 'wallSeconds': time.monotonic() - started,
                        'exitCode': proc.returncode if proc else None})
        if proc and proc.stdout:
            proc.stdout.close()
        state['stages'][name].update({'status': 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed',
                                     'error': str(error)})
        save_state(state, run_dir)
        raise


def save_state(state, run_dir):
    atomic_json(run_dir / 'state.json', state)


def requested_mode(args):
    return 'full' if getattr(args, 'full', False) else 'migration-only'


def saved_mode(state):
    return state.get('mode', 'full')


def validate_run_id(value):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}', value):
        raise Failure('Invalid run ID.')
    return value


def source_run(args):
    """Select only a completed canonical full-data run, without reading keys."""
    runs = STATE_ROOT / 'runs'
    selected = getattr(args, 'source_run_id', None)
    if selected:
        directory = runs / validate_run_id(selected)
        if not (directory / 'state.json').is_file():
            raise Failure('Unknown existing source run: ' + selected)
        state = load_json(directory / 'state.json')
        if state.get('status') != 'complete' or saved_mode(state) != 'full' or state.get('benchmarkConcurrency'):
            raise Failure('Source must be a completed canonical full-data run; child migration cycles and benchmark runs are not source roots.')
    else:
        candidates = []
        for file in runs.glob('*/state.json'):
            state = load_json(file)
            if (state.get('status') == 'complete' and saved_mode(state) == 'full'
                    and not state.get('benchmarkConcurrency')
                    and state.get('stages', {}).get('seed', {}).get('status') == 'complete'):
                candidates.append((state.get('count') == 1000, state.get('createdAt', ''), file.parent, state))
        if not candidates:
            raise Failure('No completed source cohort exists. Use --full once to create synthetic test data, then run migration-only.')
        _, _, directory, state = max(candidates, key=lambda item: item[:2])
    if state.get('sourceCommit') != SOURCE_COMMIT:
        raise Failure('The source cohort uses a different pinned product source.')
    configuration = load_json(directory / 'config.json')
    owner_file = Path(configuration['ownerFile']).resolve()
    data_dir = Path(configuration['scratch']).resolve()
    try:
        owner_file.relative_to(directory.resolve())
        data_dir.relative_to(directory.resolve())
    except ValueError:
        raise Failure('The canonical source must use its own local fixture files.')
    if not owner_file.is_file() or not (data_dir / 'ciphertext').is_dir():
        raise Failure('Existing source fixture keys or ciphertext files are missing; refusing to regenerate them.')
    return directory, state, configuration


def completed_report(args):
    run_id = getattr(args, 'run_id', None)
    if not run_id:
        return None
    directory = STATE_ROOT / 'runs' / validate_run_id(run_id)
    state_file = directory / 'state.json'
    if not state_file.is_file():
        raise Failure('Unknown run ID: ' + run_id)
    state = load_json(state_file)
    if state.get('status') != 'complete':
        return None
    report = directory / 'report.md'
    if not report.is_file():
        raise Failure('The completed run report is missing; no new transactions were started.')
    say('This run is already complete: ' + str(report))
    return report


def select_run(args, digest, operator=None):
    runs = STATE_ROOT / 'runs'
    runs.mkdir(parents=True, exist_ok=True)
    mode = requested_mode(args)
    requested = None
    if args.run_id:
        requested = runs / validate_run_id(args.run_id)
        if not requested.exists():
            raise Failure('Unknown run ID: ' + args.run_id)
    elif not args.new_run:
        pending = []
        for file in runs.glob('*/state.json'):
            item = load_json(file)
            if item.get('status') != 'complete' and saved_mode(item) == mode:
                pending.append((item.get('createdAt', ''), file.parent))
        if pending:
            requested = sorted(pending)[-1][1]
    if requested:
        state = load_json(requested / 'state.json')
        if state.get('status') == 'complete':
            return requested, state
        if saved_mode(state) != mode:
            raise Failure('Saved run mode differs; use --full to resume data creation, or --migration-only for an existing-source migration.')
        if state.get('runtimeHash') != digest or state.get('sourceCommit') != SOURCE_COMMIT:
            raise Failure('Runtime changed since this run started; keep its original files or use --new-run.')
        bind_operator(state, operator)
        for key, value in [('count', args.count), ('workers', args.workers), ('chainConcurrency', args.chain_concurrency),
                           ('sourceOffset', getattr(args, 'source_offset', None)),
                           ('parentSourceRunId', getattr(args, 'source_run_id', None))]:
            if value is not None and value != state.get(key):
                raise Failure('Resume option differs from the saved run (%s); use --new-run for another experiment.' % key)
        if args.benchmark_concurrency and not state.get('benchmarkConcurrency'):
            raise Failure('This saved run is not a concurrency benchmark; use --new-run.')
        if getattr(args, 'unfused', False) and state.get('renewMode', 'unfused') != 'unfused':
            raise Failure('Resume cannot change a fused run to an unfused run; use --new-run.')
        state['status'] = 'running'
        state.pop('error', None)
        save_state(state, requested)
        say('Resuming ' + state['runId'])
        return requested, state
    if operator is None:
        raise Failure('Live runs require explicit public operator configuration.')
    fingerprint = operator_fingerprint(operator)
    workers, chain = 16, 8
    recommendation = STATE_ROOT / 'recommended-concurrency.json'
    if recommendation.exists():
        rec = load_json(recommendation)
        if rec.get('runtimeHash') == digest and rec.get('verified') and rec.get('itemsPerArm', 0) >= 60:
            workers, chain = int(rec['workers']), int(rec['chainConcurrency'])
    workers = args.workers if args.workers is not None else workers
    chain = args.chain_concurrency if args.chain_concurrency is not None else chain
    parent = None
    offset = getattr(args, 'source_offset', None) or 0
    if mode == 'migration-only':
        parent_dir, parent_state, parent_config = source_run(args)
        parent = parent_state['runId']
        available = int(parent_state['count']) - offset
        count = args.count if args.count is not None else (180 if args.benchmark_concurrency else available)
        if offset < 0 or count > available:
            raise Failure('The requested source offset/count exceeds the existing source cohort.')
    else:
        if getattr(args, 'source_run_id', None) or getattr(args, 'source_offset', None) is not None:
            raise Failure('--source-run-id/--source-offset are migration-only options.')
        count = args.count if args.count is not None else (180 if args.benchmark_concurrency else 1000)
    validate_options(count, workers, chain, args.benchmark_concurrency)
    run_id = 'renewal-%s-%s' % (dt.datetime.now().strftime('%Y%m%d-%H%M%S'), secrets.token_hex(3))
    run_dir = runs / run_id
    run_dir.mkdir(mode=0o700)
    state = {'schemaVersion': 2, 'runId': run_id, 'createdAt': stamp(), 'status': 'running', 'mode': mode,
             'sourceCommit': SOURCE_COMMIT, 'runtimeHash': digest, 'operatorFingerprint': fingerprint,
             'fundingAddress': operator['fundingAddress'], 'count': count,
             'workers': workers, 'chainConcurrency': chain,
             'renewMode': 'unfused' if mode == 'full' or getattr(args, 'unfused', False) else 'fused',
             'metadataThreads': 4 if mode == 'migration-only' and not getattr(args, 'unfused', False) else 0,
             'parentSourceRunId': parent, 'sourceOffset': offset,
             'benchmarkConcurrency': args.benchmark_concurrency, 'stages': {}}
    save_state(state, run_dir)
    return run_dir, state


def validate_options(count, workers, chain, benchmark):
    if not 1 <= count <= 1000 or not 1 <= workers <= 16 or not 1 <= chain <= min(8, workers):
        raise Failure('Use count 1–1000, workers 1–16, chain-concurrency 1–8 and no greater than workers.')
    if benchmark and (count < 24 or count % 3):
        raise Failure('Concurrency benchmark count must be divisible by 3 and at least 24 (default 180).')


def runner_command(runtime, config, command, limit=None, offset=0, workers=None, chain=None):
    result = ['node', '--import', 'tsx', str(runtime / 'run.ts'), command, '--config', str(config)]
    if limit is not None:
        result += ['--limit', str(limit), '--offset', str(offset)]
    if workers is not None:
        result += ['--concurrency', str(workers), '--chain-concurrency', str(chain)]
    if command in ('setup', 'reconcile', 'create-accounts', 'seed', 'migrate'):
        result.append('--execute')
    return result


def audit_sql(state, stem):
    suffix = '-existing' if saved_mode(state) == 'migration-only' else ''
    return stem + suffix + '.sql'


def audit_variables(state):
    return {'run_id': state['runId'], 'expected_count': state['count'],
            'expected_owners': min(2, state['count']), 'source_offset': state.get('sourceOffset', 0),
            'renew_mode': state.get('renewMode', 'unfused')}


def validate_resume_inventory(state, run_dir):
    """Completed logs never substitute for the actual local database on resume."""
    stages = state.get('stages', {})
    configuration = load_json(run_dir / 'config.json')
    owner_file = Path(configuration['ownerFile'])
    source_stage = 'prepare-existing' if saved_mode(state) == 'migration-only' else 'seed'
    keys_stage = 'prepare-existing' if saved_mode(state) == 'migration-only' else 'setup'
    if stages.get(keys_stage, {}).get('status') == 'complete' and not owner_file.is_file():
        raise Failure('The saved fixture key file is missing; refusing to create replacement owners.')
    if stages.get(source_stage, {}).get('status') != 'complete':
        return
    run_id = sql_literal(state['runId'])
    if saved_mode(state) == 'migration-only':
        vector_query = '(SELECT count(*) FROM exercise_renewal_memories m JOIN vector_entries v ON v.id=m.vector_entry_id WHERE m.run_id=%s)' % run_id
    else:
        vector_query = '(SELECT count(*) FROM vector_entries WHERE left(id,%d)=%s)' % (len(state['runId']) + 1, sql_literal(state['runId'] + ':'))
    observed = json.loads(psql(CONTAINER, """SELECT json_build_object(
        'catalog', (SELECT count(*) FROM exercise_renewal_memories WHERE run_id=%s),
        'vectors', %s,
        'liveStages', (SELECT count(*) FROM exercise_renewal_memories WHERE run_id=%s AND stage IN ('seeded','migrated')),
        'migrated', (SELECT count(*) FROM exercise_renewal_memories WHERE run_id=%s AND stage='migrated'));
    """ % (run_id, vector_query, run_id, run_id)))
    if any(observed[key] != state['count'] for key in ('catalog', 'vectors', 'liveStages')):
        raise Failure('Completed source inventory no longer exists intact in the isolated database.')
    migration_names = ('migrate',) if not state['benchmarkConcurrency'] else ('migrate-8-4','migrate-16-4','migrate-16-8')
    if all(stages.get(name, {}).get('status') == 'complete' for name in migration_names) and observed['migrated'] != state['count']:
        raise Failure('Completed migration receipts differ from the current database state.')
    variables = audit_variables(state)
    if stages.get('before', {}).get('status') == 'complete':
        baseline = load_json(run_dir / 'before.json')
        current = json.loads(psql(CONTAINER, file=ASSETS / 'audit' / audit_sql(state, 'snapshot'), variables=variables))
        if current.get('stable_fingerprint') != baseline.get('stable_fingerprint'):
            raise Failure('Current stable DB fields differ from the saved pre-migration baseline.')
    if all(stages.get(name, {}).get('status') == 'complete' for name in migration_names):
        current_checks = json.loads(psql(CONTAINER, file=ASSETS / 'audit' / audit_sql(state, 'verify'), variables=variables))
        if not current_checks.get('all_passed'):
            raise Failure('Current DB invariants no longer match the completed migration.')


def capture_sql(state, name, container, asset, output, run_dir, variables):
    prior = state.setdefault('stages', {}).get(name, {})
    if prior.get('status') == 'complete':
        check_stage_artifacts(prior)
        return
    attempts = prior.get('attempts', [])
    attempted = run_dir / 'logs' / ('%s.attempt-%d.json' % (name, len(attempts) + 1))
    attempted.parent.mkdir(parents=True, exist_ok=True)
    attempt = {'startedAt': stamp(), 'sqlAsset': str(asset), 'log': str(attempted)}
    state['stages'][name] = {'status': 'running', 'attempts': attempts + [attempt]}
    save_state(state, run_dir)
    started = time.monotonic()
    try:
        content = psql(container, file=asset, variables=variables)
        attempted.write_text(content + '\n')
        value = json.loads(content)
        if name in ('sql-verify', 'source-verify') and not value.get('all_passed'):
            raise Failure('Independent SQL assertions failed; see ' + str(attempted))
        if name in ('before', 'after') and (value.get('catalog_count') != variables['expected_count'] or value.get('vector_count') != variables['expected_count']):
            raise Failure('Snapshot does not contain the complete requested cohort: ' + str(attempted))
        output.write_text(content + '\n')
        attempt.update({'completedAt': stamp(), 'wallSeconds': time.monotonic() - started, 'exitCode': 0})
        state['stages'][name] = {'status': 'complete', 'attempts': attempts + [attempt],
                                 'artifacts': [{'path': str(path), 'sha256': sha(path)} for path in (attempted, output)]}
        save_state(state, run_dir)
    except BaseException as error:
        attempt.update({'completedAt': stamp(), 'wallSeconds': time.monotonic() - started, 'exitCode': 1})
        if not attempted.exists():
            attempted.write_text(json.dumps({'error': str(error)}) + '\n')
        state['stages'][name].update({'status': 'failed', 'error': str(error)})
        save_state(state, run_dir)
        raise


def write_report(state, run_dir, config, passed, error=None):
    summary = {'status': 'PASS' if passed else 'FAILED', 'runId': state['runId'],
               'count': state['count'], 'sourceCommit': SOURCE_COMMIT,
               'workers': state['workers'], 'chainConcurrency': state['chainConcurrency'],
               'benchmarkConcurrency': state['benchmarkConcurrency'], 'mode': saved_mode(state),
               'parentSourceRunId': state.get('parentSourceRunId'), 'sourceOffset': state.get('sourceOffset', 0),
               'renewMode': state.get('renewMode', 'unfused'),
               'metadataThreads': state.get('metadataThreads', 0),
               'runDirectory': str(run_dir), 'error': error, 'stages': state.get('stages', {})}
    cost_file = run_dir / 'cost.json'
    if cost_file.exists():
        try:
            summary['cost'] = load_json(cost_file)
        except ValueError:
            pass
    phases = []
    for name, stage in state.get('stages', {}).items():
        attempts = stage.get('attempts', [])
        phases.append((name, sum(item.get('wallSeconds', 0) for item in attempts), stage.get('status')))
    report = ['# Renewal testnet — ' + summary['status'], '',
              'Run: `%s`; mode **%s**; %d memories; source `%s`.' % (state['runId'], saved_mode(state), state['count'], SOURCE_COMMIT[:8]), '',
              'Full real testnet protocol: local DB → download ciphertext + metadata → fresh upload/certify → copy metadata + original-owner transfer → atomic DB update.', '',
              '## Stages', '', '| Stage | Seconds, including attempts | Status |', '| --- | ---: | --- |']
    report += ['| %s | %.2f | %s |' % row for row in phases]
    if saved_mode(state) == 'migration-only':
        report += ['', 'Existing canonical source: `%s`, offset %d, renewal mode `%s`.' %
                   (state.get('parentSourceRunId'), state.get('sourceOffset', 0), state.get('renewMode', 'fused')),
                   'This cycle uses the existing ciphertext, owner accounts and vector rows. It does not fund accounts, encrypt new content, upload new source data or insert replacement vector rows. Only replacement Blob objects, current object/lease heads and existing-row metadata are updated; original source-creation history remains intact.']
        if state.get('metadataThreads'):
            report += ['', 'Metadata uses a qualified persistent cache with a %d-thread pool for misses. Cold computation is included in migration time. The optimized path reuses finalized receipts while retaining visibility, fresh object/metadata/readback checks and atomic DB CAS.' % state['metadataThreads']]
            cache_attempts = []
            for name, stage in state.get('stages', {}).items():
                if name == 'migrate' or name.startswith('migrate-'):
                    for index, attempt in enumerate(stage.get('attempts', []), 1):
                        stats = (attempt.get('metrics') or {}).get('metadataCache')
                        if isinstance(stats, dict):
                            cache_attempts.append(dict(stats, stage=name, attempt=index))
            summary['metadataCacheAttempts'] = cache_attempts
            if cache_attempts:
                report += ['', '| Metadata computation attempt | Calls | Hits | Misses | Computed | Threads |',
                           '| --- | ---: | ---: | ---: | ---: | ---: |']
                for stats in cache_attempts:
                    report += ['| %s #%d | %s | %s | %s | %s | %s |' % (
                        stats['stage'], stats['attempt'], stats.get('calls', '—'), stats.get('hits', '—'),
                        stats.get('misses', '—'), stats.get('computed', '—'), stats.get('threads', '—'))]
    if error:
        report += ['', '## Stopped safely', '', str(error), '',
                   'Run the same entry point again to resume this saved run. Prepared transactions are reconciled before more mutations; the script does not delete the journal or blindly mint another replacement.']
    if summary.get('cost'):
        report += ['', '## Exact transaction cost', '', 'See [cost audit](cost.json). Funding principal is fixture capital, not a fee.']
        totals = summary['cost'].get('totals', {})
        if totals:
            report += ['', '| Category | SUI gas + relay tip | WAL |', '| --- | ---: | ---: |']
            for category in (('renew',) if saved_mode(state) == 'migration-only' else ('setup', 'seed', 'renew')):
                item = totals.get(category, {})
                if item:
                    report += ['| %s | %s | %s |' % (category, item.get('suiTotal', '—'), item.get('walTotal', '—'))]
    if passed:
        report += ['', '## Verification', '',
                   'Independent SQL, stable-field snapshots, source/download hashes and metadata, fresh onchain objects, exact transaction costs, and sampled original-owner decryption all passed.',
                   '', 'Ciphertext keeps its content-addressed blob ID; a fresh Sui Blob object has the later lease and original owner. This exercises the protocol with synthetic data, not the product HTTP/auth/queue stack. DB expires_at is estimated; onchain end_epoch is authoritative. Both objects are retained for audit.',
                   '', '## Local artifacts', '',
                   '- [Public configuration](config.public.json) · [before](before.json) · [after](after.json) · [SQL checks](sql-verify.json)',
                   '- [Snapshot comparison](snapshot-comparison.json) · [file audit](artifact-verify.json) · [chain audit](chain/summary.json)',
                   '- [Mapping](manifest.json) · [exact cost](cost.json)',
                   '', 'The database volume, ciphertext/download files and mode-0600 synthetic fixture keys remain local for inspection. Existing wallet keys are never exported. No Enoki, LLM, mainnet or production data is used.']
    if state.get('benchmarkConcurrency') and passed:
        scores = []
        for name, workers, chain in [('migrate-8-4', 8, 4), ('migrate-16-4', 16, 4), ('migrate-16-8', 16, 8)]:
            attempts = state['stages'][name]['attempts']
            seconds = sum(item.get('wallSeconds', 0) for item in attempts)
            scores.append({'stage': name, 'workers': workers, 'chainConcurrency': chain,
                           'seconds': seconds, 'itemsPerSecond': (state['count'] // 3) / seconds,
                           'performance': next((attempt.get('metrics', {}).get('performance', {}) for attempt in reversed(attempts) if attempt.get('metrics')), {})})
        fastest = max(scores, key=lambda item: item['itemsPerSecond'])
        reliable = [item for item in scores if all(attempt.get('exitCode') == 0 for attempt in state['stages'][item['stage']]['attempts'])]
        near_fastest = [item for item in reliable if item['itemsPerSecond'] >= fastest['itemsPerSecond'] / 1.05]
        best = min(near_fastest, key=lambda item: (item['chainConcurrency'], item['workers'])) if near_fastest else None
        summary['concurrencyResults'] = scores
        summary['fastestMeasuredConcurrency'] = fastest
        summary['recommendedConcurrency'] = best
        report += ['', '## Concurrency comparison', '', '| Workers / chain | Items | Seconds | Items/min | Node CPU % | Event-loop p95 ms | Chain use % | Queue p95 ms | Peak chain | Max RSS MiB |', '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
        for item in scores:
            perf = item.get('performance', {})
            chain_perf = perf.get('chain', {})
            report += ['| %d / %d | %d | %.2f | %.2f | %.1f | %.1f | %.1f | %.1f | %s | %.1f |' % (
                item['workers'], item['chainConcurrency'], state['count'] // 3, item['seconds'], item['itemsPerSecond'] * 60,
                perf.get('cpuPercentOfOneCore', 0), perf.get('eventLoopDelayMs', {}).get('p95', 0),
                chain_perf.get('capacityUtilizationPercent', 0), chain_perf.get('queueWaitMs', {}).get('p95', 0),
                chain_perf.get('activePeak', '—'), perf.get('processLifetimeMaxRssKiB', 0) / 1024)]
        report += ['', 'CPU is the Node runner process as a percentage of one core; it excludes Sui CLI child CPU. Event-loop delay and chain queue measurements are observed, not independent timing stages to sum. Chain occupancy includes transaction build/sign/execute/wait time.']
        if best and state['count'] // 3 >= 60:
            recommendation = dict(best, runtimeHash=state['runtimeHash'], verified=True,
                                  itemsPerArm=state['count'] // 3, sourceRunId=state['runId'], measuredAt=stamp())
            atomic_json(STATE_ROOT / 'recommended-concurrency.json', recommendation)
            report += ['', 'Future default runs use the fully verified setting within 5% of the fastest result with fewer chain slots/workers, bound to this runtime version. These are sequential testnet samples, not a guarantee of mainnet throughput.']
    atomic_json(run_dir / 'summary.json', summary)
    (run_dir / 'report.md').write_text('\n'.join(report) + '\n')
    return run_dir / 'report.md'


def run_pipeline(args):
    global LOCK_FD
    historic_report = completed_report(args)
    if historic_report:
        return historic_report
    digest, hashes = runtime_hash()
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_stream = (STATE_ROOT / 'tool.lock').open('a+')
    try:
        fcntl.flock(lock_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        LOCK_FD = lock_stream.fileno()
    except BlockingIOError:
        lock_stream.close()
        raise Failure('Another renewal run is active. This entry point permits only one mutating process at a time.')
    run_dir = None
    state = None
    try:
        operator = resolve_operator(args)
        require_tools()
        run_dir, state = select_run(args, digest, operator=operator)
        atomic_json(STATE_ROOT / 'operator.json', dict(operator, schemaVersion=1))
        if state.get('status') == 'complete':
            say('This run is already complete: ' + str(run_dir / 'report.md'))
            return run_dir / 'report.md'
        state['runtimeFiles'] = hashes
        save_state(state, run_dir)
        cache = STATE_ROOT / 'cache'
        cache.mkdir(parents=True, exist_ok=True)
        source, runtime, deps = ensure_source_and_dependencies(cache)
        ensure_docker()
        ensure_image(cache)
        database = ensure_database(cache, source)
        config_path = run_dir / 'config.json'
        if config_path.exists():
            config = load_json(config_path)
            if config['runId'] != state['runId'] or config['count'] != state['count']:
                raise Failure('Saved configuration does not match its run state.')
        else:
            defaults = load_json(ASSETS / 'testnet-defaults.json')
            if defaults.get('network') != 'testnet' or defaults.get('sourceCommit') != SOURCE_COMMIT:
                raise Failure('Public defaults must use testnet and the pinned source commit.')
            defaults.pop('sourceCommit', None)
            for key in ('fundingAlias', 'fundingPublicKey', 'fundingAddress', 'writerAddress'):
                defaults.pop(key, None)
            defaults['walrusAggregatorUrl'] = PUBLIC_CONFIG['walrusAggregatorUrl']
            config = dict(defaults, runId=state['runId'], count=state['count'], container=CONTAINER,
                          scratch=str(run_dir / 'data'), ownerFile=str(run_dir / 'data' / 'owners.private.json'),
                          databaseUrl='postgresql://%s:%s@127.0.0.1:%d/%s' %
                          (DB_USER, quote(database['password'], safe=''), database['port'], DB_NAME))
            config.update(operator)
            config.update({'mode': saved_mode(state), 'renewMode': state.get('renewMode', 'unfused'),
                           'metadataThreads': state.get('metadataThreads', 4),
                           'metadataCacheDir': str(STATE_ROOT / 'cache' / 'blob-metadata-v1')})
            if saved_mode(state) == 'migration-only':
                parent_dir = STATE_ROOT / 'runs' / state['parentSourceRunId']
                parent_config = load_json(parent_dir / 'config.json')
                if parent_config['databaseUrl'] != config['databaseUrl']:
                    raise Failure('The existing source is not in this isolated local database.')
                config.update({'parentSourceRunId': state['parentSourceRunId'],
                               'sourceOffset': state.get('sourceOffset', 0),
                               'sourceOwnerFile': parent_config['ownerFile'],
                               'sourceCipherDir': str(Path(parent_config['scratch']) / 'ciphertext')})
            atomic_json(config_path, config)
        if operator_fingerprint(config) != state['operatorFingerprint']:
            raise Failure('Saved run funding configuration differs from its bound operator.')
        # A changed port is safe after Docker recreation; the DB identity/name remain fixed.
        expected_url = 'postgresql://%s:%s@127.0.0.1:%d/%s' % (DB_USER, quote(database['password'], safe=''), database['port'], DB_NAME)
        if config['databaseUrl'] != expected_url:
            raise Failure('Database connection changed since this run began; refusing to point a saved run elsewhere.')
        public_config = dict(config)
        public_config.pop('ownerFile', None)
        public_config.pop('sourceOwnerFile', None)
        public_config['databaseUrl'] = 'postgresql://%s:REDACTED@127.0.0.1:%d/%s' % (DB_USER, database['port'], DB_NAME)
        atomic_json(run_dir / 'config.public.json', public_config)
        variables = audit_variables(state)
        # Preflight works with no owner file, so all chain/environment checks precede funding.
        run_stage(state, 'preflight', runner_command(runtime, config_path, 'preflight'), run_dir, cwd=runtime, expect_complete=True)
        # Reconciliation is always run on resume, not skipped by a prior completion receipt.
        reconcile_name = 'reconcile-%d' % (1 + sum(key.startswith('reconcile-') for key in state['stages']))
        run_stage(state, reconcile_name, runner_command(runtime, config_path, 'reconcile'), run_dir, cwd=runtime, expect_complete=True)
        validate_resume_inventory(state, run_dir)
        if saved_mode(state) == 'migration-only':
            run_stage(state, 'prepare-existing', runner_command(runtime, config_path, 'prepare-existing'), run_dir, cwd=runtime, expect_complete=True)
        else:
            run_stage(state, 'setup', runner_command(runtime, config_path, 'setup'), run_dir, cwd=runtime, expect_complete=True)
            run_stage(state, 'seed', runner_command(runtime, config_path, 'seed', state['count'], workers=8 if state['benchmarkConcurrency'] else state['workers'], chain=4 if state['benchmarkConcurrency'] else state['chainConcurrency']), run_dir, cwd=runtime, expect_complete=True)
        audit = runtime / 'audit'
        capture_sql(state, 'source-verify', CONTAINER, audit / audit_sql(state, 'source-verify'), run_dir / 'source-verify.json', run_dir, variables)
        capture_sql(state, 'before', CONTAINER, audit / audit_sql(state, 'snapshot'), run_dir / 'before.json', run_dir, variables)
        if state['benchmarkConcurrency']:
            per_arm = state['count'] // 3
            for index, (workers, chain) in enumerate(((8, 4), (16, 4), (16, 8))):
                name = 'migrate-%d-%d' % (workers, chain)
                run_stage(state, name, runner_command(runtime, config_path, 'migrate', per_arm, index * per_arm, workers, chain), run_dir, cwd=runtime, expect_complete=True)
        else:
            run_stage(state, 'migrate', runner_command(runtime, config_path, 'migrate', state['count'], workers=state['workers'], chain=state['chainConcurrency']), run_dir, cwd=runtime, expect_complete=True)
        capture_sql(state, 'after', CONTAINER, audit / audit_sql(state, 'snapshot'), run_dir / 'after.json', run_dir, variables)
        capture_sql(state, 'sql-verify', CONTAINER, audit / audit_sql(state, 'verify'), run_dir / 'sql-verify.json', run_dir, variables)
        capture_sql(state, 'manifest', CONTAINER, audit / audit_sql(state, 'artifact-manifest'), run_dir / 'manifest.json', run_dir, variables)
        run_stage(state, 'snapshot-comparison', [sys.executable, str(audit / 'compare-snapshots.py'), str(run_dir / 'before.json'), str(run_dir / 'after.json'), '--expected-count', str(state['count'])], run_dir, output=run_dir / 'snapshot-comparison.json')
        artifact_command = [sys.executable, str(audit / 'verify-artifacts.py'), str(run_dir / 'manifest.json'), config['scratch'], '--expected-count', str(state['count'])]
        if saved_mode(state) == 'migration-only':
            artifact_command += ['--source-cipher-dir', config['sourceCipherDir']]
        run_stage(state, 'artifact-verify', artifact_command, run_dir, output=run_dir / 'artifact-verify.json')
        if state['count'] <= 20:
            samples = [(0, state['count'])]
        else:
            samples = [(0, 10), (state['count'] - 10, 10)]
        for offset, count in samples:
            run_stage(state, 'owner-decrypt-%d' % offset, runner_command(runtime, config_path, 'verify', count, offset), run_dir, cwd=runtime, expect_complete=True)
        run_stage(state, 'chain-audit', ['node', str(audit / 'audit.mjs'), '--config', str(config_path), '--expected-count', str(state['count']), '--container', CONTAINER, '--manifest', str(run_dir / 'manifest.json'), '--execute', '--out', str(run_dir / 'chain')], run_dir, cwd=runtime, artifact_paths=[run_dir / 'chain' / 'summary.json', run_dir / 'chain' / 'objects.json', run_dir / 'chain' / 'pairs.json', run_dir / 'chain' / 'requests.json'])
        existing_only = saved_mode(state) == 'migration-only'
        run_stage(state, 'cost-audit', ['node', str(audit / 'cost-audit.mjs'), '--config', str(config_path), '--expect-seed', '0' if existing_only else str(state['count']), '--expect-renew', str(state['count']), '--expect-setup', '0' if existing_only else '3', '--renew-mode', state.get('renewMode', 'unfused'), '--require-complete', '--details', '--out', str(run_dir / 'cost.json')], run_dir, cwd=runtime, artifact_paths=[run_dir / 'cost.json'])
        # Require explicit pass verdicts, not only child exit codes.
        for name in ('sql-verify.json', 'snapshot-comparison.json', 'artifact-verify.json'):
            if not load_json(run_dir / name).get('all_passed'):
                raise Failure('Final verification failed: ' + name)
        if not load_json(run_dir / 'chain' / 'summary.json').get('passed'):
            raise Failure('Fresh onchain audit did not pass.')
        state['completedAt'] = stamp()
        report = write_report(state, run_dir, config, True)
        state['status'] = 'complete'
        save_state(state, run_dir)
        say('PASS: %d memories. Report: %s' % (state['count'], report))
        return report
    except BaseException as error:
        if run_dir and state:
            state.update({'status': 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed', 'error': str(error)})
            save_state(state, run_dir)
            report = write_report(state, run_dir, None, False, str(error))
            say('Stopped. Run the same file to resume. Report: ' + str(report))
        raise
    finally:
        fcntl.flock(lock_stream, fcntl.LOCK_UN)
        lock_stream.close()
        LOCK_FD = None


def plan(args):
    mode = requested_mode(args)
    parent_id = None
    offset = getattr(args, 'source_offset', None) or 0
    source_error = None
    source_count = 1000
    if mode == 'full' and (getattr(args, 'source_run_id', None) or getattr(args, 'source_offset', None) is not None):
        raise Failure('--source-run-id/--source-offset are migration-only options.')
    if mode == 'migration-only':
        try:
            _, parent, _ = source_run(args)
            parent_id = parent['runId']
            source_count = int(parent['count']) - offset
        except (Failure, OSError, ValueError, KeyError) as error:
            if getattr(args, 'source_run_id', None):
                raise Failure(str(error))
            source_error = str(error)
    count = args.count if args.count is not None else (180 if args.benchmark_concurrency else source_count)
    recommended_workers, recommended_chain = 16, 8
    recommendation = STATE_ROOT / 'recommended-concurrency.json'
    if recommendation.is_file():
        try:
            digest, _ = runtime_hash()
            rec = load_json(recommendation)
            if rec.get('runtimeHash') == digest and rec.get('verified') and rec.get('itemsPerArm', 0) >= 60:
                recommended_workers, recommended_chain = int(rec['workers']), int(rec['chainConcurrency'])
        except (Failure, OSError, ValueError, KeyError):
            pass
    workers = args.workers if args.workers is not None else recommended_workers
    chain = args.chain_concurrency if args.chain_concurrency is not None else recommended_chain
    validate_options(count, workers, chain, args.benchmark_concurrency)
    if offset < 0 or (parent_id and count > source_count):
        raise Failure('The requested offset/count exceeds the existing source cohort.')
    stages = ['bootstrap pinned source/dependencies', 'start isolated local PostgreSQL',
              'apply checksummed product migrations', 'read-only preflight', 'reconcile saved transactions']
    if mode == 'migration-only':
        stages += ['prepare existing-source references and original-vector CAS snapshots']
    else:
        stages += ['setup synthetic owners/accounts', 'seed fresh synthetic source data']
    stages += ['source audit + before snapshot',
               'migrate' if not args.benchmark_concurrency else 'compare 8/4,16/4,16/8 on disjoint equal arms',
               'SQL + stable fields + downloaded artifacts', 'sample owner decryption',
               'fresh onchain audit', 'exact cost audit', 'report']
    print(json.dumps({'mode': 'plan-only', 'operation': mode, 'network': 'testnet', 'count': count,
                      'workers': workers, 'chainConcurrency': chain, 'sourceCommit': SOURCE_COMMIT,
                      'stateRoot': str(STATE_ROOT),
                      'fundingConfiguration': 'Explicit --funding-alias and --funding-public-key, or local operator.json, required only for live use.',
                      'parentSourceRunId': parent_id,
                      'sourceOffset': offset, 'sourceSelectionError': source_error,
                      'createsSourceData': mode == 'full', 'setupFunding': mode == 'full',
                      'renewMode': 'unfused' if mode == 'full' or getattr(args, 'unfused', False) else 'fused',
                      'metadataThreads': 4 if mode == 'migration-only' and not getattr(args, 'unfused', False) else 0,
                      'metadataCachePolicy': 'verified ciphertext + shard count + codec fingerprint; cold misses computed in worker pool',
                      'sourceEpochs': 2 if mode == 'full' else None, 'minimumRenewalEpochs': 4,
                      'leaseStrategy': 'per item: max(minimum lease, source end epoch + 1 - fresh system epoch)',
                      'stages': stages, 'sideEffects': False}, indent=2))


def self_test():
    validate_options(1000, 8, 4, False)
    validate_options(180, 16, 8, True)
    for values in ((0, 8, 4, False), (1000, 17, 8, False), (1000, 4, 8, False), (25, 8, 4, True)):
        try:
            validate_options(*values)
        except Failure:
            pass
        else:
            raise AssertionError('Unsafe options accepted: ' + repr(values))
    assert sql_literal("a'b") == "'a''b'"
    assert requires_autocommit('CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx ON t(id);')
    assert requires_autocommit('DROP INDEX CONCURRENTLY IF EXISTS idx;')
    assert requires_autocommit('REINDEX INDEX CONCURRENTLY idx;')
    assert requires_autocommit('REINDEX (VERBOSE) TABLE CONCURRENTLY t;')
    assert not requires_autocommit('DROP INDEX IF EXISTS idx;')
    assert not requires_autocommit('-- DROP INDEX CONCURRENTLY idx;\nCREATE TABLE t(id int);')
    with tempfile.TemporaryDirectory() as directory:
        file = Path(directory) / 'state.json'
        atomic_json(file, {'status': 'running'})
        assert load_json(file)['status'] == 'running'
        assert file.stat().st_mode & 0o777 == 0o600
        artifact = Path(directory) / 'artifact.json'
        artifact.write_text('{}')
        stage = {'artifacts': [{'path': str(artifact), 'sha256': sha(artifact)}]}
        check_stage_artifacts(stage)
        artifact.write_text('{"changed":true}')
        try:
            check_stage_artifacts(stage)
        except Failure:
            pass
        else:
            raise AssertionError('Changed completed-stage artifact accepted')
    print('PASS: offline option guards, concurrent-index migration classification, atomic private state and artifact-resume integrity. No Docker/network/wallet calls.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--full', action='store_true', help='Explicitly create fresh synthetic source data before migration.')
    modes.add_argument('--migration-only', action='store_true', help='Migrate already-existing source data (default).')
    parser.add_argument('--source-run-id', help='Completed canonical full-data source run; latest 1000-item source is selected by default.')
    parser.add_argument('--source-offset', type=int, help='Starting memory ID within the existing canonical source.')
    parser.add_argument('--unfused', action='store_true', help='Use the diagnostic three-transaction renewal path.')
    parser.add_argument('--funding-alias', help='Sui CLI alias for the explicit testnet funding operator (first live use).')
    parser.add_argument('--funding-public-key', help='33-byte flagged Ed25519 public key in base64; never a private key.')
    parser.add_argument('--count', type=int)
    parser.add_argument('--workers', type=int)
    parser.add_argument('--chain-concurrency', type=int)
    parser.add_argument('--benchmark-concurrency', action='store_true')
    parser.add_argument('--run-id')
    parser.add_argument('--new-run', action='store_true')
    parser.add_argument('--no-open', action='store_true')
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    try:
        if args.plan:
            plan(args)
            return 0
        if args.self_test:
            self_test()
            return 0
        report = run_pipeline(args)
        if not args.no_open and sys.platform == 'darwin':
            subprocess.run(['open', str(report)], check=False)
        return 0
    except KeyboardInterrupt:
        say('Interrupted; saved journal/state will be reconciled on the next click.')
        return 130
    except (Failure, OSError, ValueError, KeyError) as error:
        say(str(error))
        return 1


if __name__ == '__main__':
    sys.exit(main())
