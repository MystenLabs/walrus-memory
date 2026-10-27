#!/usr/bin/env python3
"""
Walrus Memory Python SDK — Test Runner

Runs all tests grouped by category and prints a clean summary.

Usage:
    python3 run_tests.py

With dev server (integration tests):
    MEMWAL_PRIVATE_KEY=<hex> MEMWAL_ACCOUNT_ID=0x... MEMWAL_SERVER_URL=https://... python3 run_tests.py
"""

from __future__ import annotations

import os
import subprocess
import sys

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

SERVER_URL  = os.environ.get("MEMWAL_SERVER_URL", "https://relayer.dev.memwal.ai")
PRIVATE_KEY = os.environ.get("MEMWAL_PRIVATE_KEY", "")
ACCOUNT_ID  = os.environ.get("MEMWAL_ACCOUNT_ID", "")
HAS_KEY     = bool(PRIVATE_KEY and ACCOUNT_ID)


def run_group(label: str, node_ids: list[str], *, extra_args: list[str] | None = None) -> tuple[int, int, list[str], str]:
    """Run a group of tests, return (passed, failed, failed_names, raw_output)."""
    args = [
        sys.executable, "-m", "pytest",
        *node_ids,
        "-v", "-s",
        "--tb=short",
        "--no-header",
    ]
    if extra_args:
        args += extra_args

    env = os.environ.copy()

    result = subprocess.run(args, capture_output=True, text=True, env=env)
    out = result.stdout + result.stderr

    import re
    passed = 0
    failed = 0
    for line in out.splitlines():
        m = re.search(r"(\d+) passed", line)
        if m:
            passed = int(m.group(1))
        m2 = re.search(r"(\d+) failed", line)
        if m2:
            failed = int(m2.group(1))

    failed_names = [
        line.strip()
        for line in out.splitlines()
        if line.strip().startswith("FAILED ")
    ]

    return passed, failed, failed_names, out


def status(passed: int, failed: int) -> str:
    if failed == 0:
        return f"{GREEN}{BOLD}{passed} passed{RESET}"
    return f"{RED}{BOLD}{passed} passed, {failed} failed{RESET}"


def print_header() -> None:
    print()
    print(f"{BOLD}{CYAN}  Walrus Memory Python SDK — Test Suite{RESET}")
    print(f"  {DIM}Server: {SERVER_URL}{RESET}")
    print(f"  {DIM}Auth:   {'✓ credentials set' if HAS_KEY else '✗ no key (integration tests skipped)'}{RESET}")
    print()
    print(f"  {'Category':<28} {'Result':<20} Notes")
    print(f"  {'─' * 28} {'─' * 20} {'─' * 30}")


def print_row(label: str, passed: int, failed: int, notes: str) -> None:
    st = status(passed, failed)
    print(f"  {label:<28} {st:<38} {DIM}{notes}{RESET}")


def print_raw_failures(label: str, raw_output: str) -> None:
    """Print the TB for failed tests."""
    if "FAILED" not in raw_output:
        return
    print()
    print(f"  {RED}── {label} failures ──────────────────────{RESET}")
    in_failure = False
    for line in raw_output.splitlines():
        if line.startswith("FAILED") or line.startswith("_ "):
            in_failure = True
        if in_failure:
            print(f"    {line}")
        if line.startswith("=") and in_failure:
            in_failure = False


def main() -> None:
    print_header()

    total_passed = 0
    total_failed = 0
    all_failures: list[tuple[str, str]] = []

    # ── 1. Ed25519 signing utils ─────────────────────────────────────────────
    p, f, fails, raw = run_group("Ed25519 signing utils", ["tests/test_signing.py"])
    total_passed += p; total_failed += f
    print_row("Ed25519 signing utils", p, f,
              "hex, sha256, sign, verify, Sui address")
    if fails:
        all_failures.append(("signing", raw))

    # ── 2. Client — remember ─────────────────────────────────────────────────
    p, f, fails, raw = run_group("Client: remember()", [
        "tests/test_client.py::TestRemember",
    ])
    total_passed += p; total_failed += f
    print_row("Client: remember()", p, f,
              "body, headers, signature verifiable, namespace")
    if fails:
        all_failures.append(("Client remember", raw))

    # ── 3. Client — recall ───────────────────────────────────────────────────
    p, f, fails, raw = run_group("Client: recall()", [
        "tests/test_client.py::TestRecall",
    ])
    total_passed += p; total_failed += f
    print_row("Client: recall()", p, f, "body, headers, response parsing")
    if fails:
        all_failures.append(("Client recall", raw))

    # ── 4. Client — analyze / ask / restore ──────────────────────────────────
    p, f, fails, raw = run_group("Client: analyze/ask/restore", [
        "tests/test_client.py::TestAnalyze",
        "tests/test_client.py::TestAsk",
        "tests/test_client.py::TestRestore",
        "tests/test_client.py::TestHealth",
        "tests/test_client.py::TestManualAPI",
        "tests/test_client.py::TestPublicKey",
        "tests/test_client.py::TestContextManager",
        "tests/test_client.py::TestErrorHandling",
    ])
    total_passed += p; total_failed += f
    print_row("Client: analyze/ask/restore", p, f,
              "errors, manual API, ctx manager, public key")
    if fails:
        all_failures.append(("Client other", raw))

    # ── 5. Middleware — pure functions ────────────────────────────────────────
    p, f, fails, raw = run_group("Middleware: helpers", [
        "tests/test_middleware.py::TestFindLastUserMessage",
        "tests/test_middleware.py::TestFormatMemories",
        "tests/test_middleware.py::TestInjectOpenAIMemory",
    ])
    total_passed += p; total_failed += f
    print_row("Middleware: helpers", p, f,
              "find user msg, format, inject position")
    if fails:
        all_failures.append(("Middleware helpers", raw))

    # ── 6. Middleware — LangChain ────────────────────────────────────────────
    p, f, fails, raw = run_group("Middleware: LangChain", [
        "tests/test_middleware.py::TestWithMemWalLangChain",
    ])
    total_passed += p; total_failed += f
    print_row("Middleware: LangChain", p, f,
              "inject, no memories, min_relevance, resilience, auto_save")
    if fails:
        all_failures.append(("LangChain middleware", raw))

    # ── 7. Middleware — OpenAI ───────────────────────────────────────────────
    p, f, fails, raw = run_group("Middleware: OpenAI", [
        "tests/test_middleware.py::TestWithMemWalOpenAI",
    ])
    total_passed += p; total_failed += f
    print_row("Middleware: OpenAI", p, f,
              "async inject, no memories, resilience, auto_save, sync wrap")
    if fails:
        all_failures.append(("OpenAI middleware", raw))

    print(f"  {'─' * 78}")

    if not HAS_KEY:
        print(f"\n  {YELLOW}Integration tests skipped — set MEMWAL_PRIVATE_KEY + MEMWAL_ACCOUNT_ID to run them{RESET}")
        print_totals(total_passed, total_failed, all_failures)
        return

    print()
    print(f"  {CYAN}Integration tests → {SERVER_URL}{RESET}")
    print(f"  {'─' * 78}")

    # ── 8. Integration — Health ───────────────────────────────────────────────
    p, f, fails, raw = run_group("Health", [
        "tests/test_integration.py::TestHealth",
    ])
    total_passed += p; total_failed += f
    # Extract version from output
    version = "ok"
    for line in raw.splitlines():
        if "server version=" in line:
            version = line.strip()
    print_row("Health", p, f, f"status=ok, {version}")
    if fails:
        all_failures.append(("Health integration", raw))

    # ── 9. Integration — Auth rejection ─────────────────────────────────────
    p, f, fails, raw = run_group("Auth rejection", [
        "tests/test_integration.py::TestAuthRejection",
    ])
    total_passed += p; total_failed += f
    print_row("Auth rejection", p, f,
              "unsigned/wrong sig/expired/future/SDK wraps 401")
    if fails:
        all_failures.append(("Auth rejection", raw))

    # ── 10. Integration — remember ───────────────────────────────────────────
    p, f, fails, raw = run_group("remember()", [
        "tests/test_integration.py::TestRemember",
    ])
    total_passed += p; total_failed += f
    # Extract blob id hint
    note = "id+blob returned, default/custom namespace"
    for line in raw.splitlines():
        if "id=" in line and "blob=" in line:
            note = line.strip()
    print_row("remember()", p, f, note)
    if fails:
        all_failures.append(("remember integration", raw))

    # ── 11. Integration — recall ─────────────────────────────────────────────
    p, f, fails, raw = run_group("recall()", [
        "tests/test_integration.py::TestRecall",
    ])
    total_passed += p; total_failed += f
    note = "returns list, respects limit, correct fields"
    for line in raw.splitlines():
        if "recall total=" in line:
            note = f"{line.strip()}, respects limit, correct fields"
    print_row("recall()", p, f, note)
    if fails:
        all_failures.append(("recall integration", raw))

    # ── 12. Integration — analyze ────────────────────────────────────────────
    p, f, fails, raw = run_group("analyze()", [
        "tests/test_integration.py::TestAnalyze",
    ])
    total_passed += p; total_failed += f
    facts = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("- ") and len(stripped) > 4:
            facts.append(stripped[2:])
    quoted = ", ".join('"' + x + '"' for x in facts)
    note = ("extracted facts: " + quoted) if facts else "extracted facts"
    print_row("analyze()", p, f, note)
    if fails:
        all_failures.append(("analyze integration", raw))

    # ── 13. Integration — ask ────────────────────────────────────────────────
    p, f, fails, raw = run_group("ask()", [
        "tests/test_integration.py::TestAsk",
    ])
    total_passed += p; total_failed += f
    note = "returns answer string"
    for line in raw.splitlines():
        if "answer:" in line.lower():
            note = line.strip()
    print_row("ask()", p, f, note)
    if fails:
        all_failures.append(("ask integration", raw))

    # ── 14. Integration — Full e2e ───────────────────────────────────────────
    p, f, fails, raw = run_group("Full e2e", [
        "tests/test_integration.py::TestFullFlow",
    ])
    total_passed += p; total_failed += f
    note = "remember→recall finds it, remember→ask uses it"
    for line in raw.splitlines():
        if "recalled" in line:
            note = f"{line.strip()}"
    print_row("Full e2e", p, f, note)
    if fails:
        all_failures.append(("Full e2e", raw))

    # ── 15. Integration — Async variants ─────────────────────────────────────
    p, f, fails, raw = run_group("Async variants", [
        "tests/test_integration.py::TestAsync",
    ])
    total_passed += p; total_failed += f
    print_row("Async variants", p, f, "async health/remember/recall/analyze/ask")
    if fails:
        all_failures.append(("Async variants", raw))

    print_totals(total_passed, total_failed, all_failures)


def print_totals(total_passed: int, total_failed: int, all_failures: list) -> None:
    print()
    if total_failed == 0:
        print(f"  {GREEN}{BOLD}✓ {total_passed} passed, 0 failed{RESET}")
    else:
        print(f"  {RED}{BOLD}✗ {total_passed} passed, {total_failed} failed{RESET}")
        for label, raw in all_failures:
            print_raw_failures(label, raw)
    print()


if __name__ == "__main__":
    main()
