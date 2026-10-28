import test from "node:test";
import assert from "node:assert/strict";
import { formatRestoreResult } from "../tools/restore.js";

test("memwal_restore warns when the API reports a truncated restore", () => {
    const text = formatRestoreResult(
        {
            namespace: "my-app",
            total: 25,
            restored: 10,
            skipped: 15,
            truncated: true,
        },
        10,
    );

    assert.match(text, /^Restore partially complete/);
    assert.match(text, /truncated=true/);
    assert.match(text, /More blobs remain to restore/);
    assert.match(text, /increase limit and call again/);
    assert.doesNotMatch(text, /Sidecar cap is saturated/);
});

test("memwal_restore does not tell agents to raise limit once the sidecar cap is saturated", () => {
    const text = formatRestoreResult(
        {
            namespace: "my-app",
            total: 100,
            restored: 20,
            skipped: 80,
            truncated: true,
        },
        20,
    );

    assert.match(text, /^Restore partially complete/);
    assert.match(text, /truncated=true/);
    assert.match(text, /Sidecar cap is saturated/);
    assert.match(text, /missing-blob page/);
    assert.doesNotMatch(text, /increase limit and call again/);
});

test("memwal_restore reports a finished page when restore is not truncated", () => {
    const text = formatRestoreResult({
        namespace: "my-app",
        total: 10,
        restored: 10,
        skipped: 0,
        truncated: false,
    });

    assert.match(text, /^Restore page finished/);
    assert.match(text, /truncated=false/);
    assert.match(text, /not proof the sidecar saw every blob/);
    assert.doesNotMatch(text, /More blobs remain to restore/);
    assert.doesNotMatch(text, /Restore complete/);
});

test("memwal_restore treats an omitted legacy truncated field as false", () => {
    const text = formatRestoreResult({
        namespace: "legacy",
        total: 1,
        restored: 1,
        skipped: 0,
    });

    assert.match(text, /^Restore page finished/);
    assert.match(text, /truncated=false/);
    assert.match(text, /not proof the sidecar saw every blob/);
});

test("memwal_restore prints failed next to the other counts", () => {
    const text = formatRestoreResult({
        namespace: "my-app",
        total: 10,
        restored: 7,
        skipped: 0,
        failed: 3,
        truncated: false,
    });

    assert.match(text, /failed=3/);
    assert.match(text, /restored=7/);
    assert.match(text, /skipped=0/);
});

test("memwal_restore defaults omitted failed to 0", () => {
    const text = formatRestoreResult({
        namespace: "legacy",
        total: 1,
        restored: 1,
        skipped: 0,
        truncated: false,
    });

    assert.match(text, /failed=0/);
});

test("memwal_restore hints retry not raise-limit when the page is only transients", () => {
    const text = formatRestoreResult(
        {
            namespace: "my-app",
            total: 10,
            restored: 0,
            skipped: 0,
            failed: 0,
            truncated: true,
        },
        10,
    );

    assert.match(text, /^Restore partially complete/);
    assert.match(text, /failed=0/);
    assert.match(text, /download\/embed blip/);
    assert.match(text, /retry the same limit/);
    assert.doesNotMatch(text, /increase limit and call again/);
});

test("memwal_restore still tells agents to raise limit for WALM-431 cap truncation", () => {
    // Empty namespace, sidecar cap still expandable (limit < 20): skipped+failed
    // is not short of total, so this is page/cap truncation, not an embed blip.
    const text = formatRestoreResult(
        {
            namespace: "my-app",
            total: 0,
            restored: 0,
            skipped: 0,
            failed: 0,
            truncated: true,
        },
        10,
    );

    assert.match(text, /increase limit and call again/);
    assert.doesNotMatch(text, /download\/embed blip/);
});

test("memwal_restore states 0 on-chain blobs and suggests close namespaces when namespace is empty", () => {
    const text = formatRestoreResult(
        {
            namespace: "pcl301",
            total: 0,
            restored: 0,
            skipped: 0,
            failed: 0,
            truncated: false,
        },
        10,
        [
            { name: "pcl302", memory_count: 15, storage_used: 4096 },
            { name: "work", memory_count: 8, storage_used: 2048 },
        ],
    );

    assert.match(text, /Namespace "pcl301" holds 0 on-chain blobs\./);
    assert.match(text, /Did you mean namespace "pcl302" \(15 memories\)\?/);
    assert.match(text, /Existing namespaces: "pcl302" \(15\), "work" \(8\)\./);
});
