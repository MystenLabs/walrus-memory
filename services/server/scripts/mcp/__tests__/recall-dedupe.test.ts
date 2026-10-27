/**
 * `memwal_recall` collapses identical results before they reach the model.
 *
 * Observed on a real dev account: a `limit=5` recall returned the same fact
 * five times, consuming the entire retrieval budget on one preference and
 * crowding out every other memory the query should have surfaced.
 *
 * That is expected on the write side. Each remember is a distinct event with
 * its own blob and timestamp, and there is no content-level uniqueness
 * constraint by design (the only unique index is request idempotency on
 * `remember_jobs (owner, idempotency_key)`, which guards retries, not content).
 * So the fix belongs on the read side, and these tests pin that behavior.
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
    collapseDuplicates,
    formatCollapsedDuplicatesNote,
} from "../tools/recall.js";

const row = (text: string, distance = 0.5, blob_id?: string) => ({
    text,
    distance,
    ...(blob_id ? { blob_id } : {}),
});

test("collapses identical texts and reports the count", () => {
    const { unique, collapsed } = collapseDuplicates([
        row("User prefers dark roast coffee"),
        row("User prefers dark roast coffee"),
        row("User prefers dark roast coffee"),
        row("User prefers dark roast coffee"),
        row("User prefers dark roast coffee"),
    ]);
    assert.equal(unique.length, 1);
    assert.equal(collapsed, 4);
});

test("keeps the highest scoring copy", () => {
    // recall returns rows ranked best-first, so the survivor must be the first
    // one seen, not an arbitrary map entry.
    const { unique } = collapseDuplicates([
        row("same fact", 0.1),
        row("same fact", 0.9),
    ]);
    assert.equal(unique.length, 1);
    assert.equal(unique[0].distance, 0.1);
});

test("normalizes whitespace and case before comparing", () => {
    const { unique, collapsed } = collapseDuplicates([
        row("User prefers dark roast coffee"),
        row("  user prefers   DARK roast coffee  "),
    ]);
    assert.equal(unique.length, 1);
    assert.equal(collapsed, 1);
});

test("preserves rank order of the survivors", () => {
    const { unique } = collapseDuplicates([
        row("first", 0.1),
        row("second", 0.2),
        row("first", 0.3),
        row("third", 0.4),
    ]);
    assert.deepEqual(
        unique.map((m) => m.text),
        ["first", "second", "third"],
    );
});

test("leaves distinct facts untouched", () => {
    // The common case must not lose anything. A dedupe that is too eager is
    // worse than the duplicates it removes.
    const { unique, collapsed } = collapseDuplicates([
        row("deploy region is ap-southeast-1"),
        row("prefers dark roast coffee"),
        row("uses pnpm, not npm"),
    ]);
    assert.equal(unique.length, 3);
    assert.equal(collapsed, 0);
});

test("does not merely substring-match distinct facts", () => {
    // "coffee" appearing in both must not collapse them: these are different
    // statements and losing either would be a silent data loss bug.
    const { unique, collapsed } = collapseDuplicates([
        row("User prefers dark roast coffee"),
        row("User prefers dark roast coffee in the morning only"),
    ]);
    assert.equal(unique.length, 2);
    assert.equal(collapsed, 0);
});

test("handles an empty result set", () => {
    const { unique, collapsed, duplicates } = collapseDuplicates([]);
    assert.equal(unique.length, 0);
    assert.equal(collapsed, 0);
    assert.deepEqual(duplicates, []);
    assert.equal(formatCollapsedDuplicatesNote(duplicates), null);
});

test("names the duplicated 1-based result index and distinct blob count when a middle row is duplicated (#722)", () => {
    const { unique, collapsed, duplicates } = collapseDuplicates([
        row("Staging database runs on port 6543", 0.341, "blob-1"),
        row("User prefers dark roast coffee", 0.489, "blob-2"),
        row("Team deploys from the main branch on Fridays", 0.567, "a-L8o2vB1jQ_eX7yU3cN0zK5wF9tD6mS4pR2gH8jL0k"),
        row("Team deploys from the main branch on Fridays", 0.567, "Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8cB7aA6z"),
        row("Primary editor is Neovim with lazy.nvim", 0.619, "blob-4"),
        row("API gateway timeout is set to 30 seconds", 0.651, "blob-5"),
    ]);
    assert.equal(unique.length, 5);
    assert.equal(collapsed, 1);
    assert.deepEqual(duplicates, [
        {
            index: 3,
            collapsed: 1,
            total: 2,
            blobIds: [
                "a-L8o2vB1jQ_eX7yU3cN0zK5wF9tD6mS4pR2gH8jL0k",
                "Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8cB7aA6z",
            ],
        },
    ]);
    assert.equal(
        formatCollapsedDuplicatesNote(duplicates),
        "\n(1 duplicate copy of #3 collapsed — #3 is stored across 2 blobs; the same fact is stored more than once.)",
    );
});

test("formats single-row duplicate note without blob count when blob_id is absent or identical", () => {
    const { duplicates } = collapseDuplicates([
        row("first", 0.1),
        row("duplicated fact", 0.2),
        row("duplicated fact", 0.2),
        row("duplicated fact", 0.2),
    ]);
    assert.equal(
        formatCollapsedDuplicatesNote(duplicates),
        "\n(2 duplicate copies of #2 collapsed — 3 copies total; the same fact is stored more than once.)",
    );
});

test("formats multi-row duplicate summary when more than one survivor had duplicates", () => {
    const { collapsed, duplicates } = collapseDuplicates([
        row("fact one", 0.1, "b1"),
        row("fact one", 0.1, "b2"),
        row("fact two", 0.2, "b3"),
        row("fact three", 0.3, "b4"),
        row("fact three", 0.3, "b5"),
        row("fact three", 0.3, "b6"),
    ]);
    assert.equal(collapsed, 3);
    assert.equal(
        formatCollapsedDuplicatesNote(duplicates),
        "\n(3 duplicate copies collapsed: #1 (1 duplicate, 2 blobs), #3 (2 duplicates, 3 blobs); the same fact is stored more than once.)",
    );
});
