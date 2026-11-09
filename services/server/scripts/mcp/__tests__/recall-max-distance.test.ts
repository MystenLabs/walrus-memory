/**
 * `memwal_recall` can cut weakly related top-K hits with `maxDistance`.
 *
 * The sidecar is pinned to an SDK that may not accept object-form
 * `recall({ maxDistance })`, so the cutoff is applied here on `result.results`
 * — same polarity as the SDK: cosine distance, keep `distance < maxDistance`.
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
    allDroppedCountFromError,
    emptyRecallText,
    filterByMaxDistance,
    formatRecallLine,
} from "../tools/recall.js";

const row = (text: string, distance: number) => ({ text, distance });

test("omitting maxDistance leaves every hit in place", () => {
    const results = [
        row("close", 0.1),
        row("far", 0.9),
    ];
    assert.deepEqual(filterByMaxDistance(results), results);
    assert.deepEqual(filterByMaxDistance(results, undefined), results);
});

test("the cutoff is exclusive: keeps below maxDistance, drops at or above", () => {
    const kept = filterByMaxDistance(
        [row("best", 0.1), row("ok", 0.499), row("boundary", 0.5), row("worse", 0.9)],
        0.5,
    );
    assert.deepEqual(
        kept.map((m) => m.text),
        ["best", "ok"],
    );
});

test("all hits outside maxDistance is not reported as a decrypt failure", () => {
    const results = [row("far", 0.9), row("farther", 1.1)];
    const filtered = filterByMaxDistance(results, 0.5);
    assert.equal(filtered.length, 0);
    const text = emptyRecallText(results.length, 0);
    assert.match(text, /outside maxDistance/);
    assert.doesNotMatch(text, /decrypt/);
    assert.doesNotMatch(text, /download/);
});

test("undecrypted matches are reported alongside the cutoff, not hidden by it", () => {
    // Their distance was never computed, so "all outside maxDistance" would
    // claim more than we know: they may well have been inside the cutoff.
    const text = emptyRecallText(2, 3);
    assert.match(text, /outside maxDistance/);
    assert.match(text, /3 further matches/);
    assert.match(text, /decrypt/);
});

test("a single undecrypted match reads as singular", () => {
    assert.match(emptyRecallText(2, 1), /1 further match was/);
});

test("displayed score is 1 minus cosine distance", () => {
    const line = formatRecallLine(
        { text: "shipped the composite ranker", distance: 0.25 },
        0,
    );
    assert.match(line, /\[score=0\.750 distance=0\.250\]/);
});

test("allDroppedCountFromError extracts droppedCount from SDK all-dropped errors", () => {
    const sdkErr = Object.assign(new Error("all 3 dropped"), {
        name: "MemWalRecallAllDropped",
        code: "RECALL_ALL_DROPPED",
        droppedCount: 3,
    });
    assert.equal(allDroppedCountFromError(sdkErr), 3);
    assert.match(emptyRecallText(0, 3), /This is not an empty namespace/);
    assert.equal(allDroppedCountFromError(new Error("network failed")), null);
});
