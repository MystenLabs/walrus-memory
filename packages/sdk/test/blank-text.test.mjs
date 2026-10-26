import assert from "node:assert/strict";
import test from "node:test";

import { assertNonBlankText } from "../dist/utils.js";

test("assertNonBlankText rejects empty and whitespace-only text", () => {
    for (const text of ["", " ", "\t", "\n", "  \t\n  "]) {
        assert.throws(
            () => assertNonBlankText(text),
            (err) => err.status === 400 && err.message === "Text cannot be empty",
            `should reject ${JSON.stringify(text)}`,
        );
    }
});

test("assertNonBlankText rejects zero-width space (U+200B) and format characters (#1156)", () => {
    const zeroWidthCases = [
        "\u200B", // zero-width space
        "\u200C", // zero-width non-joiner
        "\u200D", // zero-width joiner
        "\u2060", // word joiner
        "\uFEFF", // zero-width no-break space (BOM)
        " \u200B ",
        "\t\u200B\u200C\u200D\t",
        "  \u200B\n  ",
    ];

    for (const text of zeroWidthCases) {
        assert.throws(
            () => assertNonBlankText(text),
            (err) => err.status === 400 && err.message === "Text cannot be empty",
            `should reject zero-width text ${JSON.stringify(text)}`,
        );
    }
});

test("assertNonBlankText accepts non-blank text and does not trim surrounding whitespace", () => {
    assert.doesNotThrow(() => assertNonBlankText("hello"));
    assert.doesNotThrow(() => assertNonBlankText("  hello  "));
    assert.doesNotThrow(() => assertNonBlankText("hello\u200Bworld"));
});

test("assertNonBlankText supports custom error message", () => {
    assert.throws(
        () => assertNonBlankText("\u200B", "items[0].text cannot be empty"),
        (err) => err.status === 400 && err.message === "items[0].text cannot be empty",
    );
});
