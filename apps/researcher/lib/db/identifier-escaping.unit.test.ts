import assert from "node:assert/strict";
import test from "node:test";
import { sql } from "drizzle-orm";
import { PgDialect } from "drizzle-orm/pg-core";

test("quotes embedded delimiters inside PostgreSQL identifiers", () => {
    const untrusted = 'name"; DROP TABLE "User"; --';
    const query = new PgDialect().sqlToQuery(sql`select ${sql.identifier(untrusted)}`);
    assert.equal(query.sql, 'select "name""; DROP TABLE ""User""; --"');
    assert.deepEqual(query.params, []);
});
