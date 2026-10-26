import { sql } from "drizzle-orm";
import { PgDialect } from "drizzle-orm/pg-core";
import { expect, it } from "vitest";

it("quotes embedded delimiters inside PostgreSQL identifiers", () => {
  const untrusted = 'name"; DROP TABLE "User"; --';
  const query = new PgDialect().sqlToQuery(sql`select ${sql.identifier(untrusted)}`);
  expect(query.sql).toBe('select "name""; DROP TABLE ""User""; --"');
  expect(query.params).toEqual([]);
});
