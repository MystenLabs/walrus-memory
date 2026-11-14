/**
 * Playwright global setup.
 *
 * Runs once before any test (after the webServer is spawned). Responsible for:
 *   1. Initializing and clearing the delegate fixture claims directory.
 *   2. Applying Drizzle migrations so note/user/session tables exist.
 *   3. Failing fast with a clear error if DATABASE_URL is missing in CI.
 *   4. Warming the `/` and `/api/memory/health` routes so the first hits
 *      do not race Turbopack lazy cold compilation against navigationTimeout.
 *
 * Note: migrations run via `tsx package/shared/lib/db/migrate.ts` (the same
 * entrypoint the Docker image uses) rather than `pnpm db:push`. drizzle-kit
 * 0.31.x rejects the pinned drizzle-orm 0.45.2 ("requires newer version of
 * drizzle-orm"), so every `db:*` script currently fails.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { getDelegateClaimsDir } from "./fixtures/delegate-key";

const MIGRATE_ENTRYPOINT = "package/shared/lib/db/migrate.ts";

export default async function globalSetup(): Promise<void> {
  const claimsDir = getDelegateClaimsDir();
  rmSync(claimsDir, { recursive: true, force: true });
  mkdirSync(claimsDir, { recursive: true });

  const url = process.env.DATABASE_URL;

  if (!url) {
    if (process.env.CI) {
      throw new Error(
        "DATABASE_URL is required in CI. Start a Postgres service container and export the URL.",
      );
    }
    console.warn(
      "[playwright] DATABASE_URL not set: skipping migrations (local dev only). " +
        "Start the local database with: cd apps/noter && docker compose up -d",
    );
  } else {
    console.log("[playwright] Applying Drizzle migrations...");
    const result = spawnSync("pnpm", ["exec", "tsx", MIGRATE_ENTRYPOINT], {
      stdio: "inherit",
      env: process.env,
    });

    if (result.status !== 0) {
      throw new Error(`[playwright] Migration failed with exit code ${result.status}`);
    }
  }

  // Prime Next.js/Turbopack per-route compile cache for `/` and `/api/memory/health`.
  // On a cold runner the first hit can take 15 to 30s because routes compile lazily,
  // which can exceed navigationTimeout and flake tests until retries kick in.
  // Fetching here moves that cost into setup.
  const port = process.env.PORT || "3002";
  try {
    await fetch(`http://localhost:${port}/`);
    console.log("[playwright] Warmed / route");
  } catch {
    console.warn("[playwright] Could not warm / route (continuing anyway)");
  }

  try {
    await fetch(`http://localhost:${port}/api/memory/health`);
    console.log("[playwright] Warmed /api/memory/health route");
  } catch {
    console.warn("[playwright] Could not warm /api/memory/health route (continuing anyway)");
  }
}
