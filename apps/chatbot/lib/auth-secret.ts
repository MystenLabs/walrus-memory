const MIN_AUTH_SECRET_LENGTH = 32;
const BUILD_PLACEHOLDER = "build-time-placeholder-not-a-runtime-secret";

/**
 * Reads and validates AUTH_SECRET. NextAuth silently accepts any string
 * (including a short placeholder), which weakly signs session/guest JWTs
 * instead of failing — mirrors the guard in apps/researcher/lib/auth/enoki-challenge.ts.
 *
 * `next build` imports this module, so the builder placeholder is allowed
 * only during that phase. A copied placeholder is not a runtime secret.
 */
export function getAuthSecret(): string {
  const value = process.env.AUTH_SECRET;
  const building = process.env.NEXT_PHASE === "phase-production-build";
  if (!value || value.length < MIN_AUTH_SECRET_LENGTH) {
    throw new Error(
      `AUTH_SECRET must contain at least ${MIN_AUTH_SECRET_LENGTH} characters`
    );
  }
  if (!building && value === BUILD_PLACEHOLDER) {
    throw new Error("AUTH_SECRET is the build placeholder, not a runtime secret");
  }
  return value;
}
