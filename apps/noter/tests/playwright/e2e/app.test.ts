import { expect, test } from "@playwright/test";

test.describe("App shell", () => {
  test("landing page renders the delegate-key sign-in path", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Welcome to Noter" })).toBeVisible();
    await expect(page.getByText("AI-powered note-taking on Sui blockchain")).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in with delegate key/i })).toBeVisible();
    // Google/Enoki registers in a client effect and needs a real Enoki wallet
    // adapter. Placeholder CI keys may never produce one — don't fail the
    // shell test on that path. The Google flow stays a manual check.
  });

  test("delegate key form stays collapsed until requested", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByPlaceholder(/private key/i)).toBeHidden();

    await page.getByRole("button", { name: /sign in with delegate key/i }).click();

    await expect(page.getByPlaceholder(/account id/i)).toBeVisible();
    await expect(page.getByPlaceholder(/private key/i)).toBeVisible();
  });

  test("private key input is masked by default", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: /sign in with delegate key/i }).click();

    await expect(page.getByPlaceholder(/private key/i)).toHaveAttribute("type", "password");
  });

  test("/note bounces an unauthenticated visitor back to the landing page", async ({ page }) => {
    await page.goto("/note");

    await expect(page).toHaveURL("/");
    await expect(page.getByRole("heading", { name: "Welcome to Noter" })).toBeVisible();
  });

  test("memory health endpoint answers with a structured status", async ({ request }) => {
    const response = await request.get("/api/memory/health", {
      headers: { connection: "close" },
    });

    // 200 when a server-side MEMWAL key is configured, 503 when it isn't.
    expect([200, 503]).toContain(response.status());

    const body = await response.json();
    expect(body).toHaveProperty("status");
    expect(["ok", "not_configured"]).toContain(body.status);
  });
});
