import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, expect, it, vi } from "vitest";
import { POST } from "./route";

vi.mock("@/app/(auth)/auth", () => ({
  auth: async () => ({ user: { id: "blob-sdk-test-user" } }),
}));

afterEach(() => vi.unstubAllEnvs());

it("uploads through the real Blob SDK with the existing public-file contract", async () => {
  const received: { method?: string; pathname?: string | null; access?: string; suffix?: string; authorization?: string; body?: Buffer } = {};
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    received.method = req.method;
    received.pathname = new URL(req.url!, "http://localhost").searchParams.get("pathname");
    received.access = req.headers["x-vercel-blob-access"] as string;
    received.suffix = req.headers["x-add-random-suffix"] as string;
    received.authorization = req.headers.authorization;
    received.body = Buffer.concat(chunks);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      url: "https://fixture.public.blob.vercel-storage.com/image-random.png",
      downloadUrl: "https://fixture.public.blob.vercel-storage.com/image-random.png?download=1",
      pathname: received.pathname, contentType: "image/png", contentDisposition: "inline", etag: "fixture",
    }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  vi.stubEnv("VERCEL_BLOB_API_URL", `http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  vi.stubEnv("BLOB_READ_WRITE_TOKEN", "vercel_blob_rw_fixture_synthetic-token");
  const header = Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 })).toString("base64url");
  vi.stubEnv("VERCEL_OIDC_TOKEN", `${header}.${payload}.synthetic-signature`);
  vi.stubEnv("BLOB_STORE_ID", "store_ambient");
  try {
    const bytes = Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]);
    const form = new FormData();
    form.set("file", new Blob([bytes], { type: "image/png" }), "image.png");
    const response = await POST(new Request("http://app.test/api/files/upload", { method: "POST", body: form }));
    expect(response.status).toBe(200);
    expect((await response.json()).url).toContain("fixture.public.blob.vercel-storage.com");
    expect(received.method).toBe("PUT");
    expect(received.authorization).toBe("Bearer vercel_blob_rw_fixture_synthetic-token");
    expect(received.pathname).toMatch(/^users\/blob-sdk-test-user\/[0-9a-f-]+-image\.png$/);
    expect(received.access).toBe("public");
    expect(received.suffix).toBe("1");
    expect(received.body).toEqual(Buffer.from(bytes));
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
