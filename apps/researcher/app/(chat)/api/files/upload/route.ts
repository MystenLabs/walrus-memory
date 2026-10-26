import { put } from "@vercel/blob";
import { NextResponse } from "next/server";
import { z } from "zod";

import { getSession } from "@/lib/auth/session";

const ALLOWED_TYPES = ["image/jpeg", "image/png", "application/pdf"];
const MAX_SIZE = 10 * 1024 * 1024; // 10MB

// Sanitize uploaded filename — strip path separators, restrict characters,
// and cap length to prevent path traversal via crafted filenames.
function sanitizeFilename(raw: string): string {
  return raw
    .replace(/[\/\\]/g, "")              // remove path separators
    .replace(/\.\./g, "")               // remove traversal sequences
    .replace(/[^a-zA-Z0-9.\-_]/g, "_") // replace remaining unsafe chars
    .slice(0, 100);                     // cap length
}

// Use Blob instead of File since File is not available in Node.js environment
const FileSchema = z.object({
  file: z
    .instanceof(Blob)
    .refine((file) => file.size <= MAX_SIZE, {
      message: "File size should be less than 10MB",
    })
    .refine((file) => ALLOWED_TYPES.includes(file.type), {
      message: "File type should be JPEG, PNG, or PDF",
    }),
});

export async function POST(request: Request) {
  const session = await getSession();

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (request.body === null) {
    return new Response("Request body is empty", { status: 400 });
  }

  try {
    const formData = await request.formData();
    const file = formData.get("file") as Blob;

    if (!file) {
      return NextResponse.json({ error: "No file uploaded" }, { status: 400 });
    }

    const validatedFile = FileSchema.safeParse({ file });

    if (!validatedFile.success) {
      const errorMessage = validatedFile.error.errors
        .map((error) => error.message)
        .join(", ");

      return NextResponse.json({ error: errorMessage }, { status: 400 });
    }

    // Get filename from formData since Blob doesn't have name property
    const rawFilename = (formData.get("file") as File).name;
    // Prefix with user-scoped namespace + random suffix to prevent
    // path traversal and cross-user key collisions in shared blob storage.
    const userId = session.user.id;
    const sanitized = sanitizeFilename(rawFilename);
    const blobKey = `users/${userId}/${crypto.randomUUID()}-${sanitized}`;
    const fileBuffer = await file.arrayBuffer();

    try {
      const data = await put(blobKey, fileBuffer, {
        access: "public",
        // Preserve the configured read/write token when ambient OIDC is present.
        token: process.env.BLOB_READ_WRITE_TOKEN,
        addRandomSuffix: true,
      });

      return NextResponse.json(data);
    } catch (_error) {
      return NextResponse.json({ error: "Upload failed" }, { status: 500 });
    }
  } catch (_error) {
    return NextResponse.json(
      { error: "Failed to process request" },
      { status: 500 }
    );
  }
}
