import { put } from "@vercel/blob";
import { NextResponse } from "next/server";
import { z } from "zod";

import { auth } from "@/app/(auth)/auth";

// Per-user sliding-window rate limit for uploads to prevent abuse
// (e.g. storage exhaustion, runaway costs). Kept in-memory since the chatbot
// app does not currently require a distributed limiter for this endpoint.
const UPLOAD_RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const UPLOAD_RATE_LIMIT_MAX = 20;
const uploadRateLimitStore = new Map<string, number[]>();

function checkUploadRateLimit(userId: string): {
  allowed: boolean;
  retryAfterSeconds: number;
} {
  const now = Date.now();
  const windowStart = now - UPLOAD_RATE_LIMIT_WINDOW_MS;
  const timestamps = (uploadRateLimitStore.get(userId) ?? []).filter(
    (t) => t > windowStart
  );

  if (timestamps.length >= UPLOAD_RATE_LIMIT_MAX) {
    const oldest = timestamps[0];
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((oldest + UPLOAD_RATE_LIMIT_WINDOW_MS - now) / 1000)
    );
    uploadRateLimitStore.set(userId, timestamps);
    return { allowed: false, retryAfterSeconds };
  }

  timestamps.push(now);
  uploadRateLimitStore.set(userId, timestamps);
  return { allowed: true, retryAfterSeconds: 0 };
}

// Sanitize uploaded filename — strip path separators, restrict characters,
// and cap length to prevent path traversal via crafted filenames.
function sanitizeFilename(raw: string): string {
  return raw
    .replace(/[/\\]/g, "")              // remove path separators
    .replace(/\.\./g, "")               // remove traversal sequences
    .replace(/[^a-zA-Z0-9.\-_]/g, "_") // replace remaining unsafe chars
    .slice(0, 100);                     // cap length
}

// Use Blob instead of File since File is not available in Node.js environment
const FileSchema = z.object({
  file: z
    .instanceof(Blob)
    .refine((file) => file.size <= 5 * 1024 * 1024, {
      message: "File size should be less than 5MB",
    })
    // Update the file type based on the kind of files you want to accept
    .refine((file) => ["image/jpeg", "image/png"].includes(file.type), {
      message: "File type should be JPEG or PNG",
    }),
});

export async function POST(request: Request) {
  const session = await auth();

  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Enforce per-user upload rate limit.
  const userId = session.user?.id;
  if (!userId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { allowed, retryAfterSeconds } = checkUploadRateLimit(userId);
  if (!allowed) {
    return NextResponse.json(
      { error: "Too many uploads. Please try again later." },
      {
        status: 429,
        headers: { "Retry-After": String(retryAfterSeconds) },
      }
    );
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
