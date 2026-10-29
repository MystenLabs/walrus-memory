import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { getAuthSecret } from "./auth-secret";

const ENVELOPE_VERSION = "v1";
const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const KEY_BYTES = 32;
const MIN_SECRET_LENGTH = 32;
const HKDF_INFO = "memwal-researcher-delegate-private-key-v1";

export class DelegateKeyCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DelegateKeyCryptoError";
  }
}

function resolveRawSecret(): string {
  const dedicated = process.env.DELEGATE_KEY_ENCRYPTION_SECRET;
  if (dedicated !== undefined) {
    if (dedicated.length < MIN_SECRET_LENGTH) {
      throw new DelegateKeyCryptoError(
        `DELEGATE_KEY_ENCRYPTION_SECRET must contain at least ${MIN_SECRET_LENGTH} characters`
      );
    }
    return dedicated;
  }
  return getAuthSecret();
}

function deriveEncryptionKey(secretOverride?: string): Buffer {
  const rawSecret = secretOverride ?? resolveRawSecret();
  if (rawSecret.length < MIN_SECRET_LENGTH) {
    throw new DelegateKeyCryptoError(
      `Encryption secret must contain at least ${MIN_SECRET_LENGTH} characters`
    );
  }
  const derived = hkdfSync(
    "sha256",
    Buffer.from(rawSecret, "utf8"),
    Buffer.alloc(0),
    Buffer.from(HKDF_INFO, "utf8"),
    KEY_BYTES
  );
  return Buffer.from(derived);
}

export function isEncryptedDelegateKeyEnvelope(value: string): boolean {
  return value.startsWith(`${ENVELOPE_VERSION}.`);
}

/**
 * Encrypt a delegate private key at rest using AES-256-GCM into a versioned
 * `v1.<nonce_b64url>.<ciphertext_and_tag_b64url>` envelope (matching the
 * relayer's `mcp_oauth_delegates.encrypted_private_key` envelope shape).
 */
export function encryptDelegatePrivateKey(
  plaintextKey: string,
  secretOverride?: string
): string {
  if (!plaintextKey || typeof plaintextKey !== "string") {
    throw new DelegateKeyCryptoError(
      "Delegate private key must be a non-empty string"
    );
  }
  if (isEncryptedDelegateKeyEnvelope(plaintextKey)) {
    throw new DelegateKeyCryptoError(
      "Delegate private key is already encrypted in a v1 envelope"
    );
  }

  const key = deriveEncryptionKey(secretOverride);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: AUTH_TAG_BYTES,
  });
  const ciphertext = Buffer.concat([
    cipher.update(plaintextKey, "utf8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]);

  return `${ENVELOPE_VERSION}.${nonce.toString("base64url")}.${ciphertext.toString("base64url")}`;
}

/**
 * Decrypt an at-rest `v1.<nonce_b64url>.<ciphertext_and_tag_b64url>` envelope
 * back into the delegate private key string. Fails closed on malformed or
 * tampered ciphertext.
 */
export function decryptDelegatePrivateKey(
  envelope: string,
  secretOverride?: string
): string {
  if (!envelope || typeof envelope !== "string") {
    throw new DelegateKeyCryptoError("Encrypted delegate key envelope is empty");
  }

  const parts = envelope.split(".");
  if (parts.length !== 3 || parts[0] !== ENVELOPE_VERSION) {
    throw new DelegateKeyCryptoError("Malformed delegate key envelope");
  }

  const [, nonceB64, payloadB64] = parts;
  if (!nonceB64 || !payloadB64) {
    throw new DelegateKeyCryptoError("Malformed delegate key envelope");
  }

  let nonce: Buffer;
  let payload: Buffer;
  try {
    nonce = Buffer.from(nonceB64, "base64url");
    payload = Buffer.from(payloadB64, "base64url");
  } catch {
    throw new DelegateKeyCryptoError("Malformed delegate key envelope");
  }

  if (nonce.length !== NONCE_BYTES || payload.length <= AUTH_TAG_BYTES) {
    throw new DelegateKeyCryptoError("Malformed delegate key envelope");
  }

  const ciphertext = payload.subarray(0, payload.length - AUTH_TAG_BYTES);
  const authTag = payload.subarray(payload.length - AUTH_TAG_BYTES);
  const key = deriveEncryptionKey(secretOverride);

  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, {
      authTagLength: AUTH_TAG_BYTES,
    });
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  } catch {
    throw new DelegateKeyCryptoError("Failed to decrypt delegate private key");
  }
}
