import { createDecipheriv, createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const sealEntryUrl = import.meta.resolve("@mysten/seal");
const sealRequire = createRequire(sealEntryUrl);

const [
    { bls12_381 },
    { bytesToNumberBE, bytesToNumberLE },
    { fromHex, toHex },
    {
        DecryptionError,
        EncryptedObject,
        InconsistentKeyServersError,
        InvalidCiphertextError,
        InvalidThresholdError,
        UnsupportedFeatureError,
        UserError,
    },
] = await Promise.all([
    import(pathToFileURL(sealRequire.resolve("@noble/curves/bls12-381.js")).href),
    import(pathToFileURL(sealRequire.resolve("@noble/curves/utils.js")).href),
    import(pathToFileURL(sealRequire.resolve("@mysten/bcs")).href),
    import(sealEntryUrl),
]);

const MAX_U8 = 255;
const SUI_ADDRESS_LENGTH = 32;
const ENCRYPTED_SHARE_LENGTH = 32;
const KEY_LENGTH = 32;
const GT_SIZE = 576;
const GT_PAIR_PERM = [0, 3, 1, 4, 2, 5];
const GT_PAIR_SIZE = GT_SIZE / GT_PAIR_PERM.length;

const HASH_TO_G1_DST = Buffer.from("SUI-SEAL-IBE-BLS12381-00", "utf8");
const KDF_DST = Buffer.from("SUI-SEAL-IBE-BLS12381-H2-00", "utf8");
const DERIVE_KEY_DST = Buffer.from("SUI-SEAL-IBE-BLS12381-H3-00", "utf8");
const PURPOSE_ENCRYPTED_RANDOMNESS = Buffer.from([0]);
const PURPOSE_DEM = Buffer.from([1]);

const AES_GCM_IV = Buffer.from([
    138, 55, 153, 253, 198, 46, 121, 219,
    160, 128, 89, 7, 214, 156, 148, 220,
]);
const HMAC_CTR_ENC_TAG = Buffer.from("HMAC-CTR-ENC", "utf8");
const HMAC_CTR_MAC_TAG = Buffer.from("HMAC-CTR-MAC", "utf8");

// Rijndael GF(2^8) generator 0x03 tables matching @mysten/seal/src/shamir.ts.
const GF256_EXP = new Uint8Array([
    1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53,
    95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170,
    229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49,
    83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
    76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136,
    131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154,
    181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163,
    254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160,
    251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65,
    195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117,
    159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
    155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84,
    252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202,
    69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14,
    18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23,
    57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246,
]);

const GF256_LOG = new Uint8Array([
    0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100,
    4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125,
    194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120, 101,
    47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142, 150,
    143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56, 102,
    221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16, 126,
    110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43,
    121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175,
    88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44,
    215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127,
    12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204,
    187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 151,
    178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83,
    57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68,
    17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103,
    74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7,
]);

// Bounded caches of strictly public curve points / address encodings.
const MAX_GID_CACHE = 2048;
const MAX_ADDR_CACHE = 512;
const gidBytesCache = new Map();
const addressBytesCache = new Map();

export class FallbackShareSubsetError extends Error {
    constructor(message) {
        super(message);
        this.name = "FallbackShareSubsetError";
    }
}

function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF256_EXP[(GF256_LOG[a - 1] + GF256_LOG[b - 1]) % 255];
}

function gfDiv(a, b) {
    if (b === 0) throw new Error("Division by zero in GF(256)");
    if (a === 0) return 0;
    return gfMul(a, GF256_EXP[255 - GF256_LOG[b - 1]]);
}

function combineSharesGF256(shares) {
    if (shares.length < 1) throw new Error("At least one share is required");
    const shareLength = shares[0].share.length;
    const seenIndices = new Set();
    for (const { index, share } of shares) {
        if (!Number.isInteger(index) || index <= 0 || index >= 256) {
            throw new Error(`Invalid value ${index} for GF256`);
        }
        if (share.length !== shareLength) throw new Error("All shares must have the same length");
        if (seenIndices.has(index)) throw new Error("Shares must have unique indices");
        seenIndices.add(index);
    }

    const k = shares.length;
    // Precompute Lagrange basis scalars at x = 0 once across all 32 secret bytes:
    // L_j(0) = (prod_{m} x_m) / (x_j * prod_{i != j} (x_i ^ x_j)) in GF(2^8).
    let allXProduct = 1;
    const invDenominators = new Uint8Array(k);
    for (let j = 0; j < k; j++) {
        const xj = shares[j].index;
        allXProduct = gfMul(allXProduct, xj);
        let prod = 1;
        for (let i = 0; i < k; i++) {
            if (i !== j) prod = gfMul(prod, shares[i].index ^ xj);
        }
        const denom = gfMul(xj, prod);
        invDenominators[j] = gfDiv(1, denom);
    }

    const result = new Uint8Array(shareLength);
    for (let byteIdx = 0; byteIdx < shareLength; byteIdx++) {
        let quotient = 0;
        for (let j = 0; j < k; j++) {
            quotient ^= gfMul(shares[j].share[byteIdx], invDenominators[j]);
        }
        result[byteIdx] = gfMul(allXProduct, quotient);
    }
    return result;
}

function getAddressBytes(objectId) {
    let cached = addressBytesCache.get(objectId);
    if (cached) return cached;
    const normalized = objectId.startsWith("0x") ? objectId.slice(2) : objectId;
    if (!/^[0-9a-fA-F]{1,64}$/.test(normalized)) {
        throw new UserError(`Invalid package ID ${objectId}`);
    }
    cached = fromHex(normalized.padStart(64, "0"));
    if (cached.length !== SUI_ADDRESS_LENGTH) {
        throw new Error(`Invalid object id ${objectId}`);
    }
    if (addressBytesCache.size >= MAX_ADDR_CACHE) {
        addressBytesCache.delete(addressBytesCache.keys().next().value);
    }
    addressBytesCache.set(objectId, cached);
    return cached;
}

function createFullIdHex(packageId, innerId) {
    const pkgBytes = getAddressBytes(packageId);
    const idBytes = fromHex(innerId);
    const combined = new Uint8Array(pkgBytes.length + idBytes.length);
    combined.set(pkgBytes, 0);
    combined.set(idBytes, pkgBytes.length);
    return { fullIdHex: toHex(combined), fullIdBytes: combined };
}

function getCachedHashToG1Bytes(fullIdHex, fullIdBytes) {
    let cached = gidBytesCache.get(fullIdHex);
    if (cached) {
        gidBytesCache.delete(fullIdHex);
        gidBytesCache.set(fullIdHex, cached);
        return cached;
    }
    const input = new Uint8Array(HASH_TO_G1_DST.length + fullIdBytes.length);
    input.set(HASH_TO_G1_DST, 0);
    input.set(fullIdBytes, HASH_TO_G1_DST.length);
    cached = bls12_381.G1.Point.fromAffine(bls12_381.G1.hashToCurve(input).toAffine()).toBytes();
    if (gidBytesCache.size >= MAX_GID_CACHE) {
        gidBytesCache.delete(gidBytesCache.keys().next().value);
    }
    gidBytesCache.set(fullIdHex, cached);
    return cached;
}

function fp12ToSealGtBytes(element) {
    const raw = bls12_381.fields.Fp12.toBytes(element);
    const out = new Uint8Array(GT_SIZE);
    for (let i = 0; i < GT_PAIR_PERM.length; i++) {
        const srcStart = GT_PAIR_PERM[i] * GT_PAIR_SIZE;
        out.set(raw.subarray(srcStart, srcStart + GT_PAIR_SIZE), i * GT_PAIR_SIZE);
    }
    return out;
}

function computeKdf(gtBytes, nonceBytes, gidBytes, objectId, index) {
    if (!Number.isInteger(index) || index < 0 || index > MAX_U8) {
        throw new Error(`Invalid index ${index}`);
    }
    const objectIdBytes = getAddressBytes(objectId);
    return createHash("sha3-256")
        .update(KDF_DST)
        .update(gtBytes)
        .update(nonceBytes)
        .update(gidBytes)
        .update(objectIdBytes)
        .update(Buffer.from([index]))
        .digest();
}

function deriveKeyFast(purposeTag, baseKey, encryptedShares, threshold, serviceObjectIds) {
    if (!Number.isInteger(threshold) || threshold <= 0 || threshold > MAX_U8) {
        throw new Error(`Invalid threshold ${threshold}`);
    }
    if (encryptedShares.length !== serviceObjectIds.length) {
        throw new Error(`Mismatched shares ${encryptedShares.length} and key servers ${serviceObjectIds.length}`);
    }
    if (baseKey.length !== KEY_LENGTH) {
        throw new Error(`Invalid base key ${baseKey}`);
    }
    const keyServerBytes = serviceObjectIds.map(getAddressBytes);
    for (const share of encryptedShares) {
        if (share.length !== ENCRYPTED_SHARE_LENGTH) {
            throw new Error(`Invalid encrypted shares ${encryptedShares}`);
        }
    }
    const hash = createHash("sha3-256")
        .update(DERIVE_KEY_DST)
        .update(baseKey)
        .update(purposeTag)
        .update(Buffer.from([threshold]));
    for (const share of encryptedShares) hash.update(share);
    for (const serverBytes of keyServerBytes) hash.update(serverBytes);
    return hash.digest();
}

function xorEqualLength(a, b) {
    if (a.length !== b.length) throw new Error("Invalid input");
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
}

function verifyNonceScalar(noncePoint, randomness, useBE) {
    try {
        if (randomness.length !== 32) throw new Error("Invalid scalar length");
        const r = useBE ? bytesToNumberBE(randomness) : bytesToNumberLE(randomness);
        if (r < 0n || r >= bls12_381.fields.Fr.ORDER) throw new Error("Scalar out of range");
        return bls12_381.G2.Point.BASE.multiply(r).equals(noncePoint);
    } catch {
        throw new InvalidCiphertextError("Invalid randomness");
    }
}

function verifyNonceAuto(noncePoint, randomness, checkLEEncoding) {
    if (checkLEEncoding) {
        try {
            if (verifyNonceScalar(noncePoint, randomness, false)) return true;
        } catch {
            // Fall through to big-endian check, matching verifyNonceWithLE in @mysten/seal.
        }
    }
    return verifyNonceScalar(noncePoint, randomness, true);
}

function decryptAes256GcmFast(demKey, aesPayload) {
    if (demKey.length !== 32) throw new Error("Key must be 32 bytes");
    const blob = aesPayload.blob instanceof Uint8Array ? aesPayload.blob : new Uint8Array(aesPayload.blob);
    if (blob.length < 16) throw new DecryptionError("Decryption failed");
    const aad = aesPayload.aad ? (aesPayload.aad instanceof Uint8Array ? aesPayload.aad : new Uint8Array(aesPayload.aad)) : new Uint8Array(0);
    try {
        const ciphertextBody = blob.subarray(0, blob.length - 16);
        const authTag = blob.subarray(blob.length - 16);
        const decipher = createDecipheriv("aes-256-gcm", demKey, AES_GCM_IV, { authTagLength: 16 });
        decipher.setAAD(aad);
        decipher.setAuthTag(authTag);
        const part1 = decipher.update(ciphertextBody);
        const part2 = decipher.final();
        const out = new Uint8Array(part1.length + part2.length);
        out.set(part1, 0);
        out.set(part2, part1.length);
        return out;
    } catch {
        throw new DecryptionError("Decryption failed");
    }
}

function u64LeBuffer(n) {
    const buf = Buffer.allocUnsafe(8);
    buf.writeBigUInt64LE(BigInt(n), 0);
    return buf;
}

function decryptHmac256CtrFast(demKey, hmacPayload) {
    if (demKey.length !== 32) throw new Error("Key must be 32 bytes");
    const aad = hmacPayload.aad ? new Uint8Array(hmacPayload.aad) : new Uint8Array(0);
    const blob = new Uint8Array(hmacPayload.blob);
    const expectedMac = new Uint8Array(hmacPayload.mac);
    const computedMac = createHmac("sha3-256", demKey)
        .update(HMAC_CTR_MAC_TAG)
        .update(u64LeBuffer(aad.length))
        .update(aad)
        .update(blob)
        .digest();
    if (computedMac.length !== expectedMac.length || !timingSafeEqual(computedMac, expectedMac)) {
        throw new DecryptionError(`Invalid MAC ${computedMac}`);
    }
    const blockSize = 32;
    const result = new Uint8Array(blob.length);
    for (let i = 0; i * blockSize < blob.length; i++) {
        const keystream = createHmac("sha3-256", demKey)
            .update(HMAC_CTR_ENC_TAG)
            .update(u64LeBuffer(i))
            .digest();
        const start = i * blockSize;
        const end = Math.min(start + blockSize, blob.length);
        for (let j = start; j < end; j++) {
            result[j] = blob[j] ^ keystream[j - start];
        }
    }
    return result;
}

function validateEncryptionServices(serviceObjectIds, threshold, serverWeights, totalServerWeight) {
    if (serverWeights && typeof totalServerWeight === "number") {
        for (const objectId of serviceObjectIds) {
            const configuredWeight = serverWeights.get(objectId) ?? 0;
            if (configuredWeight > 0) {
                let occurrences = 0;
                for (const candidate of serviceObjectIds) {
                    if (candidate === objectId) occurrences += 1;
                }
                if (configuredWeight !== occurrences) {
                    throw new InconsistentKeyServersError(
                        "Client's key servers must be a subset of the encrypted object's key servers",
                    );
                }
            }
        }
        if (threshold > totalServerWeight) {
            throw new InvalidThresholdError(`Invalid threshold ${threshold} for ${totalServerWeight} servers`);
        }
    }
}

/**
 * Protocol-identical Boneh-Franklin BLS12-381 threshold decryption matching
 * @mysten/seal@1.1.0, eliminating redundant pairings beyond `threshold`,
 * repeated `hashToG1(fullId)` curve hashes, repeated G1/G2 point re-encodings,
 * and per-blob WebCrypto key imports.
 */
export function decryptBonehFranklinItem({
    encryptedData,
    parsedObject,
    derivedKeysByObjectId,
    serverWeights,
    totalServerWeight,
    checkLEEncoding = false,
    uskPointCache,
}) {
    const encryptedObject = parsedObject ?? EncryptedObject.parse(encryptedData);
    if (!encryptedObject.encryptedShares?.BonehFranklinBLS12381) {
        throw new UnsupportedFeatureError("Encryption mode not supported");
    }

    const serviceObjectIds = encryptedObject.services.map(([objectId]) => objectId);
    validateEncryptionServices(serviceObjectIds, encryptedObject.threshold, serverWeights, totalServerWeight);

    const { fullIdHex, fullIdBytes } = createFullIdHex(encryptedObject.packageId, encryptedObject.id);
    const inKeystore = [];
    for (let i = 0; i < encryptedObject.services.length; i++) {
        if (derivedKeysByObjectId.has(encryptedObject.services[i][0])) {
            inKeystore.push(i);
        }
    }
    if (inKeystore.length < encryptedObject.threshold) {
        throw new Error("Not enough shares. Please fetch more keys.");
    }

    const bf = encryptedObject.encryptedShares.BonehFranklinBLS12381;
    const encryptedShares = bf.encryptedShares;
    if (encryptedShares.length !== encryptedObject.services.length) {
        throw new InvalidCiphertextError(
            `Mismatched shares ${encryptedShares.length} and services ${encryptedObject.services.length}`,
        );
    }

    const rawNonce = bf.nonce instanceof Uint8Array ? bf.nonce : new Uint8Array(bf.nonce);
    let noncePoint;
    try {
        noncePoint = bls12_381.G2.Point.fromBytes(rawNonce);
    } catch {
        throw new Error("Invalid G2 point");
    }
    const canonicalNonceBytes = rawNonce.length === 96 ? rawNonce : noncePoint.toBytes();
    const gidBytes = getCachedHashToG1Bytes(fullIdHex, fullIdBytes);

    // Compute pairings strictly for `threshold` shares instead of all cached servers.
    const selectedIndices = inKeystore.slice(0, encryptedObject.threshold);
    const perBlobGtCache = new Map();
    const shares = selectedIndices.map((serviceIdx) => {
        const [objectId, shareIndex] = encryptedObject.services[serviceIdx];
        let gtBytes = perBlobGtCache.get(objectId);
        if (!gtBytes) {
            const cacheKey = `${encryptedObject.id}:${objectId}`;
            let uskPoint = uskPointCache?.get(cacheKey);
            if (!uskPoint) {
                const uskBytes = derivedKeysByObjectId.get(objectId);
                try {
                    uskPoint = bls12_381.G1.Point.fromBytes(uskBytes);
                } catch {
                    throw new Error("Invalid G1 point");
                }
                uskPointCache?.set(cacheKey, uskPoint);
            }
            gtBytes = fp12ToSealGtBytes(bls12_381.pairing(uskPoint, noncePoint));
            perBlobGtCache.set(objectId, gtBytes);
        }
        const kdfMask = computeKdf(gtBytes, canonicalNonceBytes, gidBytes, objectId, shareIndex);
        return {
            index: shareIndex,
            share: xorEqualLength(encryptedShares[serviceIdx], kdfMask),
        };
    });

    const baseKey = combineSharesGF256(shares);
    const randomnessKey = deriveKeyFast(
        PURPOSE_ENCRYPTED_RANDOMNESS,
        baseKey,
        encryptedShares,
        encryptedObject.threshold,
        serviceObjectIds,
    );
    const randomness = xorEqualLength(bf.encryptedRandomness, randomnessKey);
    let nonceValid = false;
    try {
        nonceValid = verifyNonceAuto(noncePoint, randomness, checkLEEncoding);
    } catch (err) {
        if (inKeystore.length > encryptedObject.threshold) {
            throw new FallbackShareSubsetError(
                "Primary share subset produced out-of-field randomness; retry with full keystore",
            );
        }
        throw err;
    }
    if (!nonceValid) {
        if (inKeystore.length > encryptedObject.threshold) {
            throw new FallbackShareSubsetError("Primary share subset failed nonce verification; retry with full keystore");
        }
        throw new InvalidCiphertextError("Invalid nonce");
    }

    const demKey = deriveKeyFast(
        PURPOSE_DEM,
        baseKey,
        encryptedShares,
        encryptedObject.threshold,
        serviceObjectIds,
    );

    if (encryptedObject.ciphertext?.Aes256Gcm) {
        return decryptAes256GcmFast(demKey, encryptedObject.ciphertext.Aes256Gcm);
    }
    if (encryptedObject.ciphertext?.Hmac256Ctr) {
        return decryptHmac256CtrFast(demKey, encryptedObject.ciphertext.Hmac256Ctr);
    }
    throw new InvalidCiphertextError("Invalid ciphertext type");
}

function formatDecryptError(err) {
    if (err instanceof Error) return err.message || err.name;
    return String(err);
}

/**
 * Decrypt a slice of batch items synchronously using ephemeral per-call derived keys.
 * Ephemeral `uskPointCache` lives only for this call and is cleared before return.
 */
export function decryptBonehFranklinSlice({
    items,
    derivedKeysById,
    serverWeightsEntries,
    totalServerWeight,
    checkLEEncoding = false,
}) {
    const serverWeights = serverWeightsEntries ? new Map(serverWeightsEntries) : undefined;
    const keysMapById = new Map();
    for (const [id, entries] of derivedKeysById) {
        keysMapById.set(id, new Map(entries));
    }
    const uskPointCache = new Map();
    const results = [];
    const errors = [];
    const fallbackIndices = [];

    try {
        for (const item of items) {
            try {
                const derivedKeysByObjectId = keysMapById.get(item.fullId);
                if (!derivedKeysByObjectId || derivedKeysByObjectId.size === 0) {
                    fallbackIndices.push(item.index);
                    continue;
                }
                const decrypted = decryptBonehFranklinItem({
                    encryptedData: item.encryptedData,
                    derivedKeysByObjectId,
                    serverWeights,
                    totalServerWeight,
                    checkLEEncoding,
                    uskPointCache,
                });
                results.push({
                    index: item.index,
                    decryptedData: Buffer.from(decrypted).toString("base64"),
                });
            } catch (err) {
                if (
                    err instanceof UnsupportedFeatureError ||
                    err instanceof FallbackShareSubsetError ||
                    (err instanceof Error && err.message.startsWith("Not enough shares"))
                ) {
                    fallbackIndices.push(item.index);
                    continue;
                }
                errors.push({
                    index: item.index,
                    code: "DECRYPT_FAILED",
                    error: `decrypt failed: ${formatDecryptError(err)}`,
                });
            }
        }
        return { results, errors, fallbackIndices };
    } finally {
        uskPointCache.clear();
        for (const [, entries] of derivedKeysById) {
            for (const [, uskBytes] of entries) {
                if (uskBytes instanceof Uint8Array) uskBytes.fill(0);
            }
        }
    }
}
