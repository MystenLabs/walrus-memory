import { SuiGrpcClient } from "@mysten/sui/grpc";
import { fromBase64, normalizeSuiAddress, toHex } from "@mysten/sui/utils";
import { isTestEnvironment } from "@/lib/constants";
import { enokiConfig } from "@/lib/enoki/config";

export class DelegateAccountBindingError extends Error {
  constructor(
    message = "Delegate credentials do not match the Walrus Memory account"
  ) {
    super(message);
    this.name = "DelegateAccountBindingError";
  }
}

function publicKeyHex(value: unknown): string | null {
  if (typeof value === "string" && /^[0-9a-f]{64}$/i.test(value)) {
    return value.toLowerCase();
  }
  if (typeof value === "string") {
    try {
      const decoded = fromBase64(value);
      return decoded.length === 32 ? toHex(decoded).toLowerCase() : null;
    } catch {
      return null;
    }
  }
  if (
    Array.isArray(value) &&
    value.length === 32 &&
    value.every(
      (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255
    )
  ) {
    return toHex(new Uint8Array(value)).toLowerCase();
  }
  return null;
}

export function delegateAccountBindingError(
  objectType: unknown,
  fields: unknown,
  expected: { owner?: string; publicKeyHex: string; packageId: string }
): string | null {
  if (typeof objectType !== "string") return "Account object has no Move type";
  const [typePackage, moduleName, structName] = objectType.split("::");
  if (
    !typePackage ||
    normalizeSuiAddress(typePackage) !==
      normalizeSuiAddress(expected.packageId) ||
    moduleName !== "account" ||
    structName !== "MemWalAccount"
  ) {
    return "Object is not a configured MemWalAccount";
  }
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) {
    return "Account object has no readable fields";
  }

  const account = fields as Record<string, unknown>;
  if (account.active !== true) return "Walrus Memory account is inactive";
  if (
    expected.owner !== undefined &&
    (typeof account.owner !== "string" ||
      normalizeSuiAddress(account.owner) !==
        normalizeSuiAddress(expected.owner))
  ) {
    return "Walrus Memory account owner does not match the authenticated wallet";
  }
  if (!Array.isArray(account.delegate_keys)) {
    return "Walrus Memory account has no delegate key list";
  }
  const expectedKey = expected.publicKeyHex.toLowerCase();
  const registered = account.delegate_keys.some((entry) => {
    if (!entry || typeof entry !== "object") return false;
    return (
      publicKeyHex((entry as Record<string, unknown>).public_key) === expectedKey
    );
  });
  return registered
    ? null
    : "Delegate key is not registered on the Walrus Memory account";
}

export async function assertDelegateAccountBinding(input: {
  accountId: string;
  /** Wallet that must own the account. Omit only when no wallet is known. */
  owner?: string;
  publicKeyHex: string;
}): Promise<void> {
  if (!/^0x[0-9a-f]{64}$/i.test(input.accountId)) {
    throw new DelegateAccountBindingError("Invalid Walrus Memory account ID");
  }
  if (!enokiConfig.memwalPackageId) {
    throw new DelegateAccountBindingError(
      "Walrus Memory package is not configured"
    );
  }

  if (isTestEnvironment) {
    // Playwright runs have no chain to read. Serve a fixture object instead
    // of the gRPC fetch so the real validation below still executes — an
    // unknown account or unregistered key fails the same way it would live.
    const { mockDelegateAccountObject } = await import(
      "./delegate-account.mock"
    );
    const mocked = mockDelegateAccountObject(input.accountId);
    if (!mocked) {
      throw new DelegateAccountBindingError(
        "Unable to verify Walrus Memory account"
      );
    }
    const mockError = delegateAccountBindingError(mocked.type, mocked.json, {
      owner: input.owner,
      publicKeyHex: input.publicKeyHex,
      packageId: enokiConfig.memwalPackageId,
    });
    if (mockError) throw new DelegateAccountBindingError(mockError);
    return;
  }

  const network = enokiConfig.suiNetwork;
  const client = new SuiGrpcClient({
    network,
    baseUrl:
      process.env.SUI_GRPC_URL || `https://fullnode.${network}.sui.io:443`,
  });
  let response: Awaited<ReturnType<typeof client.getObject>>;
  try {
    response = await client.getObject({
      objectId: input.accountId,
      include: { json: true },
    });
  } catch {
    throw new DelegateAccountBindingError(
      "Unable to verify Walrus Memory account"
    );
  }

  const error = delegateAccountBindingError(
    response.object?.type,
    response.object?.json,
    {
      owner: input.owner,
      publicKeyHex: input.publicKeyHex,
      packageId: enokiConfig.memwalPackageId,
    }
  );
  if (error) throw new DelegateAccountBindingError(error);
}
