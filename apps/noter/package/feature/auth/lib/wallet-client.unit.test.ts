import { getWallets } from "@wallet-standard/core";
import { expect, it, vi } from "vitest";
import { connectWallet, detectWallets, signMessage } from "./wallet-client";

it("discovers, connects and signs with the shared Wallet Standard registry", async () => {
  vi.stubGlobal("window", {});
  let connected = false;
  const account = {
    address: `0x${"ab".repeat(32)}`, publicKey: new Uint8Array(32).fill(2),
    chains: ["sui:testnet"] as const, features: ["sui:signPersonalMessage"] as const,
  };
  const connect = vi.fn(async () => { connected = true; return { accounts: [account] }; });
  const signPersonalMessage = vi.fn(async () => ({ signature: "synthetic-signature" }));
  const unregister = getWallets().register({
    version: "1.0.0", name: "Slush", icon: "data:image/png;base64,AA==", chains: ["sui:testnet"],
    get accounts() { return connected ? [account] : []; },
    features: {
      "standard:connect": { version: "1.0.0", connect },
      "sui:signPersonalMessage": { version: "1.1.0", signPersonalMessage },
    },
  });
  try {
    expect(detectWallets()).toContain("slush");
    const connectedAccount = await connectWallet("slush");
    expect(connect).toHaveBeenCalledOnce();
    expect(connectedAccount.address).toBe(account.address);
    const result = await signMessage("slush", "login challenge", connectedAccount);
    expect(result).toEqual({ signature: "synthetic-signature", message: "login challenge" });
    expect(signPersonalMessage).toHaveBeenCalledWith({ message: new TextEncoder().encode("login challenge"), account });
  } finally {
    unregister();
    vi.unstubAllGlobals();
  }
});
