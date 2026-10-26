/**
 * WALLET CLIENT
 * Handles Sui wallet connections using Wallet Standard
 */

import { getWallets, type Wallet } from '@wallet-standard/core';
import { WALLET_TYPES, type WalletType } from "../constant";

export type WalletAccount = {
  address: string;
  publicKey: Uint8Array;
};

/**
 * Detect available Sui wallets using Wallet Standard
 */
export function detectWallets(): WalletType[] {
  const wallets: WalletType[] = [];

  if (typeof window === "undefined") return wallets;

  const availableWallets = getWallets().get();

  // Check for Slush wallet using detection names from constants
  const slushWallet = availableWallets.find(w =>
    WALLET_TYPES.slush.detectionNames.some(name =>
      w.name.toLowerCase().includes(name.toLowerCase())
    )
  );

  if (slushWallet) {
    wallets.push("slush");
  }

  return wallets;
}

/**
 * Get Slush wallet instance using Wallet Standard
 */
export function getSlushWallet(): Wallet | null {
  if (typeof window === "undefined") return null;

  const availableWallets = getWallets().get();

  const slushWallet = availableWallets.find(w =>
    WALLET_TYPES.slush.detectionNames.some(name =>
      w.name.toLowerCase().includes(name.toLowerCase())
    )
  );


  return slushWallet || null;
}

/**
 * Check if wallet is installed
 */
export function isWalletInstalled(type: WalletType): boolean {
  return detectWallets().includes(type);
}

/**
 * Connect to Slush wallet and get account
 */
export async function connectWallet(type: WalletType): Promise<WalletAccount> {
  const wallet = getSlushWallet();

  if (!wallet) {
    console.error(`[Wallet Connect] ${type} wallet not found`);
    throw new Error(`${type} wallet not installed. Please install the Slush wallet extension.`);
  }

  try {
    // Check if already connected
    if (wallet.accounts.length > 0) {
      const account = wallet.accounts[0];
      return {
        address: account.address,
        publicKey: new Uint8Array(account.publicKey),
      };
    }

    // Connect wallet using standard:connect feature
    const connectFeature = wallet.features['standard:connect'] as { connect: () => Promise<{ accounts: readonly { address: string; publicKey: readonly number[] }[] }> } | undefined;

    if (!connectFeature) {
      throw new Error("Wallet does not support standard:connect feature");
    }

    const result = await connectFeature.connect();

    if (!result.accounts || result.accounts.length === 0) {
      throw new Error("No accounts found in wallet");
    }

    const account = result.accounts[0];

    return {
      address: account.address,
      publicKey: new Uint8Array(account.publicKey),
    };
  } catch (error) {
    console.error(`[Wallet Connect] Failed to connect to ${type}:`, error);
    throw new Error(`Failed to connect to ${type} wallet: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Sign a message with Slush wallet
 */
export async function signMessage(
  type: WalletType,
  message: string,
  account: WalletAccount
): Promise<{ signature: string; message: string }> {
  const wallet = getSlushWallet();

  if (!wallet) {
    throw new Error(`${type} wallet not found`);
  }

  try {
    // Find the account in the wallet
    const walletAccount = wallet.accounts.find(a => a.address === account.address);

    if (!walletAccount) {
      throw new Error("Account not found in wallet");
    }

    // Sign message using sui:signPersonalMessage feature
    const signFeature = wallet.features['sui:signPersonalMessage'] as {
      signPersonalMessage: (params: { message: Uint8Array; account: any }) => Promise<{ signature: string | Uint8Array }>
    } | undefined;

    if (!signFeature) {
      throw new Error("Wallet does not support sui:signPersonalMessage feature");
    }

    const messageBytes = new TextEncoder().encode(message);

    const result = await signFeature.signPersonalMessage({
      message: messageBytes,
      account: walletAccount,
    });

    // Wallet standard returns signature as a base64 string; older versions return Uint8Array
    const signatureBase64 = typeof result.signature === 'string'
      ? result.signature
      : Buffer.from(result.signature).toString("base64");

    return {
      signature: signatureBase64,
      message,
    };
  } catch (error) {
    console.error(`[Wallet Sign] Failed to sign message:`, error);
    throw new Error(`Failed to sign message: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Disconnect Slush wallet
 */
export async function disconnectWallet(type: WalletType): Promise<void> {
  const wallet = getSlushWallet();

  if (!wallet) {
    return;
  }

  try {
    const disconnectFeature = wallet.features['standard:disconnect'] as { disconnect: () => Promise<void> } | undefined;

    if (disconnectFeature) {
      await disconnectFeature.disconnect();
    }
  } catch (error) {
    console.error(`[Wallet Disconnect] Error:`, error);
  }
}
