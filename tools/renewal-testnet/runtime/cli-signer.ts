import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Signer } from '@mysten/sui/cryptography';
import { Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { verifyTransactionSignature } from '@mysten/sui/verify';

const exec = promisify(execFile);

/** Existing funding key stays inside the user's Sui CLI keystore. */
export class CliSigner extends Signer {
  constructor(readonly alias: string, publicKeyWithFlag: string) {
    super();
    const bytes = Buffer.from(publicKeyWithFlag, 'base64');
    if (bytes.length !== 33 || bytes[0] !== 0) throw new Error('Expected Ed25519 public metadata');
    this.publicKey = new Ed25519PublicKey(bytes.subarray(1));
  }
  private readonly publicKey: Ed25519PublicKey;
  getPublicKey() { return this.publicKey; }
  getKeyScheme() { return 'ED25519' as const; }
  async sign(_bytes: Uint8Array): Promise<Uint8Array> {
    throw new Error('Raw signing disabled; use the intended transaction-signing operation');
  }
  async signTransaction(bytes: Uint8Array) {
    const { stdout } = await exec('sui', ['keytool', 'sign', '--address', this.alias,
      '--data', Buffer.from(bytes).toString('base64'), '--intent', '000000', '--json'],
      { timeout: 30_000, maxBuffer: 16 * 1024 * 1024 });
    const result = JSON.parse(stdout);
    const signature = result.suiSignature ?? result.sui_signature;
    if (typeof signature !== 'string') throw new Error('Sui CLI omitted serialized signature');
    await verifyTransactionSignature(bytes, signature, { address: this.toSuiAddress() });
    return { bytes: Buffer.from(bytes).toString('base64'), signature };
  }
  async signPersonalMessage(_bytes: Uint8Array): Promise<{bytes: string; signature: string}> {
    throw new Error('CLI only signs TransactionData; synthetic owners use separate SDK keypairs');
  }
}
