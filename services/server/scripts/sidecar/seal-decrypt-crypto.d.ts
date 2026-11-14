export class FallbackShareSubsetError extends Error {}

export interface DecryptBonehFranklinItemInput {
    encryptedData: Uint8Array;
    parsedObject?: any;
    derivedKeysByObjectId: Map<string, Uint8Array>;
    serverWeights?: Map<string, number>;
    totalServerWeight?: number;
    checkLEEncoding?: boolean;
    uskPointCache?: Map<string, unknown>;
}

export interface DecryptSliceItem {
    index: number;
    encryptedData: Uint8Array;
    fullId: string;
    threshold?: number;
    parsedObject?: any;
}

export interface DecryptBonehFranklinSliceInput {
    items: DecryptSliceItem[];
    derivedKeysById: Array<[string, Array<[string, Uint8Array]>]>;
    serverWeightsEntries?: Array<[string, number]>;
    totalServerWeight?: number;
    checkLEEncoding?: boolean;
}

export interface DecryptBonehFranklinSliceOutput {
    results: Array<{ index: number; decryptedData: string }>;
    errors: Array<{ index: number; code: string; error: string }>;
    fallbackIndices: number[];
}

export function combineSharesGF256(shares: Array<{ index: number; share: Uint8Array }>): Uint8Array;
export function decryptBonehFranklinItem(input: DecryptBonehFranklinItemInput): Uint8Array;
export function decryptBonehFranklinSlice(input: DecryptBonehFranklinSliceInput): DecryptBonehFranklinSliceOutput;
