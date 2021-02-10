import { WitnessUtxo } from 'bip174/src/lib/interfaces';
export interface BlindingData {
    satoshis: number;
    amountBlinder: string;
    asset: string;
    assetBlinder: string;
}
export declare function valueBlindingFactor(inValues: string[], outValues: string[], inGenerators: Buffer[], outGenerators: Buffer[], inFactors: Buffer[], outFactors: Buffer[]): Buffer;
export declare function valueCommitment(value: string, generator: Buffer, factor: Buffer): Buffer;
export declare function assetCommitment(asset: Buffer, factor: Buffer): Buffer;
export interface UnblindOutputResult {
    value: string;
    valueBlindingFactor: Buffer;
    asset: Buffer;
    assetBlindingFactor: Buffer;
}
export declare function unblindOutput(ephemeralPubkey: Buffer, blindingPrivkey: Buffer, rangeproof: Buffer, valueCommit: Buffer, asset: Buffer, scriptPubkey: Buffer): UnblindOutputResult;
export declare function unblindOutputWithKey(prevout: WitnessUtxo, blindingPrivKey: Buffer): BlindingData;
export declare function unblindOutputWithNonce(prevout: WitnessUtxo, nonce: Buffer): BlindingData;
export interface RangeProofInfoResult {
    ctExp: number;
    ctBits: number;
    minValue: number;
    maxValue: number;
}
export declare function rangeProofInfo(proof: Buffer): RangeProofInfoResult;
export declare function rangeProof(value: string, blindingPubkey: Buffer, ephemeralPrivkey: Buffer, asset: Buffer, assetBlindingFactor: Buffer, valueBlindFactor: Buffer, valueCommit: Buffer, scriptPubkey: Buffer, minValue?: string, exp?: number, minBits?: number): Buffer;
export declare function surjectionProof(outputAsset: Buffer, outputAssetBlindingFactor: Buffer, inputAssets: Buffer[], inputAssetBlindingFactors: Buffer[], seed: Buffer): Buffer;
export declare function confidentialValueToSatoshi(value: Buffer): number;
export declare function satoshiToConfidentialValue(amount: number): Buffer;
export declare function isUnconfidentialValue(value: Buffer): boolean;
