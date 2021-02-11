import { Output } from './transaction';
export declare function valueBlindingFactor(inValues: string[], outValues: string[], inGenerators: Buffer[], outGenerators: Buffer[], inFactors: Buffer[], outFactors: Buffer[]): Buffer;
export declare function valueCommitment(value: string, generator: Buffer, factor: Buffer): Buffer;
export declare function assetCommitment(asset: Buffer, factor: Buffer): Buffer;
export interface UnblindOutputResult {
    value: string;
    valueBlindingFactor: Buffer;
    asset: Buffer;
    assetBlindingFactor: Buffer;
}
export declare function unblindOutputWithKey(out: Output, blindingPrivKey: Buffer): UnblindOutputResult;
export declare function unblindOutputWithNonce(out: Output, nonce: Buffer): UnblindOutputResult;
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
