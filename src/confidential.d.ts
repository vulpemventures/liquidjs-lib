/// <reference types="node" />
import { Output } from './transaction';
import { Pset, IssuanceBlindingArgs, OutputBlindingArgs, OwnedInput, PsetBlindingGenerator, PsetBlindingValidator } from './psetv2';
import { Slip77Interface } from 'slip77';
import { TinySecp256k1Interface } from 'ecpair';
export declare function valueBlindingFactor(inValues: string[], outValues: string[], inGenerators: Buffer[], outGenerators: Buffer[], inFactors: Buffer[], outFactors: Buffer[]): Promise<Buffer>;
export declare function valueCommitment(value: string, gen: Buffer, factor: Buffer): Promise<Buffer>;
export declare function assetCommitment(asset: Buffer, factor: Buffer): Promise<Buffer>;
export interface UnblindOutputResult {
    value: string;
    valueBlindingFactor: Buffer;
    asset: Buffer;
    assetBlindingFactor: Buffer;
}
export declare function unblindOutputWithKey(out: Output, blindingPrivKey: Buffer): Promise<UnblindOutputResult>;
export declare function unblindOutputWithNonce(out: Output, nonce: Buffer): Promise<UnblindOutputResult>;
export interface RangeProofInfoResult {
    ctExp: number;
    ctBits: number;
    minValue: number;
    maxValue: number;
}
export declare function rangeProofInfo(proof: Buffer): Promise<RangeProofInfoResult>;
/**
 *  nonceHash from blinding key + ephemeral key and then rangeProof computation
 */
export declare function rangeProofWithNonceHash(value: string, blindingPubkey: Buffer, ephemeralPrivkey: Buffer, asset: Buffer, assetBlindingFactor: Buffer, valueBlindFactor: Buffer, valueCommit: Buffer, scriptPubkey: Buffer, minValue?: string, exp?: number, minBits?: number): Promise<Buffer>;
export declare function rangeProofVerify(valueCommit: Buffer, assetCommit: Buffer, proof: Buffer, script?: Buffer): Promise<boolean>;
/**
 *  rangeProof computation without nonceHash step.
 */
export declare function rangeProof(value: string, nonce: Buffer, asset: Buffer, assetBlindingFactor: Buffer, valueBlindFactor: Buffer, valueCommit: Buffer, scriptPubkey: Buffer, minValue?: string, exp?: number, minBits?: number): Promise<Buffer>;
export declare function surjectionProof(outputAsset: Buffer, outputAssetBlindingFactor: Buffer, inputAssets: Buffer[], inputAssetBlindingFactors: Buffer[], seed: Buffer): Promise<Buffer>;
export declare function surjectionProofVerify(inAssets: Buffer[], inAssetBlinders: Buffer[], outAsset: Buffer, outAssetBlinder: Buffer, proof: Buffer): Promise<boolean>;
export declare function blindValueProof(value: string, valueCommit: Buffer, assetCommit: Buffer, valueBlinder: Buffer, opts?: RngOpts): Promise<Buffer>;
export declare function blindAssetProof(asset: Buffer, assetCommit: Buffer, assetBlinder: Buffer): Promise<Buffer>;
export declare function assetBlindProofVerify(asset: Buffer, assetCommit: Buffer, proof: Buffer): Promise<boolean>;
interface RngOpts {
    rng?(arg0: number): Buffer;
}
export declare type KeysGenerator = (opts?: RngOpts) => {
    publicKey: Buffer;
    privateKey: Buffer;
};
export declare class ZKPValidator implements PsetBlindingValidator {
    verifyValueRangeProof(valueCommit: Buffer, assetCommit: Buffer, proof: Buffer, script: Buffer): Promise<boolean>;
    verifyAssetSurjectionProof(inAssets: Buffer[], inAssetBlinders: Buffer[], outAsset: Buffer, outAssetBlinder: Buffer, proof: Buffer): Promise<boolean>;
    verifyBlindValueProof(valueCommit: Buffer, assetCommit: Buffer, proof: Buffer): Promise<boolean>;
    verifyBlindAssetProof(asset: Buffer, assetCommit: Buffer, proof: Buffer): Promise<boolean>;
}
export declare class ZKPGenerator implements PsetBlindingGenerator {
    static fromOwnedInputs(ownedInputs: OwnedInput[]): ZKPGenerator;
    static fromInBlindingKeys(inBlindingKeys: Buffer[]): ZKPGenerator;
    static fromMasterBlindingKey(masterKey: Buffer): ZKPGenerator;
    static ECCKeysGenerator(ec: TinySecp256k1Interface): KeysGenerator;
    ownedInputs?: OwnedInput[];
    inBlindingKeys?: Buffer[];
    masterBlindingKey?: Slip77Interface;
    opts?: RngOpts;
    private constructor();
    computeAndAddToScalarOffset(scalar: Buffer, value: string, assetBlinder: Buffer, valueBlinder: Buffer): Promise<Buffer>;
    subtractScalars(inputScalar: Buffer, outputScalar: Buffer): Promise<Buffer>;
    lastValueCommitment(value: string, asset: Buffer, blinder: Buffer): Promise<Buffer>;
    lastBlindValueProof(value: string, valueCommit: Buffer, assetCommit: Buffer, blinder: Buffer): Promise<Buffer>;
    lastValueRangeProof(value: string, asset: Buffer, valueCommit: Buffer, valueBlinder: Buffer, assetBlinder: Buffer, script: Buffer, nonce: Buffer): Promise<Buffer>;
    unblindInputs(pset: Pset, inIndexes?: number[]): Promise<OwnedInput[]>;
    blindIssuances(pset: Pset, blindingKeysByIndex: Record<number, Buffer>): Promise<IssuanceBlindingArgs[]>;
    blindOutputs(pset: Pset, keysGenerator: KeysGenerator, outIndexes?: number[], blindedIssuances?: IssuanceBlindingArgs[]): Promise<OutputBlindingArgs[]>;
    private calculateScalarOffset;
    private unblindUtxo;
    private getInputAssetsAndBlinders;
    private maybeUnblindInUtxos;
}
export declare function confidentialValueToSatoshi(value: Buffer): number;
export declare function satoshiToConfidentialValue(amount: number): Buffer;
export {};
