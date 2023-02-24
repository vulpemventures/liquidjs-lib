/// <reference types="node" />
import type { Slip77Interface } from 'slip77';
import type { KeysGenerator, Pset } from './pset';
import type { IssuanceBlindingArgs, OutputBlindingArgs, OwnedInput } from './blinder';
import { ZKPInterface } from '../secp256k1-zkp';
export declare class ZKPValidator {
    private confidential;
    constructor(zkpLib: ZKPInterface);
    verifyValueRangeProof(proof: Buffer, valueCommitment: Buffer, assetCommitment: Buffer, script: Buffer): boolean;
    verifyAssetSurjectionProof(inAssets: Buffer[], inAssetBlinders: Buffer[], outAsset: Buffer, outAssetBlinder: Buffer, proof: Buffer): boolean;
    verifyBlindValueProof(proof: Buffer, valueCommitment: Buffer, assetCommitment: Buffer): boolean;
    verifyBlindAssetProof(asset: Buffer, assetCommit: Buffer, proof: Buffer): boolean;
}
declare type ZKPGeneratorOption = (g: ZKPGenerator) => void;
export declare class ZKPGenerator {
    private zkp;
    private ownedInputs?;
    private inBlindingKeys?;
    private masterBlindingKey?;
    private opts?;
    private confidential;
    constructor(zkp: ZKPInterface, ...options: ZKPGeneratorOption[]);
    static WithBlindingKeysOfInputs(inBlindingKeys: Buffer[]): ZKPGeneratorOption;
    static WithMasterBlindingKey(masterKey: Slip77Interface): ZKPGeneratorOption;
    static WithOwnedInputs(ownedInputs: OwnedInput[]): ZKPGeneratorOption;
    computeAndAddToScalarOffset(scalar: Buffer, value: string, assetBlinder: Buffer, valueBlinder: Buffer): Buffer;
    subtractScalars(inputScalar: Buffer, outputScalar: Buffer): Buffer;
    lastValueCommitment(value: string, asset: Buffer, blinder: Buffer): Buffer;
    lastBlindValueProof(value: string, valueCommit: Buffer, assetCommit: Buffer, blinder: Buffer): Buffer;
    lastValueRangeProof(value: string, asset: Buffer, valueCommitment: Buffer, assetCommitment: Buffer, valueBlinder: Buffer, assetBlinder: Buffer, nonce: Buffer, script: Buffer): Buffer;
    unblindInputs(pset: Pset, inIndexes?: number[]): OwnedInput[];
    blindIssuances(pset: Pset, blindingKeysByIndex: Record<number, Buffer>): IssuanceBlindingArgs[];
    blindOutputs(pset: Pset, keysGenerator: KeysGenerator, outIndexes?: number[]): OutputBlindingArgs[];
    private calculateScalarOffset;
    private unblindUtxo;
    private getInputAssetsAndBlinders;
    private maybeUnblindInUtxos;
}
export {};
