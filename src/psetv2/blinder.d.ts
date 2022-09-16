/// <reference types="node" />
import { UnblindOutputResult } from '../confidential';
import { Pset } from './pset';
export interface IssuanceBlindingArgs {
    index: number;
    issuanceAsset: Buffer;
    issuanceToken: Buffer;
    issuanceValueCommitment: Buffer;
    issuanceTokenCommitment: Buffer;
    issuanceValueRangeProof: Buffer;
    issuanceTokenRangeProof: Buffer;
    issuanceValueBlindProof: Buffer;
    issuanceTokenBlindProof: Buffer;
    issuanceValueBlinder: Buffer;
    issuanceTokenBlinder: Buffer;
}
export interface OutputBlindingArgs {
    index: number;
    nonce: Buffer;
    nonceCommitment: Buffer;
    valueCommitment: Buffer;
    assetCommitment: Buffer;
    valueRangeProof: Buffer;
    assetSurjectionProof: Buffer;
    valueBlindProof: Buffer;
    assetBlindProof: Buffer;
    valueBlinder: Buffer;
    assetBlinder: Buffer;
}
export declare type OwnedInput = {
    index: number;
} & UnblindOutputResult;
export interface PsetBlindingGenerator {
    computeAndAddToScalarOffset(scalar: Buffer, value: string, assetBlinder: Buffer, valueBlinder: Buffer): Promise<Buffer>;
    subtractScalars(inputScalar: Buffer, outputScalar: Buffer): Promise<Buffer>;
    lastValueCommitment(value: string, asset: Buffer, blinder: Buffer): Promise<Buffer>;
    lastBlindValueProof(value: string, valueCommitment: Buffer, assetCommitment: Buffer, blinder: Buffer): Promise<Buffer>;
    lastValueRangeProof(value: string, asset: Buffer, valueCommitment: Buffer, valueBlinder: Buffer, assetBlinder: Buffer, script: Buffer, nonce: Buffer): Promise<Buffer>;
}
export interface PsetBlindingValidator {
    verifyValueRangeProof(valueCommitment: Buffer, assetCommitment: Buffer, proof: Buffer, script: Buffer): Promise<boolean>;
    verifyAssetSurjectionProof(inAssets: Buffer[], inAssetBlinders: Buffer[], outAsset: Buffer, outAssetBlinder: Buffer, proof: Buffer): Promise<boolean>;
    verifyBlindValueProof(valueCommitment: Buffer, assetCommitment: Buffer, proof: Buffer): Promise<boolean>;
    verifyBlindAssetProof(asset: Buffer, assetCommitment: Buffer, proof: Buffer): Promise<boolean>;
}
export declare class Blinder {
    pset: Pset;
    ownedInputs: OwnedInput[];
    blindingValidator: PsetBlindingValidator;
    blindingGenerator: PsetBlindingGenerator;
    constructor(pset: Pset, ownedInputs: OwnedInput[], validator: PsetBlindingValidator, generator: PsetBlindingGenerator);
    blindNonLast(args: {
        issuanceBlindingArgs?: IssuanceBlindingArgs[];
        outputBlindingArgs: OutputBlindingArgs[];
    }): Promise<void>;
    blindLast(args: {
        issuanceBlindingArgs?: IssuanceBlindingArgs[];
        outputBlindingArgs: OutputBlindingArgs[];
    }): Promise<void>;
    private blind;
    private calculateInputScalar;
    private calculateOutputScalar;
    private calculateLastValueBlinder;
    private validateIssuanceBlindingArgs;
    private validateOutputBlindingArgs;
    private ownOutput;
    private validateBlindingData;
}
