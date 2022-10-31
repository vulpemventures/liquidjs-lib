/// <reference types="node" />
import { UnblindOutputResult } from '../confidential';
import { Pset } from './pset';
import { ZKPGenerator, ZKPValidator } from './zkp';
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
export declare class Blinder {
    pset: Pset;
    ownedInputs: OwnedInput[];
    blindingValidator: ZKPValidator;
    blindingGenerator: ZKPGenerator;
    constructor(pset: Pset, ownedInputs: OwnedInput[], validator: ZKPValidator, generator: ZKPGenerator);
    blindNonLast(args: {
        issuanceBlindingArgs?: IssuanceBlindingArgs[];
        outputBlindingArgs: OutputBlindingArgs[];
    }): void;
    blindLast(args: {
        issuanceBlindingArgs?: IssuanceBlindingArgs[];
        outputBlindingArgs: OutputBlindingArgs[];
    }): void;
    private blind;
    private calculateInputScalar;
    private calculateOutputScalar;
    private calculateLastValueBlinder;
    private validateIssuanceBlindingArgs;
    private validateOutputBlindingArgs;
    private ownOutput;
    private validateBlindingData;
}
