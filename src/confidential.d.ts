/// <reference types="node" />
import { Output } from './transaction';
export interface UnblindOutputResult {
    value: string;
    valueBlindingFactor: Buffer;
    asset: Buffer;
    assetBlindingFactor: Buffer;
}
export interface RangeProofInfoResult {
    ctExp: number;
    ctBits: number;
    minValue: number;
    maxValue: number;
}
declare type Ecdh = (pubkey: Buffer, scalar: Buffer) => Buffer;
interface Ec {
    prvkeyNegate: (key: Buffer) => Buffer;
    prvkeyTweakAdd: (key: Buffer, tweak: Buffer) => Buffer;
    prvkeyTweakMul: (key: Buffer, tweak: Buffer) => Buffer;
}
interface Generator {
    generate: (seed: Buffer) => Buffer;
    generateBlinded(key: Buffer, blind: Buffer): Buffer;
    parse(input: Buffer): Buffer;
    serialize(generator: Buffer): Buffer;
}
interface Pedersen {
    commit(blindFactor: Buffer, value: string, generator: Buffer): Buffer;
    commitSerialize(commitment: Buffer): Buffer;
    commitParse(input: Buffer): Buffer;
    blindSum(blinds: Array<Buffer>, nneg?: number): Buffer;
    verifySum(commits: Array<Buffer>, negativeCommits: Array<Buffer>): boolean;
    blindGeneratorBlindSum(values: Array<string>, nInputs: number, blindGenerators: Array<Buffer>, blindFactors: Array<Buffer>): Buffer;
}
interface RangeProof {
    info(proof: Buffer): {
        exp: number;
        mantissa: string;
        minValue: string;
        maxValue: string;
    };
    verify(commit: Buffer, proof: Buffer, generator: Buffer, extraCommit?: Buffer): boolean;
    sign(commit: Buffer, blind: Buffer, nonce: Buffer, value: string, generator: Buffer, minValue?: string, base10Exp?: number, minBits?: number, message?: Buffer, extraCommit?: Buffer): Buffer;
    rewind(commit: Buffer, proof: Buffer, nonce: Buffer, generator: Buffer, extraCommit?: Buffer): {
        value: string;
        minValue: string;
        maxValue: string;
        blindFactor: Buffer;
        message: Buffer;
    };
}
interface SurjectionProof {
    serialize: (proof: {
        nInputs: number;
        usedInputs: Buffer;
        data: Buffer;
    }) => Buffer;
    parse: (proof: Buffer) => {
        nInputs: number;
        usedInputs: Buffer;
        data: Buffer;
    };
    initialize: (inputTags: Array<Buffer>, inputTagsToUse: number, outputTag: Buffer, maxIterations: number, seed: Buffer) => {
        proof: {
            nInputs: number;
            usedInputs: Buffer;
            data: Buffer;
        };
        inputIndex: number;
    };
    generate: (proof: {
        nInputs: number;
        usedInputs: Buffer;
        data: Buffer;
    }, inputTags: Array<Buffer>, outputTag: Buffer, inputIndex: number, inputBlindingKey: Buffer, outputBlindingKey: Buffer) => {
        nInputs: number;
        usedInputs: Buffer;
        data: Buffer;
    };
    verify: (proof: {
        nInputs: number;
        usedInputs: Buffer;
        data: Buffer;
    }, inputTags: Array<Buffer>, outputTag: Buffer) => boolean;
}
export interface ZKPInterface {
    ecdh: Ecdh;
    ec: Ec;
    surjectionproof: SurjectionProof;
    rangeproof: RangeProof;
    pedersen: Pedersen;
    generator: Generator;
}
export declare class Confidential {
    private zkp;
    constructor(zkp: ZKPInterface);
    nonceHash(pubkey: Buffer, privkey: Buffer): Buffer;
    valueBlindingFactor(inValues: string[], outValues: string[], inGenerators: Buffer[], outGenerators: Buffer[], inFactors: Buffer[], outFactors: Buffer[]): Buffer;
    valueCommitment(value: string, gen: Buffer, factor: Buffer): Buffer;
    assetCommitment(asset: Buffer, factor: Buffer): Buffer;
    unblindOutputWithKey(out: Output, blindingPrivKey: Buffer): UnblindOutputResult;
    unblindOutputWithNonce(out: Output, nonce: Buffer): UnblindOutputResult;
    rangeProofInfo(proof: Buffer): RangeProofInfoResult;
    /**
     *  nonceHash from blinding key + ephemeral key and then rangeProof computation
     */
    rangeProofWithNonceHash(value: string, blindingPubkey: Buffer, ephemeralPrivkey: Buffer, asset: Buffer, assetBlindingFactor: Buffer, valueBlindFactor: Buffer, valueCommit: Buffer, scriptPubkey: Buffer, minValue?: string, exp?: number, minBits?: number): Buffer;
    rangeProofVerify(valueCommit: Buffer, assetCommit: Buffer, proof: Buffer, script?: Buffer): boolean;
    /**
     *  rangeProof computation without nonceHash step.
     */
    rangeProof(value: string, nonce: Buffer, asset: Buffer, assetBlindingFactor: Buffer, valueBlindFactor: Buffer, valueCommit: Buffer, scriptPubkey: Buffer, minValue?: string, exp?: number, minBits?: number): Buffer;
    surjectionProof(outputAsset: Buffer, outputAssetBlindingFactor: Buffer, inputAssets: Buffer[], inputAssetBlindingFactors: Buffer[], seed: Buffer): Buffer;
    surjectionProofVerify(inAssets: Buffer[], inAssetBlinders: Buffer[], outAsset: Buffer, outAssetBlinder: Buffer, proof: Buffer): boolean;
    blindValueProof(value: string, valueCommit: Buffer, assetCommit: Buffer, valueBlinder: Buffer, nonce: Buffer): Buffer;
    blindAssetProof(asset: Buffer, assetCommit: Buffer, assetBlinder: Buffer): Buffer;
    assetBlindProofVerify(asset: Buffer, assetCommit: Buffer, proof: Buffer): boolean;
}
export declare function confidentialValueToSatoshi(value: Buffer): number;
export declare function satoshiToConfidentialValue(amount: number): Buffer;
export {};
