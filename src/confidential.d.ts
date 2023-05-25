/// <reference types="node" />
import { Secp256k1Interface as ZKPInterface } from './secp256k1-zkp';
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
export declare class Confidential {
    private zkp;
    constructor(zkp: ZKPInterface);
    nonceHash(pubkey: Buffer, privkey: Buffer): Buffer;
    valueBlindingFactor(inValues: string[], outValues: string[], inAssetBlinders: Buffer[], outAssetBlinders: Buffer[], inValueBlinders: Buffer[], outValueBlinders: Buffer[]): Buffer;
    valueCommitment(value: string, generator: Buffer, blinder: Buffer): Buffer;
    assetCommitment(asset: Buffer, factor: Buffer): Buffer;
    unblindOutputWithKey(out: Output, blindingPrivKey: Buffer): UnblindOutputResult;
    unblindOutputWithNonce(out: Output, nonce: Buffer): UnblindOutputResult;
    rangeProofInfo(proof: Buffer): RangeProofInfoResult;
    /**
     *  nonceHash from blinding key + ephemeral key and then rangeProof computation
     */
    rangeProofWithNonceHash(blindingPubkey: Buffer, ephemeralPrivkey: Buffer, value: string, asset: Buffer, valueCommitment: Buffer, assetCommitment: Buffer, valueBlinder: Buffer, assetBlinder: Buffer, scriptPubkey: Buffer, minValue?: string, exp?: string, minBits?: string): Buffer;
    rangeProofVerify(proof: Buffer, valueCommitment: Buffer, assetCommitment: Buffer, script?: Buffer): boolean;
    /**
     *  rangeProof computation without nonceHash step.
     */
    rangeProof(value: string, asset: Buffer, valueCommitment: Buffer, assetCommitment: Buffer, valueBlinder: Buffer, assetBlinder: Buffer, nonce: Buffer, scriptPubkey: Buffer, minValue?: string, exp?: string, minBits?: string): Buffer;
    surjectionProof(outputAsset: Buffer, outputAssetBlindingFactor: Buffer, inputAssets: Buffer[], inputAssetBlindingFactors: Buffer[], seed: Buffer): Buffer;
    surjectionProofVerify(inAssets: Buffer[], inAssetBlinders: Buffer[], outAsset: Buffer, outAssetBlinder: Buffer, proof: Buffer): boolean;
    blindValueProof(value: string, valueCommitment: Buffer, assetCommitment: Buffer, valueBlinder: Buffer, nonce: Buffer): Buffer;
    blindAssetProof(asset: Buffer, assetCommitment: Buffer, assetBlinder: Buffer): Buffer;
    assetBlindProofVerify(asset: Buffer, assetCommitment: Buffer, proof: Buffer): boolean;
}
export declare function confidentialValueToSatoshi(value: Buffer): number;
export declare function satoshiToConfidentialValue(amount: number): Buffer;
