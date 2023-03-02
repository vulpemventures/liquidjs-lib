/// <reference types="node" />
export interface Xpub {
    extendedKey: Buffer;
    masterFingerprint: Buffer;
    derivationPath: string;
}
export interface PartialSig {
    pubkey: Buffer;
    signature: Buffer;
}
export interface Bip32Derivation {
    masterFingerprint: Buffer;
    pubkey: Buffer;
    path: string;
}
export interface WitnessUtxo {
    script: Buffer;
    value: number;
    nonce: Buffer;
    asset: Buffer;
    rangeProof?: Buffer;
    surjectionProof?: Buffer;
}
export declare type TapKeySig = Buffer;
export interface TapScriptSig extends PartialSig {
    leafHash: Buffer;
}
interface TapScript {
    leafVersion: number;
    script: Buffer;
}
export declare type ControlBlock = Buffer;
export interface TapLeafScript extends TapScript {
    controlBlock: ControlBlock;
}
export interface TapBip32Derivation extends Bip32Derivation {
    leafHashes: Buffer[];
}
export declare type TapInternalKey = Buffer;
export declare type TapMerkleRoot = Buffer;
export interface TapLeaf extends TapScript {
    depth: number;
}
export interface TapTree {
    leaves: TapLeaf[];
}
export interface RngOpts {
    rng?(arg0: number): Buffer;
}
export {};
