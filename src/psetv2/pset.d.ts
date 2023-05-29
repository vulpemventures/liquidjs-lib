/// <reference types="node" />
import { Transaction } from '../transaction';
import { PsetGlobal } from './globals';
import { PsetInput } from './input';
import { PartialSig, RngOpts } from './interfaces';
import { PsetOutput } from './output';
export declare const magicPrefix: Buffer;
export declare const magicPrefixWithSeparator: Buffer;
export declare type ValidateSigFunction = (pubkey: Buffer, msghash: Buffer, signature: Buffer) => boolean;
export declare type KeysGenerator = (opts?: RngOpts) => {
    publicKey: Buffer;
    privateKey: Buffer;
};
export interface KeysGeneratorSecp256k1Interface {
    pointFromScalar(privateKey: Uint8Array, compressed?: boolean): Uint8Array | null;
}
export interface ECDSAVerifier {
    verify(h: Uint8Array, Q: Uint8Array, signature: Uint8Array, strict?: boolean): boolean;
}
export interface SchnorrVerifier {
    verifySchnorr: (msghash: Buffer, pubkey: Uint8Array, signature: Uint8Array, extra?: Uint8Array) => boolean;
}
export declare class Pset {
    static fromBase64(data: string): Pset;
    static fromBuffer(buf: Buffer): Pset;
    static ECCKeysGenerator(ecc: KeysGeneratorSecp256k1Interface): KeysGenerator;
    static ECDSASigValidator(ecc: ECDSAVerifier): ValidateSigFunction;
    static SchnorrSigValidator(ecc: SchnorrVerifier): ValidateSigFunction;
    inputs: PsetInput[];
    outputs: PsetOutput[];
    globals: PsetGlobal;
    constructor(globals?: PsetGlobal, inputs?: PsetInput[], outputs?: PsetOutput[]);
    sanityCheck(): this;
    copy(): Pset;
    inputsModifiable(): boolean;
    outputsModifiable(): boolean;
    hasSighashSingle(): boolean;
    needsBlinding(): boolean;
    isFullyBlinded(): boolean;
    isComplete(): boolean;
    locktime(): number;
    unsignedTx(): Transaction;
    validateAllSignatures(validator: ValidateSigFunction): boolean;
    addInput(newInput: PsetInput): this;
    addOutput(newOutput: PsetOutput): this;
    validateInputSignatures(index: number, validator: ValidateSigFunction): boolean;
    validatePartialSignature(index: number, validator: ValidateSigFunction, ps: PartialSig): boolean;
    getInputPreimage(index: number, sighashType: number, genesisBlockHash?: Buffer, leafHash?: Buffer): Buffer;
    toBase64(): string;
    toBuffer(): Buffer;
    private isDuplicatedInput;
}
