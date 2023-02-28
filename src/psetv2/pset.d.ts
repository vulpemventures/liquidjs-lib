/// <reference types="node" />
import type { Ecc as Secp256k1Interface } from '@vulpemventures/secp256k1-zkp';
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
export declare class Pset {
    static fromBase64(data: string): Pset;
    static fromBuffer(buf: Buffer): Pset;
    static ECCKeysGenerator(ec: Secp256k1Interface): KeysGenerator;
    static ECDSASigValidator(ecc: Secp256k1Interface): ValidateSigFunction;
    static SchnorrSigValidator(ecc: Secp256k1Interface): ValidateSigFunction;
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
