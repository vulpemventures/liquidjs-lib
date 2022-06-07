/// <reference types="node" />
import { TinySecp256k1Interface } from 'ecpair';
import { Transaction } from '../transaction';
import { Global } from './globals';
import { Input } from './input';
import { PartialSig } from './interfaces';
import { Output } from './output';
export declare const magicPrefix: Buffer;
export declare const magicPrefixWithSeparator: Buffer;
export declare type ValidateSigFunction = (pubkey: Buffer, msghash: Buffer, signature: Buffer) => boolean;
export declare class Pset {
    static fromBase64(data: string): Pset;
    static fromBuffer(buf: Buffer): Pset;
    static ECDSASigValidator(ecc: TinySecp256k1Interface): ValidateSigFunction;
    static SchnorrSigValidator(ecc: TinySecp256k1Interface): ValidateSigFunction;
    inputs: Input[];
    outputs: Output[];
    globals: Global;
    constructor(globals?: Global, inputs?: Input[], outputs?: Output[]);
    sanityCheck(): void;
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
    addInput(newInput: Input): void;
    addOutput(newOutput: Output): void;
    validateInputSignatures(index: number, validator: ValidateSigFunction): boolean;
    validatePartialSignature(index: number, validator: ValidateSigFunction, ps: PartialSig): boolean;
    getInputPreimage(index: number, sighashType: number): Buffer;
    toBase64(): string;
    toBuffer(): Buffer;
    private isDuplicatedInput;
}
