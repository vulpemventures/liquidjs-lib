/// <reference types="node" />
import { payments } from '..';
import { PartialSig, RngOpts } from './interfaces';
export declare function getPayment(script: Buffer, scriptType: ScriptType, partialSig: PartialSig[]): payments.Payment;
export declare function hasSigs(neededSigs: number, partialSig?: any[], pubkeys?: Buffer[]): boolean;
export declare function witnessStackToScriptWitness(witness: Buffer[]): Buffer;
export declare function scriptWitnessToWitnessStack(buffer: Buffer): Buffer[];
declare type ScriptType = 'witnesspubkeyhash' | 'pubkeyhash' | 'multisig' | 'pubkey' | 'nonstandard';
export declare function classifyScript(script: Buffer): ScriptType;
export declare const isP2MS: (script: Buffer) => boolean;
export declare const isP2PK: (script: Buffer) => boolean;
export declare const isP2PKH: (script: Buffer) => boolean;
export declare const isP2WPKH: (script: Buffer) => boolean;
export declare const isP2WSH: (script: Buffer) => boolean;
export declare const isP2SH: (script: Buffer) => boolean;
export declare const isP2TR: (script: Buffer) => boolean;
export declare function pubkeyPositionInScript(pubkey: Buffer, script: Buffer): number;
export declare function randomBytes(options?: RngOpts): Buffer;
export {};
