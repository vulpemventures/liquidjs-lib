/// <reference types="node" />
import { Input } from './input';
import { Pset } from './pset';
export declare type FinalScriptsFunc = (inputIndex: number, // Which input is it?
input: Input, // The PSBT input contents
script: Buffer, // The "meaningful" locking script Buffer (redeemScript for P2SH etc.)
isSegwit: boolean, // Is it segwit?
isP2SH: boolean, // Is it P2SH?
isP2WSH: boolean) => {
    finalScriptSig: Buffer | undefined;
    finalScriptWitness: Buffer | undefined;
};
export declare type FinalTaprootScriptsFunc = (inputIndex: number, // Which input is it?
input: Input, // The PSBT input contents
tapLeafHashToFinalize?: Buffer) => {
    finalScriptWitness: Buffer | undefined;
};
export declare class Finalizer {
    pset: Pset;
    constructor(pset: Pset);
    finalize(): void;
    finalizeInput(inputIndex: number, finalScriptsFunc?: FinalScriptsFunc | FinalTaprootScriptsFunc): void;
    private _finalizeInput;
}
