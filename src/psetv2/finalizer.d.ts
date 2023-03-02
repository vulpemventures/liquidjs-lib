/// <reference types="node" />
import { Pset } from './pset';
export declare type FinalizeFunc = (inIndex: number, pset: Pset) => {
    finalScriptSig?: Buffer;
    finalScriptWitness?: Buffer;
};
export declare class Finalizer {
    pset: Pset;
    constructor(pset: Pset);
    finalize(): void;
    finalizeInput(inIndex: number, finalizeFunc?: FinalizeFunc): this;
}
