/// <reference types="node" />
import { PartialSig } from './interfaces';
import { Pset, ValidateSigFunction } from './pset';
export declare class Signer {
    pset: Pset;
    constructor(pset: Pset);
    signInput(inIndex: number, psig: PartialSig, validator: ValidateSigFunction, redeemScript?: Buffer, witnessScript?: Buffer): void;
}
