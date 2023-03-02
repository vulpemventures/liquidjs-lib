/// <reference types="node" />
import { PartialSig, TapKeySig, TapScriptSig } from './interfaces';
import { Pset, ValidateSigFunction } from './pset';
export interface BIP174SigningData {
    partialSig: PartialSig;
    redeemScript?: Buffer;
    witnessScript?: Buffer;
}
export interface BIP371SigningData {
    tapKeySig?: TapKeySig;
    tapScriptSigs?: TapScriptSig[];
    genesisBlockHash: Buffer;
}
export declare class Signer {
    pset: Pset;
    constructor(pset: Pset);
    addSignature(inIndex: number, sigData: BIP174SigningData | BIP371SigningData, validator: ValidateSigFunction): this;
    private _addSignature;
    private _addTaprootSignature;
}
