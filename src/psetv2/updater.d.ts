/// <reference types="node" />
import { TxOutput } from '..';
import { IssuanceContract } from '../issuance';
import { Transaction } from '../transaction';
import { Input, Output } from './creator';
import { Bip32Derivation, PartialSig } from './interfaces';
import { Pset, ValidateSigFunction } from './pset';
export interface AddInIssuanceArgs {
    assetAmount?: number;
    tokenAmount?: number;
    contract?: IssuanceContract;
    assetAddress?: string;
    tokenAddress?: string;
    blindedIssuance: boolean;
}
export interface AddInReissuanceArgs {
    entropy: string | Buffer;
    assetAmount: number;
    assetAddress: string;
    tokenAmount: number;
    tokenAddress: string;
    tokenAssetBlinder: string | Buffer;
}
export declare class Updater {
    pset: Pset;
    constructor(pset: Pset);
    addInputs(ins: Input[]): void;
    addOutputs(outs: Output[]): void;
    addInNonWitnessUtxo(inIndex: number, nonWitnessUtxo: Transaction): void;
    addInWitnessUtxo(inIndex: number, witnessUtxo: TxOutput): void;
    addInRedeemScript(inIndex: number, redeemScript: Buffer): void;
    addInWitnessScript(inIndex: number, witnessScript: Buffer): void;
    addInBIP32Derivation(inIndex: number, d: Bip32Derivation): void;
    addInSighashType(inIndex: number, sighashType: number): void;
    addInIssuance(inIndex: number, args: AddInIssuanceArgs): void;
    addInReissuance(inIndex: number, args: AddInReissuanceArgs): void;
    addInPartialSignature(inIndex: number, ps: PartialSig, validator: ValidateSigFunction): void;
    addOutBIP32Derivation(outIndex: number, d: Bip32Derivation): void;
    addOutRedeemScript(outIndex: number, redeemScript: Buffer): void;
    addOutWitnessScript(outIndex: number, witnessScript: Buffer): void;
    private validateIssuanceInput;
    private validateReissuanceInput;
}
