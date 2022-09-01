/// <reference types="node" />
import { TxOutput } from '..';
import { IssuanceContract } from '../issuance';
import { Transaction } from '../transaction';
import { Input, Output } from './creator';
import { Bip32Derivation, PartialSig, TapBip32Derivation, TapInternalKey, TapLeafScript, TapMerkleRoot, TapScriptSig, TapTree } from './interfaces';
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
    addInputs(ins: Input[]): this;
    addOutputs(outs: Output[]): this;
    addInNonWitnessUtxo(inIndex: number, nonWitnessUtxo: Transaction): this;
    addInWitnessUtxo(inIndex: number, witnessUtxo: TxOutput): this;
    addInRedeemScript(inIndex: number, redeemScript: Buffer): this;
    addInWitnessScript(inIndex: number, witnessScript: Buffer): this;
    addInBIP32Derivation(inIndex: number, d: Bip32Derivation): this;
    addInSighashType(inIndex: number, sighashType: number): this;
    addInUtxoRangeProof(inIndex: number, proof: Buffer): this;
    addInIssuance(inIndex: number, args: AddInIssuanceArgs): this;
    addInReissuance(inIndex: number, args: AddInReissuanceArgs): this;
    addInPartialSignature(inIndex: number, ps: PartialSig, validator: ValidateSigFunction): this;
    addInTapKeySig(inIndex: number, sig: Buffer, genesisBlockHash: Buffer, validator: ValidateSigFunction): this;
    addInTapScriptSig(inIndex: number, sig: TapScriptSig, genesisBlockHash: Buffer, validator: ValidateSigFunction): this;
    addInTapLeafScript(inIndex: number, leafScript: TapLeafScript): this;
    addInTapBIP32Derivation(inIndex: number, d: TapBip32Derivation): this;
    addInTapInternalKey(inIndex: number, tapInternalKey: TapInternalKey): this;
    addInTapMerkleRoot(inIndex: number, tapMerkleRoot: TapMerkleRoot): this;
    addOutBIP32Derivation(outIndex: number, d: Bip32Derivation): this;
    addOutRedeemScript(outIndex: number, redeemScript: Buffer): this;
    addOutWitnessScript(outIndex: number, witnessScript: Buffer): this;
    addOutTapInternalKey(outIndex: number, tapInternalKey: TapInternalKey): this;
    addOutTapTree(outIndex: number, tapTree: TapTree): this;
    addOutTapBIP32Derivation(outIndex: number, d: TapBip32Derivation): this;
    private validateIssuanceInput;
    private validateReissuanceInput;
}
