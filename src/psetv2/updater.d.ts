/// <reference types="node" />
import { TxOutput } from '..';
import { IssuanceContract } from '../issuance';
import { Transaction } from '../transaction';
import { Bip32Derivation, PartialSig, TapBip32Derivation, TapInternalKey, TapLeafScript, TapMerkleRoot, TapScriptSig, TapTree } from './interfaces';
import { Pset, ValidateSigFunction } from './pset';
declare type OutputDestination = string | {
    script: Buffer;
    blindingPublicKey?: Buffer;
};
export interface IssuanceOpts {
    assetAmount?: number;
    tokenAmount?: number;
    contract?: IssuanceContract;
    assetAddress?: OutputDestination;
    tokenAddress?: OutputDestination;
    blindedIssuance?: boolean;
}
export interface ReissuanceOpts {
    entropy: string | Buffer;
    assetAmount: number;
    assetAddress: OutputDestination;
    tokenAmount: number;
    tokenAddress: OutputDestination;
    tokenAssetBlinder: string | Buffer;
    initialIssuanceBlinded?: boolean;
    blindedIssuance?: boolean;
}
export interface UpdaterInput {
    txid: string;
    txIndex: number;
    sequence?: number;
    heightLocktime?: number;
    timeLocktime?: number;
    witnessUtxo?: TxOutput;
    nonWitnessUtxo?: Transaction;
    witnessScript?: Buffer;
    sighashType?: number;
    tapInternalKey?: TapInternalKey;
    tapLeafScript?: TapLeafScript;
    tapMerkleRoot?: TapMerkleRoot;
    issaunceOpts?: IssuanceOpts;
    reissuanceOpts?: ReissuanceOpts;
    explicitValue?: number;
    explicitValueProof?: Buffer;
    explicitAsset?: Buffer;
    explicitAssetProof?: Buffer;
}
export interface UpdaterOutput {
    asset: string;
    amount: number;
    script?: Buffer;
    blindingPublicKey?: Buffer;
    blinderIndex?: number;
}
export declare class Updater {
    pset: Pset;
    constructor(pset: Pset);
    addInputs(ins: UpdaterInput[]): this;
    addOutputs(outs: UpdaterOutput[]): this;
    addInNonWitnessUtxo(inIndex: number, nonWitnessUtxo: Transaction): this;
    addInWitnessUtxo(inIndex: number, witnessUtxo: TxOutput): this;
    addInRedeemScript(inIndex: number, redeemScript: Buffer): this;
    addInWitnessScript(inIndex: number, witnessScript: Buffer): this;
    addInBIP32Derivation(inIndex: number, d: Bip32Derivation): this;
    addInSighashType(inIndex: number, sighashType: number): this;
    addInUtxoRangeProof(inIndex: number, proof: Buffer): this;
    addInIssuance(inIndex: number, args: IssuanceOpts): this;
    addInReissuance(inIndex: number, args: ReissuanceOpts): this;
    addInPartialSignature(inIndex: number, ps: PartialSig, validator: ValidateSigFunction): this;
    addInTimeLocktime(inIndex: number, locktime: number): this;
    addInHeightLocktime(inIndex: number, locktime: number): this;
    addInTapKeySig(inIndex: number, sig: Buffer, genesisBlockHash: Buffer, validator: ValidateSigFunction): this;
    addInTapScriptSig(inIndex: number, sig: TapScriptSig, genesisBlockHash: Buffer, validator: ValidateSigFunction): this;
    addInTapLeafScript(inIndex: number, tapLeafScript: TapLeafScript): this;
    addInTapBIP32Derivation(inIndex: number, d: TapBip32Derivation): this;
    addInTapInternalKey(inIndex: number, tapInternalKey: TapInternalKey): this;
    addInTapMerkleRoot(inIndex: number, tapMerkleRoot: TapMerkleRoot): this;
    addInExplicitValue(inIndex: number, explicitValue: number, explicitValueProof: Buffer): this;
    addInExplicitAsset(inIndex: number, explicitAsset: Buffer, explicitAssetProof: Buffer): this;
    addOutBIP32Derivation(outIndex: number, d: Bip32Derivation): this;
    addOutRedeemScript(outIndex: number, redeemScript: Buffer): this;
    addOutWitnessScript(outIndex: number, witnessScript: Buffer): this;
    addOutTapInternalKey(outIndex: number, tapInternalKey: TapInternalKey): this;
    addOutTapTree(outIndex: number, tapTree: TapTree): this;
    addOutTapBIP32Derivation(outIndex: number, d: TapBip32Derivation): this;
    private validateIssuanceInput;
    private validateReissuanceInput;
    private validateOutputIndex;
    private validateInputIndex;
}
export {};
