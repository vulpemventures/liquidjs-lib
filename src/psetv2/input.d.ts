/// <reference types="node" />
import { BufferReader } from '../bufferutils';
import { Output, Transaction } from '../transaction';
import { Bip32Derivation, PartialSig, TapBip32Derivation, TapInternalKey, TapKeySig, TapLeafScript, TapMerkleRoot, TapScriptSig } from './interfaces';
import { KeyPair } from './key_pair';
import { ProprietaryData } from './proprietary_data';
export declare class Input {
    static fromBuffer(r: BufferReader): Input;
    nonWitnessUtxo?: Transaction;
    witnessUtxo?: Output;
    partialSigs?: PartialSig[];
    sighashType?: number;
    redeemScript?: Buffer;
    witnessScript?: Buffer;
    bip32Derivation?: Bip32Derivation[];
    finalScriptSig?: Buffer;
    finalScriptWitness?: Buffer;
    ripemd160Preimages?: Record<string, Buffer>;
    sha256Preimages?: Record<string, Buffer>;
    hash160Preimages?: Record<string, Buffer>;
    hash256Preimages?: Record<string, Buffer>;
    previousTxid: Buffer;
    previousTxIndex: number;
    sequence: number;
    requiredTimeLocktime?: number;
    requiredHeightLocktime?: number;
    tapKeySig?: TapKeySig;
    tapScriptSig?: TapScriptSig[];
    tapLeafScript?: TapLeafScript[];
    tapBip32Derivation?: TapBip32Derivation[];
    tapInternalKey?: TapInternalKey;
    tapMerkleRoot?: TapMerkleRoot;
    issuanceValue?: number;
    issuanceValueCommitment?: Buffer;
    issuanceValueRangeproof?: Buffer;
    issuanceInflationKeysRangeproof?: Buffer;
    peginTx?: Transaction;
    peginTxoutProof?: Buffer;
    peginGenesisHash?: Buffer;
    peginClaimScript?: Buffer;
    peginValue?: number;
    peginWitness?: Buffer;
    issuanceInflationKeys?: number;
    issuanceInflationKeysCommitment?: Buffer;
    issuanceBlindingNonce?: Buffer;
    issuanceAssetEntropy?: Buffer;
    utxoRangeProof?: Buffer;
    issuanceBlindValueProof?: Buffer;
    issuanceBlindInflationKeysProof?: Buffer;
    proprietaryData?: ProprietaryData[];
    unknowns?: KeyPair[];
    constructor(previousTxid?: Buffer, previousTxIndex?: number, sequence?: number);
    sanityCheck(): this;
    hasIssuance(): boolean;
    hasIssuanceBlinded(): boolean;
    hasReissuance(): boolean;
    isFinalized(): boolean;
    isTaproot(): boolean;
    getIssuanceAssetHash(): Buffer | undefined;
    getIssuanceInflationKeysHash(blindedIssuance: boolean): Buffer | undefined;
    getUtxo(): Output | undefined;
    toBuffer(): Buffer;
    private getKeyPairs;
}
