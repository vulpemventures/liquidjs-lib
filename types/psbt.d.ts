import * as confidential from './confidential';
import { KeyValue, PsbtGlobalUpdate, PsbtInput, PsbtInputUpdate, PsbtOutput, PsbtOutputUpdate, TransactionInput, WitnessUtxo, NonWitnessUtxo } from 'bip174-liquid/src/lib/interfaces';
import { Network } from './networks';
import { Transaction } from './transaction';
import { Signer, SignerAsync } from './ecpair';
import { IssuanceContract, Outpoint } from './issuance';
import { IssuanceBlindingKeys } from './types';
import { Psbt as PsbtBase } from 'bip174-liquid';
export interface AddIssuanceArgs {
    assetAmount: number;
    assetAddress: string;
    tokenAmount: number;
    tokenAddress?: string;
    precision: number;
    contract?: IssuanceContract;
    blindedIssuance?: boolean;
}
export interface AddReissuanceArgs {
    tokenPrevout: Outpoint;
    witnessUtxo?: WitnessUtxo;
    nonWitnessUtxo?: NonWitnessUtxo;
    prevoutBlinder: Buffer;
    entropy: Buffer;
    assetAmount: number;
    assetAddress: string;
    tokenAmount: number;
    tokenAddress: string;
    precision: number;
    blindedIssuance?: boolean;
}
/**
 * Psbt class can parse and generate a PSBT binary based off of the BIP174.
 * There are 6 roles that this class fulfills. (Explained in BIP174)
 *
 * Creator: This can be done with `new Psbt()`
 * Updater: This can be done with `psbt.addInput(input)`, `psbt.addInputs(inputs)`,
 *   `psbt.addOutput(output)`, `psbt.addOutputs(outputs)` when you are looking to
 *   add new inputs and outputs to the PSBT, and `psbt.updateGlobal(itemObject)`,
 *   `psbt.updateInput(itemObject)`, `psbt.updateOutput(itemObject)`
 *   addInput requires hash: Buffer | string; and index: number; as attributes
 *   and can also include any attributes that are used in updateInput method.
 *   addOutput requires script: Buffer; and value: number; and likewise can include
 *   data for updateOutput.
 *   For a list of what attributes should be what types. Check the bip174 library.
 *   Also, check the integration tests for some examples of usage.
 * Signer: There are a few methods. signAllInputs and signAllInputsAsync, which will search all input
 *   information for your pubkey or pubkeyhash, and only sign inputs where it finds
 *   your info. Or you can explicitly sign a specific input with signInput and
 *   signInputAsync. For the async methods you can create a SignerAsync object
 *   and use something like a hardware wallet to sign with. (You must implement this)
 * Combiner: psbts can be combined easily with `psbt.combine(psbt2, psbt3, psbt4 ...)`
 *   the psbt calling combine will always have precedence when a conflict occurs.
 *   Combine checks if the internal bitcoin transaction is the same, so be sure that
 *   all sequences, version, locktime, etc. are the same before combining.
 * Input Finalizer: This role is fairly important. Not only does it need to construct
 *   the input scriptSigs and witnesses, but it SHOULD verify the signatures etc.
 *   Before running `psbt.finalizeAllInputs()` please run `psbt.validateSignaturesOfAllInputs()`
 *   Running any finalize method will delete any data in the input(s) that are no longer
 *   needed due to the finalized scripts containing the information.
 * Transaction Extractor: This role will perform some checks before returning a
 *   Transaction object. Such as fee rate not being larger than maximumFeeRate etc.
 */
export declare class Psbt {
    readonly data: PsbtBase;
    static fromBase64(data: string, opts?: PsbtOptsOptional): Psbt;
    static fromHex(data: string, opts?: PsbtOptsOptional): Psbt;
    static fromBuffer(buffer: Buffer, opts?: PsbtOptsOptional): Psbt;
    private __CACHE;
    private opts;
    constructor(opts?: PsbtOptsOptional, data?: PsbtBase);
    readonly inputCount: number;
    combine(...those: Psbt[]): this;
    clone(): Psbt;
    setMaximumFeeRate(satoshiPerByte: number): void;
    setVersion(version: number): this;
    setLocktime(locktime: number): this;
    setInputSequence(inputIndex: number, sequence: number): this;
    addInputs(inputDatas: PsbtInputExtended[]): this;
    addInput(inputData: PsbtInputExtended): this;
    addIssuance(args: AddIssuanceArgs, inputIndex?: number): this;
    addReissuance(args: AddReissuanceArgs): this;
    addOutputs(outputDatas: PsbtOutputExtended[]): this;
    addOutput(outputData: PsbtOutputExtended): this;
    extractTransaction(disableFeeCheck?: boolean): Transaction;
    getFeeRate(): number;
    getFee(): number;
    finalizeAllInputs(): this;
    finalizeInput(inputIndex: number): this;
    validateSignaturesOfAllInputs(): boolean;
    validateSignaturesOfInput(inputIndex: number, pubkey?: Buffer): boolean;
    signAllInputsHD(hdKeyPair: HDSigner, sighashTypes?: number[]): this;
    signAllInputsHDAsync(hdKeyPair: HDSigner | HDSignerAsync, sighashTypes?: number[]): Promise<void>;
    signInputHD(inputIndex: number, hdKeyPair: HDSigner, sighashTypes?: number[]): this;
    signInputHDAsync(inputIndex: number, hdKeyPair: HDSigner | HDSignerAsync, sighashTypes?: number[]): Promise<void>;
    signAllInputs(keyPair: Signer, sighashTypes?: number[]): this;
    signAllInputsAsync(keyPair: Signer | SignerAsync, sighashTypes?: number[]): Promise<void>;
    signInput(inputIndex: number, keyPair: Signer, sighashTypes?: number[]): this;
    signInputAsync(inputIndex: number, keyPair: Signer | SignerAsync, sighashTypes?: number[]): Promise<void>;
    toBuffer(): Buffer;
    toHex(): string;
    toBase64(): string;
    updateGlobal(updateData: PsbtGlobalUpdate): this;
    updateInput(inputIndex: number, updateData: PsbtInputUpdate): this;
    updateOutput(outputIndex: number, updateData: PsbtOutputUpdate): this;
    blindOutputs(blindingDataLike: BlindingDataLike[], blindingPubkeys: Buffer[], opts?: RngOpts): Promise<this>;
    blindOutputsByIndex(inputsBlindingData: Map<number, BlindingDataLike>, outputsBlindingPubKeys: Map<number, Buffer>, issuancesBlindingKeys?: Map<number, IssuanceBlindingKeys>, opts?: RngOpts): Promise<this>;
    addUnknownKeyValToGlobal(keyVal: KeyValue): this;
    addUnknownKeyValToInput(inputIndex: number, keyVal: KeyValue): this;
    addUnknownKeyValToOutput(outputIndex: number, keyVal: KeyValue): this;
    clearFinalizedInput(inputIndex: number): this;
    private searchInputIndexForIssuance;
    private unblindInputsToIssuanceBlindingData;
    private blindInputs;
    private blindOutputsRaw;
    private rawBlindOutputs;
}
interface PsbtOptsOptional {
    network?: Network;
    maximumFeeRate?: number;
}
interface PsbtInputExtended extends PsbtInput, TransactionInput {
}
declare type PsbtOutputExtended = PsbtOutputExtendedScript | PsbtOutputExtendedAddress;
interface PsbtOutputExtendedScript extends PsbtOutput {
    script: string | Buffer;
    asset: string | Buffer;
    value: number | Buffer;
    nonce?: string | Buffer;
}
interface PsbtOutputExtendedAddress extends PsbtOutput {
    address: string;
    asset: string | Buffer;
    value: number | Buffer;
    nonce?: string | Buffer;
}
interface HDSignerBase {
    /**
     * DER format compressed publicKey buffer
     */
    publicKey: Buffer;
    /**
     * The first 4 bytes of the sha256-ripemd160 of the publicKey
     */
    fingerprint: Buffer;
}
interface HDSigner extends HDSignerBase {
    /**
     * The path string must match /^m(\/\d+'?)+$/
     * ex. m/44'/0'/0'/1/23 levels with ' must be hard derivations
     */
    derivePath(path: string): HDSigner;
    /**
     * Input hash (the "message digest") for the signature algorithm
     * Return a 64 byte signature (32 byte r and 32 byte s in that order)
     */
    sign(hash: Buffer): Buffer;
}
/**
 * Same as above but with async sign method
 */
interface HDSignerAsync extends HDSignerBase {
    derivePath(path: string): HDSignerAsync;
    sign(hash: Buffer): Promise<Buffer>;
}
interface RngOpts {
    rng?(arg0: number): Buffer;
}
export declare type BlindingDataLike = Buffer | confidential.UnblindOutputResult | undefined;
/**
 * Compute outputs blinders
 * @param inputsBlindingData the transaction inputs blinding data
 * @param outputsData data = [satoshis, asset] of output to blind ([string Buffer])
 * @returns an array of BlindingData[] corresponding of blinders to blind outputs specified in outputsData
 */
export declare function computeOutputsBlindingData(inputsBlindingData: confidential.UnblindOutputResult[], outputsData: Array<[string, Buffer]>): Promise<confidential.UnblindOutputResult[]>;
/**
 * toBlindingData convert a BlindingDataLike to UnblindOutputResult
 * @param blindDataLike blinding data "like" associated to a specific input I
 * @param witnessUtxo the prevout of the input I
 */
export declare function toBlindingData(blindDataLike: BlindingDataLike, witnessUtxo?: WitnessUtxo): Promise<confidential.UnblindOutputResult>;
export declare function validateAddIssuanceArgs(args: AddIssuanceArgs): void;
export declare function validateAddReissuanceArgs(args: AddReissuanceArgs): void;
export {};
