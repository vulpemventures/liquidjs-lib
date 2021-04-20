import { Issuance } from './issuance';
export declare const ZERO: Buffer;
export interface Output {
    script: Buffer;
    value: Buffer;
    asset: Buffer;
    nonce: Buffer;
    rangeProof?: Buffer;
    surjectionProof?: Buffer;
}
export interface Input {
    hash: Buffer;
    index: number;
    script: Buffer;
    sequence: number;
    witness: Buffer[];
    isPegin?: boolean;
    issuance?: Issuance;
    peginWitness?: Buffer[];
    issuanceRangeProof?: Buffer;
    inflationRangeProof?: Buffer;
}
export declare class Transaction {
    static readonly DEFAULT_SEQUENCE = 4294967295;
    static readonly SIGHASH_ALL = 1;
    static readonly SIGHASH_NONE = 2;
    static readonly SIGHASH_SINGLE = 3;
    static readonly SIGHASH_ANYONECANPAY = 128;
    static readonly ADVANCED_TRANSACTION_MARKER = 0;
    static readonly ADVANCED_TRANSACTION_FLAG = 1;
    static fromBuffer(buffer: Buffer, _NO_STRICT?: boolean): Transaction;
    static fromHex(hex: string): Transaction;
    static isCoinbaseHash(buffer: Buffer): boolean;
    version: number;
    locktime: number;
    flag: number;
    ins: Input[];
    outs: Output[];
    isCoinbase(): boolean;
    validateIssuance(assetBlindingNonce: Buffer, assetEntropy: Buffer, assetAmount: Buffer, tokenAmount: Buffer): boolean;
    addInput(hash: Buffer, index: number, sequence?: number, scriptSig?: Buffer, issuance?: Issuance): number;
    addOutput(scriptPubKey: Buffer, value: Buffer, asset: Buffer, nonce: Buffer, rangeProof?: Buffer, surjectionProof?: Buffer): number;
    hasWitnesses(): boolean;
    weight(): number;
    virtualSize(): number;
    byteLength(_ALLOW_WITNESS?: boolean): number;
    clone(): Transaction;
    /**
     * Hash transaction for signing a specific input.
     *
     * Bitcoin uses a different hash for each signed transaction input.
     * This method copies the transaction, makes the necessary changes based on the
     * hashType, and then hashes the result.
     * This hash can then be used to sign the provided transaction input.
     */
    hashForSignature(inIndex: number, prevOutScript: Buffer, hashType: number): Buffer;
    hashForWitnessV0(inIndex: number, prevOutScript: Buffer, value: Buffer, hashType: number): Buffer;
    getHash(forWitness?: boolean): Buffer;
    getId(): string;
    toBuffer(buffer?: Buffer, initialOffset?: number): Buffer;
    toHex(): string;
    setInputScript(index: number, scriptSig: Buffer): void;
    setWitness(index: number, witness: Buffer[]): void;
    setPeginWitness(index: number, peginWitness: Buffer[]): void;
    setInputIssuanceRangeProof(index: number, issuanceRangeProof: Buffer): void;
    setInputInflationRangeProof(index: number, inflationRangeProof: Buffer): void;
    setOutputNonce(index: number, nonce: Buffer): void;
    setOutputRangeProof(index: number, proof: Buffer): void;
    setOutputSurjectionProof(index: number, proof: Buffer): void;
    private __byteLength;
    private __toBuffer;
}
