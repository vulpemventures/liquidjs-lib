/// <reference types="node" />
import { BufferReader } from '../bufferutils';
import { Bip32Derivation, TapBip32Derivation, TapInternalKey, TapTree } from './interfaces';
import { KeyPair } from './key_pair';
import { ProprietaryData } from './proprietary_data';
export declare class OutputDuplicateFieldError extends Error {
    constructor(message?: string);
}
export declare class PsetOutput {
    static fromBuffer(r: BufferReader): PsetOutput;
    redeemScript?: Buffer;
    witnessScript?: Buffer;
    bip32Derivation?: Bip32Derivation[];
    value: number;
    script?: Buffer;
    tapBip32Derivation?: TapBip32Derivation[];
    tapTree?: TapTree;
    tapInternalKey?: TapInternalKey;
    valueCommitment?: Buffer;
    asset?: Buffer;
    assetCommitment?: Buffer;
    valueRangeproof?: Buffer;
    assetSurjectionProof?: Buffer;
    blindingPubkey?: Buffer;
    ecdhPubkey?: Buffer;
    blinderIndex?: number;
    blindValueProof?: Buffer;
    blindAssetProof?: Buffer;
    proprietaryData?: ProprietaryData[];
    unknowns?: KeyPair[];
    constructor(value?: number, asset?: Buffer, script?: Buffer);
    sanityCheck(): this;
    needsBlinding(): boolean;
    isPartiallyBlinded(): boolean;
    isFullyBlinded(): boolean;
    isTaproot(): boolean;
    toBuffer(): Buffer;
    private getKeyPairs;
}
