/// <reference types="node" />
import { BufferReader } from '../bufferutils';
import { Bip32Derivation } from './interfaces';
import { KeyPair } from './key_pair';
import { ProprietaryData } from './proprietary_data';
export declare class Output {
    static fromBuffer(r: BufferReader): Output;
    redeemScript?: Buffer;
    witnessScript?: Buffer;
    bip32Derivation?: Bip32Derivation[];
    value: number;
    script?: Buffer;
    valueCommitment?: Buffer;
    asset: Buffer;
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
    sanityCheck(): void;
    isBlinded(): boolean;
    isPartiallyBlinded(): boolean;
    isFullyBlinded(): boolean;
    toBuffer(): Buffer;
    private getKeyPairs;
}
