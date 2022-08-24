/// <reference types="node" />
import { KeyPair } from './key_pair';
import { ProprietaryData } from './proprietary_data';
import BitSet from 'bitset';
import { BufferReader } from '../bufferutils';
import { Xpub } from './interfaces';
export declare class GlobalDuplicateFieldError extends Error {
    constructor(message?: string);
}
export declare class Global {
    static fromBuffer(r: BufferReader): Global;
    xpubs?: Xpub[];
    txVersion: number;
    inputCount: number;
    outputCount: number;
    txModifiable?: BitSet;
    version: number;
    fallbackLocktime?: number;
    scalars?: Buffer[];
    modifiable?: BitSet;
    proprietaryData?: ProprietaryData[];
    unknowns?: KeyPair[];
    constructor(txVersion?: number, inputCount?: number, outputCount?: number, version?: number, fallbackLocktime?: number);
    sanityCheck(): this;
    toBuffer(): Buffer;
    private getKeyPairs;
}
