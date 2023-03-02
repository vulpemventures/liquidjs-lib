/// <reference types="node" />
import { BufferReader } from '../bufferutils';
export declare const ErrEmptyKey: Error;
export declare class Key {
    static fromBuffer(r: BufferReader): Key;
    keyType: number;
    keyData: Buffer;
    constructor(keyType: number, keyData?: Buffer);
    toBuffer(): Buffer;
}
export declare class KeyPair {
    static fromBuffer(r: BufferReader): KeyPair;
    key: Key;
    value: Buffer;
    constructor(key: Key, value?: Buffer);
    toBuffer(): Buffer;
}
