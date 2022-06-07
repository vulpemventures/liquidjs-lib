/// <reference types="node" />
import { KeyPair } from './key_pair';
export declare class ProprietaryData {
    static fromKeyPair(keyPair: KeyPair): ProprietaryData;
    static proprietaryKey(subType: number, keyData?: Buffer): Buffer;
    identifier: Buffer;
    subType: number;
    keyData: Buffer;
    value: Buffer;
    constructor(id: Buffer, subType: number, keyData: Buffer, value: Buffer);
}
