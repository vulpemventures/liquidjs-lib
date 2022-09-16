/// <reference types="node" />
export declare const hardenedKeyStart = 2147483648;
export declare function decodeBip32Derivation(buf: Buffer): {
    masterFingerprint: Buffer;
    path: string;
};
export declare function encodeBIP32Derivation(masterFingerprint: Buffer, path: string): Buffer;
