/// <reference types="node" />
export declare type Outpoint = {
    txid: string;
    vout: number;
};
export interface TinySecp256k1Interface {
    privateMultiply: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
    pointMultiply: (point: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
    pointAdd: (point1: Uint8Array, point2: Uint8Array) => Uint8Array | null;
    pointFromScalar: (key: Uint8Array) => Uint8Array | null;
    privateAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
    privateNegate: (key: Uint8Array) => Uint8Array;
}
export interface SilentPayment {
    scriptPubKey(inputs: Outpoint[], inputPrivateKey: Buffer, silentPaymentAddress: string, index?: number): Buffer;
    ecdhSharedSecret(secret: Buffer, pubkey: Buffer, seckey: Buffer): Buffer;
    publicKey(spendPubKey: Buffer, index: number, ecdhSharedSecret: Buffer): Buffer;
    secretKey(spendPrivKey: Buffer, index: number, ecdhSharedSecret: Buffer): Buffer;
}
export declare class SilentPaymentAddress {
    readonly spendPublicKey: Buffer;
    readonly scanPublicKey: Buffer;
    constructor(spendPublicKey: Buffer, scanPublicKey: Buffer);
    static decode(str: string): SilentPaymentAddress;
    encode(): string;
}
export declare function SPFactory(ecc: TinySecp256k1Interface): SilentPayment;
