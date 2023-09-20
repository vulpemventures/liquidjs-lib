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
    makeScriptPubKey(inputs: Outpoint[], inputPrivateKey: Buffer, silentPaymentAddress: string, index?: number): Buffer;
    isMine(scriptPubKey: Buffer, inputs: Outpoint[], inputPublicKey: Buffer, scanSecretKey: Buffer, index?: number): boolean;
    makeSigningKey(inputs: Outpoint[], inputPublicKey: Buffer, spendSecretKey: Buffer, index?: number): Buffer;
}
export declare class SilentPaymentAddress {
    readonly spendPublicKey: Buffer;
    readonly scanPublicKey: Buffer;
    constructor(spendPublicKey: Buffer, scanPublicKey: Buffer);
    static decode(str: string): SilentPaymentAddress;
    encode(): string;
}
export declare function SPFactory(ecc: TinySecp256k1Interface): SilentPayment;
