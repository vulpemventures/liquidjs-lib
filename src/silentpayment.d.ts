/// <reference types="node" />
import { bip341 } from '.';
export declare type Target = {
    silentPaymentAddress: string;
    value: number;
    asset: string;
};
export declare type Output = {
    scriptPubKey: string;
    value: number;
    asset: string;
};
export interface TinySecp256k1Interface extends bip341.BIP341Secp256k1Interface {
    privateMultiply: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
    pointMultiply: (point: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
    pointAdd: (point1: Uint8Array, point2: Uint8Array) => Uint8Array | null;
    pointFromScalar: (key: Uint8Array) => Uint8Array | null;
    privateAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
    privateNegate: (key: Uint8Array) => Uint8Array;
    ecdh: (pubkey: Uint8Array, privkey: Uint8Array) => Uint8Array;
}
export declare class SilentPaymentAddress {
    readonly spendPublicKey: Buffer;
    readonly scanPublicKey: Buffer;
    constructor(spendPublicKey: Buffer, scanPublicKey: Buffer);
    static decode(str: string): SilentPaymentAddress;
    encode(): string;
}
export declare class SilentPayment {
    private ecc;
    constructor(ecc: TinySecp256k1Interface);
    /**
     * create the transaction outputs sending outpoints identified by *outpointHash* to the *targets*
     * @param inputsOutpointsHash hash of the input outpoints sent to the targets
     * @param sumInputsPrivKeys sum of input private keys
     * @param targets silent payment addresses receiving value/asset pair
     * @returns a list of "silent-payment" taproot outputs
     */
    pay(inputsOutpointsHash: Buffer, sumInputsPrivKeys: Buffer, targets: Target[]): Output[];
    sumSecretKeys(outpointKeys: {
        key: Buffer;
        isTaproot?: boolean;
    }[]): Buffer;
    sumPublicKeys(keys: Buffer[]): Buffer;
    makeSharedSecret(inputsOutpointsHash: Buffer, inputPubKey: Buffer, scanSecretKey: Buffer): Buffer;
    makePublicKey(spendPubKey: Buffer, index: number, ecdhSharedSecret: Buffer): Buffer;
    makeSecretKey(spendPrivKey: Buffer, index: number, ecdhSharedSecret: Buffer): Buffer;
}
export declare function ser32(i: number): Buffer;
export declare function outpointsHash(parameters: {
    txid: string;
    vout: number;
}[]): Buffer;
