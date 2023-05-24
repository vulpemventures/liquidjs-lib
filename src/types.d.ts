/// <reference types="node" />
export declare const typeforce: any;
export declare function isPoint(p: Buffer | number | undefined | null): boolean;
export declare function UInt31(value: number): boolean;
export declare function BIP32Path(value: string): boolean;
export declare namespace BIP32Path {
    var toJSON: () => string;
}
export declare function Signer(obj: any): boolean;
export declare function Satoshi(value: number): boolean;
export declare const ECPoint: any;
export declare const Network: any;
export interface IssuanceBlindingKeys {
    assetKey?: Buffer;
    tokenKey?: Buffer;
}
export interface XOnlyPointAddTweakResult {
    parity: 1 | 0;
    xOnlyPubkey: Uint8Array;
}
export interface Tapleaf {
    output: Buffer;
    version?: number;
}
export declare const TAPLEAF_VERSION_MASK = 254;
export declare function isTapleaf(o: any): o is Tapleaf;
/**
 * Binary tree repsenting script path spends for a Taproot input.
 * Each node is either a single Tapleaf, or a pair of Tapleaf | Taptree.
 * The tree has no balancing requirements.
 */
export declare type Taptree = [Taptree | Tapleaf, Taptree | Tapleaf] | Tapleaf;
export declare function isTaptree(scriptTree: any): scriptTree is Taptree;
export interface TinySecp256k1Interface {
    isXOnlyPoint(p: Uint8Array): boolean;
    xOnlyPointAddTweak(p: Uint8Array, tweak: Uint8Array): XOnlyPointAddTweakResult | null;
    privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
    privateNegate(d: Uint8Array): Uint8Array;
}
export declare const Buffer256bit: any;
export declare const Hash160bit: any;
export declare const Hash256bit: any;
export declare const ConfidentialCommitment: any;
export declare const AssetBufferWithFlag: any;
export declare const AssetBuffer: any;
export declare const ConfidentialValue: any;
export declare const BufferOne: any;
export declare const Number: any;
export declare const Array: any;
export declare const Boolean: any;
export declare const String: any;
export declare const Buffer: any;
export declare const Hex: any;
export declare const Object: any;
export declare const maybe: any;
export declare const tuple: any;
export declare const UInt8: any;
export declare const UInt32: any;
export declare const Function: any;
export declare const BufferN: any;
export declare const Null: any;
export declare const oneOf: any;
export interface ConfidentialSecp256k1Interface {
    ecc: {
        privateNegate: (key: Uint8Array) => Uint8Array;
        privateAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
        privateMul: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
    };
    ecdh: (pubkey: Uint8Array, scalar: Uint8Array) => Uint8Array;
    pedersen: {
        commitment(value: string, generator: Uint8Array, blinder: Uint8Array): Uint8Array;
        blindGeneratorBlindSum(values: Array<string>, assetBlinders: Array<Uint8Array>, valueBlinders: Array<Uint8Array>, nInputs: number): Uint8Array;
    };
    generator: {
        generate: (seed: Uint8Array) => Uint8Array;
        generateBlinded(key: Uint8Array, blinder: Uint8Array): Uint8Array;
    };
    rangeproof: {
        info(proof: Uint8Array): {
            exp: string;
            mantissa: string;
            minValue: string;
            maxValue: string;
        };
        verify(proof: Uint8Array, valueCommitment: Uint8Array, assetCommitment: Uint8Array, extraCommit?: Uint8Array): boolean;
        sign(value: string, valueCommitment: Uint8Array, assetCommitment: Uint8Array, valueBlinder: Uint8Array, nonce: Uint8Array, minValue?: string, base10Exp?: string, minBits?: string, message?: Uint8Array, extraCommit?: Uint8Array): Uint8Array;
        rewind(proof: Uint8Array, valueCommitment: Uint8Array, assetCommitment: Uint8Array, nonce: Uint8Array, extraCommit?: Uint8Array): {
            value: string;
            minValue: string;
            maxValue: string;
            blinder: Uint8Array;
            message: Uint8Array;
        };
    };
    surjectionproof: {
        initialize: (inputTags: Array<Uint8Array>, outputTag: Uint8Array, maxIterations: number, seed: Uint8Array) => {
            proof: Uint8Array;
            inputIndex: number;
        };
        generate: (proof: Uint8Array, inputTags: Array<Uint8Array>, outputTag: Uint8Array, inputIndex: number, inputBlindingKey: Uint8Array, outputBlindingKey: Uint8Array) => Uint8Array;
        verify: (proof: Uint8Array, inputTags: Array<Uint8Array>, outputTag: Uint8Array) => boolean;
    };
}
