/// <reference types="node" />
import { TinySecp256k1Interface as ECPairSecp256k1Interface } from 'ecpair';
export declare const LEAF_VERSION_TAPSCRIPT = 196;
export interface XOnlyPointAddTweakResult {
    parity: 1 | 0;
    xOnlyPubkey: Uint8Array;
}
export interface TinySecp256k1Interface extends ECPairSecp256k1Interface {
    xOnlyPointAddTweak(p: Uint8Array, tweak: Uint8Array): XOnlyPointAddTweakResult | null;
    privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
    privateSub(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
    signSchnorr(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
    verifySchnorr(h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean;
}
export interface BIP341API {
    taprootSignKey(messageHash: Buffer, privateKey: Buffer): Buffer;
    taprootSignScriptStack(internalPublicKey: Buffer, leaf: TaprootLeaf, treeRootHash: Buffer, path: Buffer[]): Buffer[];
    taprootOutputScript(internalPublicKey: Buffer, tree?: HashTree): Buffer;
}
export declare function BIP341Factory(ecc: TinySecp256k1Interface): BIP341API;
export interface TaprootLeaf {
    scriptHex: string;
    version?: number;
}
export interface HashTree {
    hash: Buffer;
    scriptHex?: string;
    left?: HashTree;
    right?: HashTree;
}
export declare function tapLeafHash(leaf: TaprootLeaf): Buffer;
export declare function toHashTree(leaves: TaprootLeaf[], withScriptHex?: boolean): HashTree;
/**
 * Given a MAST tree, it finds the path of a particular hash.
 * @param node - the root of the tree
 * @param hash - the hash to search for
 * @returns - and array of hashes representing the path, or an empty array if no pat is found
 */
export declare function findScriptPath(node: HashTree, hash: Buffer): Buffer[];
