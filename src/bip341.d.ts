/// <reference types="node" />
import type { Ecc as Secp256k1Interface } from './secp256k1-zkp';
export declare const LEAF_VERSION_TAPSCRIPT = 196;
export interface XOnlyPointAddTweakResult {
    parity: 1 | 0;
    xOnlyPubkey: Uint8Array;
}
export interface BIP341API {
    taprootSignKey(messageHash: Buffer, privateKey: Buffer): Buffer;
    taprootSignScriptStack(internalPublicKey: Buffer, leaf: TaprootLeaf, treeRootHash: Buffer, path: Buffer[]): Buffer[];
    taprootOutputScript(internalPublicKey: Buffer, tree?: HashTree): Buffer;
}
export declare function BIP341Factory(ecc: Secp256k1Interface): BIP341API;
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
