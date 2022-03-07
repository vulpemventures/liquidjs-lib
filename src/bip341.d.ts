/// <reference types="node" />
import { ECPairInterface } from 'ecpair';
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
export declare function toHashTree(leaves: TaprootLeaf[]): HashTree;
/**
 * Given a MAST tree, it finds the path of a particular hash.
 * @param node - the root of the tree
 * @param hash - the hash to search for
 * @returns - and array of hashes representing the path, or an empty array if no pat is found
 */
export declare function findScriptPath(node: HashTree, hash: Buffer): Buffer[];
export declare function taprootOutputScript(internalPublicKey: Buffer, tree?: HashTree): Buffer;
/**
 * Compute the taproot part of the witness stack needed to spend a P2TR output via script path
 * TAPROOT_WITNESS = [SCRIPT, CONTROL_BLOCK]
 * WITNESS_STACK = [...INPUTS, TAPROOT_WITNESS] <- u need to add the script's inputs to the stack
 * @param internalPublicKey the taproot internal public key
 * @param leaf the leaf to use to sign the taproot coin
 * @param path the path to the leaf in the MAST tree see findScriptPath function
 */
export declare function taprootSignScriptStack(internalPublicKey: Buffer, leaf: TaprootLeaf, treeRootHash: Buffer, path: Buffer[]): Buffer[];
export declare function taprootSignKey(messageHash: Buffer, key: ECPairInterface): Buffer;
