/// <reference types="node" />
import { ECPairInterface } from 'ecpair';
export interface Leaf {
    name?: string;
    scriptHex: string;
    leafVersion?: number;
}
export declare type ScriptTree = Leaf | ScriptTree[];
export interface TaprootLeaf extends Leaf {
    leafVersion: number;
    controlBlock: Buffer;
}
export interface TaprootTree {
    leaves: TaprootLeaf[];
    hash: Buffer;
}
export declare function taprootTreeHelper(scripts: ScriptTree): TaprootTree;
export declare function taprootOutputScript(internalPublicKey: Buffer, scriptTree?: ScriptTree): Buffer;
/**
 * Compute the taproot part of the witness stack needed to spend a P2TR output via script path
 * TAPROOT_WITNESS = [SCRIPT, CONTROL_BLOCK]
 * WITNESS_STACK = [...INPUTS, TAPROOT_WITNESS] <- u need to add the script's inputs to the stack
 * @param internalPublicKey the taproot internal public key
 * @param scriptTree the taproot script tree using to recompute path to the leaf. Names have to be specified!
 * @param scriptName the leaf to use
 */
export declare function taprootSignScriptStack(internalPublicKey: Buffer, scriptTree: ScriptTree, scriptName: string): Buffer[];
export declare function taprootSignKey(messageHash: Buffer, key: ECPairInterface): Buffer;
