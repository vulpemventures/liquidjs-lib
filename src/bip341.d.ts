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
export declare function taprootSignScriptStack(internalPublicKey: Buffer, scriptTree: ScriptTree, scriptName: string): Buffer[];
export declare function taprootSignKey(messageHash: Buffer, key: ECPairInterface): Uint8Array;
