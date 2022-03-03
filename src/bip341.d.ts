/// <reference types="node" />
import { ECPairInterface } from 'ecpair';
interface Leaf {
    name?: string;
    scriptHex: string;
    leafVersion?: number;
}
declare type ScriptTree = Leaf | ScriptTree[];
export declare function taprootOutputScript(internalPublicKey: Buffer, scriptTree?: ScriptTree): Buffer;
export declare function taprootSignScript(internalPublicKey: Buffer, scriptTree: ScriptTree, scriptNum: number, scriptInputs: Buffer[]): Buffer[];
export declare function taprootSignKey(messageHash: Buffer, key: ECPairInterface): Uint8Array;
export {};
