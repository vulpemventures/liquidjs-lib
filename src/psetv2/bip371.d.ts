/// <reference types="node" />
import { TapLeafScript } from './interfaces';
import { Input } from './input';
export declare const toXOnly: (pubKey: Buffer) => Buffer;
export declare function serializeTaprootSignature(sig: Buffer, sighashType?: number): Buffer;
export declare function sortSignatures(input: Input, tapLeaf: TapLeafScript): Buffer[];
/**
 * Find tapleaf by hash, or get the signed tapleaf with the shortest path.
 */
export declare function findTapLeafToFinalize(input: Input, inputIndex: number, leafHashToFinalize?: Buffer): TapLeafScript;
