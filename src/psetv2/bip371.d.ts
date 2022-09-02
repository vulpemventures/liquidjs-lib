/// <reference types="node" />
import { TapLeafScript } from './interfaces';
import { PsetInput } from './input';
export declare const toXOnly: (pubkey: Buffer) => Buffer;
export declare function serializeTaprootSignature(sig: Buffer, sighashType?: number): Buffer;
export declare function sortSignatures(input: PsetInput, tapLeaf: TapLeafScript): Buffer[];
/**
 * Find tapleaf by hash, or get the signed tapleaf with the shortest path.
 */
export declare function findTapLeafToFinalize(input: PsetInput, inputIndex: number, leafHashToFinalize?: Buffer): TapLeafScript;
