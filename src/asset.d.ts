/// <reference types="node" />
export declare class AssetHash {
    static UNCONFIDENTIAL_PREFIX: number;
    static CONFIDENTIAL_PREFIXES: number[];
    private prefix;
    private value;
    private constructor();
    static fromHex(hex: string): AssetHash;
    static fromBytes(bytes: Buffer): AssetHash;
    get hex(): string;
    get bytes(): Buffer;
    get bytesWithoutPrefix(): Buffer;
    get isConfidential(): boolean;
}
