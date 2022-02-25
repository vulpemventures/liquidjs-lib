/// <reference types="node" />
export declare class AssetHash {
    static CONFIDENTIAL_ASSET_PREFIX: Buffer;
    static UNCONFIDENTIAL_ASSET_PREFIX: Buffer;
    private prefix;
    private value;
    constructor(prefix: Buffer, value: Buffer);
    static fromHex(hex: string, isConfidential: boolean): AssetHash;
    static fromBytes(bytes: Buffer): AssetHash;
    get hex(): string;
    get bytes(): Buffer;
}
