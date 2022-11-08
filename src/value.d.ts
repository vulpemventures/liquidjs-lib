/// <reference types="node" />
export declare class ElementsValue {
    static UNCONFIDENTIAL_PREFIX: number;
    static CONFIDENTIAL_PREFIXES: number[];
    private prefix;
    private value;
    private constructor();
    static fromNumber(num: number): ElementsValue;
    static fromHex(hex: string): ElementsValue;
    static fromBytes(bytes: Buffer): ElementsValue;
    get hex(): string;
    get bytes(): Buffer;
    get number(): number;
    get isConfidential(): boolean;
}
