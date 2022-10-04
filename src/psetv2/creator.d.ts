/// <reference types="node" />
import { Pset } from './pset';
import { PsetInput } from './input';
import { PsetOutput } from './output';
export declare class CreatorInput {
    txid: string;
    txIndex: number;
    sequence: number;
    heightLocktime: number;
    timeLocktime: number;
    constructor(txid: string, txIndex: number, sequence?: number, heightLocktime?: number, timeLocktime?: number);
    validate(): void;
    toPartialInput(): PsetInput;
}
export declare class CreatorOutput {
    asset: string;
    amount: number;
    script?: Buffer;
    blindingPublicKey?: Buffer;
    blinderIndex?: number;
    constructor(asset: string, amount: number, script?: Buffer, blindingPublicKey?: Buffer, blinderIndex?: number);
    validate(): void;
    toPartialOutput(): PsetOutput;
}
export declare class Creator {
    static newPset(args?: {
        inputs?: CreatorInput[];
        outputs?: CreatorOutput[];
        locktime?: number;
    }): Pset;
}
