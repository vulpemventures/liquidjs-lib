import { Pset } from './pset';
import { Input as PsetInput } from './input';
import { Output as PsetOutput } from './output';
export declare class Input {
    txid: string;
    txIndex: number;
    sequence: number;
    heightLocktime: number;
    timeLocktime: number;
    constructor(txid: string, txIndex: number, sequence?: number, heightLocktime?: number, timeLocktime?: number);
    validate(): void;
    toPartialInput(): PsetInput;
}
export declare class Output {
    asset: string;
    amount: number;
    address?: string;
    blinderIndex?: number;
    constructor(asset: string, amount: number, address?: string, blinderIndex?: number);
    validate(): void;
    toPartialOutput(): PsetOutput;
}
export declare class Creator {
    static newPset(args: {
        inputs?: Input[];
        outputs?: Output[];
        locktime?: number;
    }): Pset;
}
