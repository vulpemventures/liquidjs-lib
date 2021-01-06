import { WitnessUtxo } from 'bip174/src/lib/interfaces';
export declare function isConfidentialUtxo(witnessUtxo: WitnessUtxo): boolean;
export interface UnblindWitnessUtxoResult {
    value: string;
    ag: Buffer;
    abf: Buffer;
    vbf: Buffer;
}
export declare function tryToUnblindWitnessUtxo(prevout: WitnessUtxo, blindingPrivKey: Buffer): UnblindWitnessUtxoResult;
export declare function tryToUnblindWithSetOfPrivKeys(prevout: WitnessUtxo, blindingPrivKeys: Array<Buffer>): {
    result?: UnblindWitnessUtxoResult;
    success: boolean;
};
