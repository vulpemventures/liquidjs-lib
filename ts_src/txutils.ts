import { WitnessUtxo } from 'bip174/src/lib/interfaces';
import * as confidential from './confidential';

function bufferNotEmptyOrNull(buffer?: Buffer): boolean {
    return buffer != null && buffer.length > 0 && buffer != Buffer.from('0x00', 'hex');
}

export function isConfidentialUtxo(witnessUtxo: WitnessUtxo) {
    return bufferNotEmptyOrNull(witnessUtxo.rangeProof)
        && bufferNotEmptyOrNull(witnessUtxo.surjectionProof)
        && bufferNotEmptyOrNull(witnessUtxo.nonce)
}


export interface UnblindWitnessUtxoResult {
    value: string;
    ag: Buffer;
    abf: Buffer;
    vbf: Buffer;
}

export function tryToUnblindWitnessUtxo(prevout: WitnessUtxo, blindingPrivKey: Buffer): UnblindWitnessUtxoResult {
    const unblindPrevout: UnblindWitnessUtxoResult = {
        value: '',
        ag: Buffer.alloc(0),
        abf: Buffer.alloc(0),
        vbf: Buffer.alloc(0),
    };

    const unblindProof = confidential.unblindOutput(
        prevout.nonce,
        blindingPrivKey,
        prevout.rangeProof!,
        prevout.value,
        prevout.asset,
        prevout.script,
    );


    unblindPrevout.ag = unblindProof.asset;
    unblindPrevout.value = unblindProof.value;
    unblindPrevout.abf = unblindProof.assetBlindingFactor;
    unblindPrevout.vbf = unblindProof.valueBlindingFactor;

    return unblindPrevout
}

export function tryToUnblindWithSetOfPrivKeys(
    prevout: WitnessUtxo,
    blindingPrivKeys: Array<Buffer>
): { result?: UnblindWitnessUtxoResult; success: boolean } {
    for (const key of blindingPrivKeys) {
        try {
            const unblindResult = tryToUnblindWitnessUtxo(prevout, key)
            return {
                result: unblindResult,
                success: true,
            }
        } catch (_) {
            continue
        }
    }

    return {
        result: undefined,
        success: false
    }
}