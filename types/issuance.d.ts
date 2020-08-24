export interface IssuanceContract {
    name: string;
    ticker: string;
    version: number;
    precision: number;
}
export interface OutPoint {
    txHash: string;
    vout: number;
}
/**
 * Generate the entropy.
 * @param outPoint the prevout point used to compute the entropy.
 * @param contractHash the 32 bytes contract hash.
 */
export declare function generateEntropy(outPoint: OutPoint, contractHash?: Buffer): Buffer;
/**
 * calculate the asset tag from a given entropy.
 * @param entropy the entropy used to compute the asset tag.
 */
export declare function calculateAsset(entropy: Buffer): string;
/**
 * Compute the reissuance token.
 * @param entropy the entropy used to compute the reissuance token.
 * @param confidential true if confidential.
 */
export declare function calculateReissuanceToken(entropy: Buffer, confidential?: boolean): Buffer;
