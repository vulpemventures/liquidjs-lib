import { Issuance } from './transaction';
/**
 * Ricardian asset contract.
 */
export interface IssuanceContract {
    name: string;
    ticker: string;
    version: number;
    precision: number;
}
/**
 * An object describing an output point of the blockchain.
 */
export interface OutPoint {
    txHash: Buffer;
    vout: number;
}
/**
 * Checks if a contract given as parameter is valid or not.
 * @param contract contract to validate.
 */
export declare function validateIssuanceContract(contract: IssuanceContract): boolean;
/**
 * Returns an Issuance object for issuance transaction input.
 * @param assetAmount the number of asset to issue.
 * @param tokenAmount the number of token to issue.
 * @param vout the out point (txhash and vout index).
 * @param precision the number of digit after the decimal point (8 for satoshi).
 * @param contract the asset ricarding contract of the issuance.
 */
export declare function newIssuance(assetAmount: number, tokenAmount: number, vout: OutPoint, precision?: number, contract?: IssuanceContract): Issuance;
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
export declare function calculateAsset(entropy: Buffer): Buffer;
/**
 * Compute the reissuance token.
 * @param entropy the entropy used to compute the reissuance token.
 * @param confidential true if confidential.
 */
export declare function calculateReissuanceToken(entropy: Buffer, confidential?: boolean): Buffer;
