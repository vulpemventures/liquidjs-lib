import { Input } from './transaction';
export interface IssuanceEntity {
    domain: string;
}
/**
 * Ricardian asset contract.
 */
export interface IssuanceContract {
    name: string;
    ticker: string;
    version: number;
    precision: number;
    entity: IssuanceEntity;
}
/**
 * An object describing an output point of the blockchain.
 */
export interface Outpoint {
    txHash: Buffer;
    vout: number;
}
/**
 * An object describing an issuance. Can be attached to a Tx input.
 */
export interface Issuance {
    assetBlindingNonce: Buffer;
    assetEntropy: Buffer;
    assetAmount: Buffer;
    tokenAmount: Buffer;
}
/**
 * returns true if the issuance's token amount is not 0x00 or null buffer.
 * @param issuance issuance to test
 */
export declare function hasTokenAmount(issuance: Issuance): boolean;
/**
 * Checks if a contract given as parameter is valid or not.
 * @param contract contract to validate.
 */
export declare function validateIssuanceContract(contract: IssuanceContract): boolean;
/**
 * Returns the SHA256 value of the JSON encoded Issuance contract.
 * @param contract the contract to digest.
 */
export declare function hashContract(contract: IssuanceContract): Buffer;
/**
 * Returns an Issuance object for issuance transaction input.
 * @param assetAmount the number of asset to issue.
 * @param tokenAmount the number of token to issue.
 * @param precision the number of digit after the decimal point (8 for satoshi).
 * @param contract the asset ricarding contract of the issuance.
 */
export declare function newIssuance(assetAmount: number, tokenAmount: number, precision?: number, contract?: IssuanceContract): Issuance;
export declare function isReissuance(issuance: Issuance): boolean;
/**
 * Generate the entropy.
 * @param outPoint the prevout point used to compute the entropy.
 * @param contractHash the 32 bytes contract hash.
 */
export declare function generateEntropy(outPoint: Outpoint, contractHash?: Buffer): Buffer;
/**
 * compute entropy from an input with issuance.
 * @param input reissuance or issuance input.
 */
export declare function issuanceEntropyFromInput(input: Input): Buffer;
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
/**
 * converts asset amount to confidential value.
 * @param assetAmount the asset amount.
 * @param precision the precision, 8 by default.
 */
export declare function toConfidentialAssetAmount(assetAmount: number, precision?: number): Buffer;
/**
 * converts token amount to confidential value.
 * @param assetAmount the token amount.
 * @param precision the precision, 8 by default.
 */
export declare function toConfidentialTokenAmount(tokenAmount: number, precision?: number): Buffer;
