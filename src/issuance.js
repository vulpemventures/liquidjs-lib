'use strict';
var __importStar =
  (this && this.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
const address_1 = require('./address');
const bufferutils_1 = require('./bufferutils');
const confidential_1 = require('./confidential');
const bcrypto = __importStar(require('./crypto'));
const sha256d_1 = require('./sha256d');
/**
 * returns true if the issuance's token amount is not 0x00 or null buffer.
 * @param issuance issuance to test
 */
function hasTokenAmount(issuance) {
  if (issuance.tokenAmount && issuance.tokenAmount.length > 1) return true;
  return false;
}
exports.hasTokenAmount = hasTokenAmount;
/**
 * Checks if a contract given as parameter is valid or not.
 * @param contract contract to validate.
 */
function validateIssuanceContract(contract) {
  const precisionIsValid = contract.precision >= 0 && contract.precision <= 8;
  return precisionIsValid;
}
exports.validateIssuanceContract = validateIssuanceContract;
/**
 * Returns the SHA256 value of the JSON encoded Issuance contract.
 * @param contract the contract to digest.
 */
function hashContract(contract) {
  if (!validateIssuanceContract(contract))
    throw new Error('Invalid asset contract');
  return bcrypto.sha256(Buffer.from(JSON.stringify(contract)));
}
exports.hashContract = hashContract;
/**
 * Returns an Issuance object for issuance transaction input.
 * @param assetAmount the number of asset to issue.
 * @param tokenAmount the number of token to issue.
 * @param precision the number of digit after the decimal point (8 for satoshi).
 * @param contract the asset ricarding contract of the issuance.
 */
function newIssuance(assetAmount, tokenAmount, precision = 8, contract) {
  if (assetAmount < 0) throw new Error('Invalid asset amount');
  if (tokenAmount < 0) throw new Error('Invalid token amount');
  if (precision < 0 || precision > 8) throw new Error('Invalid precision');
  let contractHash = Buffer.alloc(32);
  if (contract) {
    if (contract.precision !== precision)
      throw new Error('precision is not equal to the asset contract precision');
    contractHash = hashContract(contract);
  }
  const iss = {
    assetAmount: toConfidentialAssetAmount(assetAmount, precision),
    tokenAmount: toConfidentialTokenAmount(tokenAmount, precision),
    assetBlindingNonce: Buffer.alloc(32),
    // in case of issuance, the asset entropy = the contract hash.
    assetEntropy: contractHash,
  };
  return iss;
}
exports.newIssuance = newIssuance;
/**
 * Generate the entropy.
 * @param outPoint the prevout point used to compute the entropy.
 * @param contractHash the 32 bytes contract hash.
 */
function generateEntropy(outPoint, contractHash = Buffer.alloc(32)) {
  if (outPoint.txHash.length !== 32) {
    throw new Error('Invalid txHash length');
  }
  const tBuffer = Buffer.allocUnsafe(36);
  const s = new bufferutils_1.BufferWriter(tBuffer, 0);
  s.writeSlice(outPoint.txHash);
  s.writeInt32(outPoint.vout);
  const prevoutHash = bcrypto.hash256(s.buffer);
  const concatened = Buffer.concat([prevoutHash, contractHash]);
  return sha256d_1.sha256Midstate(concatened);
}
exports.generateEntropy = generateEntropy;
/**
 * calculate the asset tag from a given entropy.
 * @param entropy the entropy used to compute the asset tag.
 */
function calculateAsset(entropy) {
  if (entropy.length !== 32) throw new Error('Invalid entropy length');
  const kZero = Buffer.alloc(32);
  return sha256d_1.sha256Midstate(Buffer.concat([entropy, kZero]));
}
exports.calculateAsset = calculateAsset;
/**
 * Compute the reissuance token.
 * @param entropy the entropy used to compute the reissuance token.
 * @param confidential true if confidential.
 */
function calculateReissuanceToken(entropy, confidential = false) {
  if (entropy.length !== 32) throw new Error('Invalid entropy length');
  return sha256d_1.sha256Midstate(
    Buffer.concat([
      entropy,
      Buffer.of(getTokenFlag(confidential) + 1),
      Buffer.alloc(31),
    ]),
  );
}
exports.calculateReissuanceToken = calculateReissuanceToken;
function getTokenFlag(confidential) {
  if (confidential) return 1;
  return 0;
}
/**
 * converts asset amount to confidential value.
 * @param assetAmount the asset amount.
 * @param precision the precision, 8 by default.
 */
function toConfidentialAssetAmount(assetAmount, precision = 8) {
  const amount = Math.pow(10, precision) * assetAmount;
  return confidential_1.satoshiToConfidentialValue(amount);
}
/**
 * converts token amount to confidential value.
 * @param assetAmount the token amount.
 * @param precision the precision, 8 by default.
 */
function toConfidentialTokenAmount(tokenAmount, precision = 8) {
  if (tokenAmount === 0) return Buffer.from('00', 'hex');
  return toConfidentialAssetAmount(tokenAmount, precision);
}
function validateAddIssuanceArgs(args) {
  if (args.assetAmount <= 0)
    throw new Error('asset amount must be greater than zero.');
  if (args.tokenAmount < 0) throw new Error('token amount must be positive.');
  if (args.tokenAddress) {
    if (
      address_1.isConfidential(args.assetAddress) !==
      address_1.isConfidential(args.tokenAddress)
    ) {
      throw new Error(
        'tokenAddress and assetAddress are not of the same type (confidential or unconfidential).',
      );
    }
  }
}
exports.validateAddIssuanceArgs = validateAddIssuanceArgs;
