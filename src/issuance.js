'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function (o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.amountWithPrecisionToSatoshis =
  exports.calculateReissuanceToken =
  exports.calculateAsset =
  exports.issuanceEntropyFromInput =
  exports.generateEntropy =
  exports.isReissuance =
  exports.newIssuance =
  exports.hashContract =
  exports.validateIssuanceContract =
  exports.hasTokenAmount =
    void 0;
const bufferutils_1 = require('./bufferutils');
const bcrypto = __importStar(require('./crypto'));
const sha256d_1 = require('./sha256d');
const value_1 = require('./value');
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
  const sortedKeys = Object.keys(contract).sort();
  const sortedContract = sortedKeys.reduce(
    (obj, key) => ({ ...obj, [key]: contract[key] }),
    {},
  );
  return bcrypto
    .sha256(Buffer.from(JSON.stringify(sortedContract)))
    .slice()
    .reverse();
}
exports.hashContract = hashContract;
/**
 * Returns an unblinded Issuance object for issuance transaction input.
 * @param assetSats the number of asset to issue.
 * @param tokenSats the number of token to issue.
 * @param contract the asset ricarding contract of the issuance.
 */
function newIssuance(assetSats, tokenSats, contract) {
  if (assetSats < 0) throw new Error('Invalid asset amount');
  if (tokenSats < 0) throw new Error('Invalid token amount');
  const contractHash = contract ? hashContract(contract) : Buffer.alloc(32);
  const issuanceObject = {
    assetAmount:
      assetSats === 0
        ? Buffer.of(0x00)
        : value_1.ElementsValue.fromNumber(assetSats).bytes,
    tokenAmount:
      tokenSats === 0
        ? Buffer.of(0x00)
        : value_1.ElementsValue.fromNumber(tokenSats).bytes,
    assetBlindingNonce: Buffer.alloc(32),
    // in case of issuance, the asset entropy = the contract hash.
    assetEntropy: contractHash,
  };
  return issuanceObject;
}
exports.newIssuance = newIssuance;
function isReissuance(issuance) {
  return !issuance.assetBlindingNonce.equals(Buffer.alloc(32));
}
exports.isReissuance = isReissuance;
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
  return (0, sha256d_1.sha256Midstate)(concatened);
}
exports.generateEntropy = generateEntropy;
/**
 * compute entropy from an input with issuance.
 * @param input reissuance or issuance input.
 */
function issuanceEntropyFromInput(input) {
  if (!input.issuance) throw new Error('input does not contain issuance data');
  return isReissuance(input.issuance)
    ? input.issuance.assetEntropy
    : generateEntropy(
        { txHash: input.hash, vout: input.index },
        input.issuance.assetEntropy,
      );
}
exports.issuanceEntropyFromInput = issuanceEntropyFromInput;
/**
 * calculate the asset tag from a given entropy.
 * @param entropy the entropy used to compute the asset tag.
 */
function calculateAsset(entropy) {
  if (entropy.length !== 32) throw new Error('Invalid entropy length');
  const kZero = Buffer.alloc(32);
  return (0, sha256d_1.sha256Midstate)(Buffer.concat([entropy, kZero]));
}
exports.calculateAsset = calculateAsset;
/**
 * Compute the reissuance token.
 * @param entropy the entropy used to compute the reissuance token.
 * @param confidential true if confidential.
 */
function calculateReissuanceToken(entropy, confidential = false) {
  if (entropy.length !== 32) throw new Error('Invalid entropy length');
  return (0, sha256d_1.sha256Midstate)(
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
 * converts asset amount to satoshis.
 * satoshis = assetAmount * 10^precision
 * @param assetAmount the asset amount.
 * @param precision the precision, 8 by default (like L-BTC).
 */
function amountWithPrecisionToSatoshis(assetAmount, precision = 8) {
  return Math.pow(10, precision) * assetAmount;
}
exports.amountWithPrecisionToSatoshis = amountWithPrecisionToSatoshis;
