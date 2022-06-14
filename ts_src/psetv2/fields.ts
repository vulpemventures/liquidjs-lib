export const separator = 0x00;

export enum GlobalTypes {
  XPUB = 1,
  TX_VERSION,
  FALLBACK_LOCKTIME,
  INPUT_COUNT,
  OUTPUT_COUNT,
  TX_MODIFIABLE,
  SIGHASH_SINGLE_INPUTS,
  VERSION = 0xfb,
  PROPRIETARY = 0xfc,
}

export enum GlobalProprietaryTypes {
  SCALAR,
  TX_MODIFIABLE,
}

export const GLOBAL_PROPRIETARY_TYPE_NAMES = ['scalar', 'txModifiable'];

export enum InputTypes {
  NON_WITNESS_UTXO,
  WITNESS_UTXO,
  PARTIAL_SIG,
  SIGHASH_TYPE,
  REDEEM_SCRIPT,
  WITNESS_SCRIPT,
  BIP32_DERIVATION,
  FINAL_SCRIPTSIG,
  FINAL_SCRIPTWITNESS,
  POR_COMMITMENT,
  RIPEMD_160,
  SHA_256,
  HASH_160,
  HASH_256,
  PREVIOUS_TXID,
  PREVIOUS_TXINDEX,
  SEQUENCE,
  REQUIRED_TIME_LOCKTIME,
  REQUIRED_HEIGHT_LOCKTIME,
  TAP_KEY_SIG,
  TAP_SCRIPT_SIG,
  TAP_LEAF_SCRIPT,
  TAP_BIP32_DERIVATION,
  TAP_INTERNAL_KEY,
  TAP_MERKLE_ROOT,
  PROPRIETARY = 0xfc,
}

export enum InputProprietaryTypes {
  ISSUANCE_VALUE,
  ISSUANCE_VALUE_COMMITMENT,
  ISSUANCE_VALUE_RANGEPROOF,
  ISSUANCE_INFLATION_KEYS_RANGEPROOF,
  PEGIN_TX,
  PEGIN_TXOUT_PROOF,
  PEGIN_GENESIS_HASH,
  PEGIN_CLAIM_SCRIPT,
  PEGIN_VALUE,
  PEGIN_WITNESS,
  ISSUANCE_INFLATION_KEYS,
  ISSUANCE_INFLATION_KEYS_COMMITMENT,
  ISSUANCE_BLINDING_NONCE,
  ISSUANCE_ASSET_ENTROPY,
  UTXO_RANGEPROOF,
  ISSUANCE_BLIND_VALUE_PROOF,
  ISSUANCE_BLIND_INFLATION_KEYS_PROOF,
}

export enum OutputTypes {
  REDEEM_SCRIPT,
  WITNESS_SCRIPT,
  BIP32_DERIVATION,
  AMOUNT,
  SCRIPT,
  TAP_INTERNAL_KEY,
  TAP_TREE,
  TAP_BIP32_DERIVATION,
  PROPRIETARY = 0xfc,
}

export enum OutputProprietaryTypes {
  VALUE_COMMITMENT = 1,
  ASSET,
  ASSET_COMMITMENT,
  VALUE_RANGEPROOF,
  ASSET_SURJECTION_PROOF,
  BLINDING_PUBKEY,
  ECDH_PUBKEY,
  BLINDER_INDEX,
  BLIND_VALUE_PROOF,
  BLIND_ASSET_PROOF,
}
