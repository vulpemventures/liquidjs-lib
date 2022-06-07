export declare const separator = 0;
export declare enum GlobalTypes {
    XPUB = 1,
    TX_VERSION = 2,
    FALLBACK_LOCKTIME = 3,
    INPUT_COUNT = 4,
    OUTPUT_COUNT = 5,
    TX_MODIFIABLE = 6,
    SIGHASH_SINGLE_INPUTS = 7,
    VERSION = 251,
    PROPRIETARY = 252
}
export declare const GLOBAL_TYPE_NAMES: string[];
export declare enum GlobalProprietaryTypes {
    SCALAR = 0,
    TX_MODIFIABLE = 1
}
export declare const GLOBAL_PROPRIETARY_TYPE_NAMES: string[];
export declare enum InputTypes {
    NON_WITNESS_UTXO = 0,
    WITNESS_UTXO = 1,
    PARTIAL_SIG = 2,
    SIGHASH_TYPE = 3,
    REDEEM_SCRIPT = 4,
    WITNESS_SCRIPT = 5,
    BIP32_DERIVATION = 6,
    FINAL_SCRIPTSIG = 7,
    FINAL_SCRIPTWITNESS = 8,
    POR_COMMITMENT = 9,
    RIPEMD_160 = 10,
    SHA_256 = 11,
    HASH_160 = 12,
    HASH_256 = 13,
    PREVIOUS_TXID = 14,
    PREVIOUS_TXINDEX = 15,
    SEQUENCE = 16,
    REQUIRED_TIME_LOCKTIME = 17,
    REQUIRED_HEIGHT_LOCKTIME = 18,
    TAP_KEY_SIG = 19,
    TAP_SCRIPT_SIG = 20,
    TAP_LEAF_SIG = 21,
    TAP_BIP32_DERIVATION = 22,
    TAP_INTERNAL_KEY = 23,
    TAP_MERKLE_ROOT = 24,
    PROPRIETARY = 252
}
export declare const INPUT_TYPE_NAMES: string[];
export declare enum InputProprietaryTypes {
    ISSUANCE_VALUE = 0,
    ISSUANCE_VALUE_COMMITMENT = 1,
    ISSUANCE_VALUE_RANGEPROOF = 2,
    ISSUANCE_INFLATION_KEYS_RANGEPROOF = 3,
    PEGIN_TX = 4,
    PEGIN_TXOUT_PROOF = 5,
    PEGIN_GENESIS_HASH = 6,
    PEGIN_CLAIM_SCRIPT = 7,
    PEGIN_VALUE = 8,
    PEGIN_WITNESS = 9,
    ISSUANCE_INFLATION_KEYS = 10,
    ISSUANCE_INFLATION_KEYS_COMMITMENT = 11,
    ISSUANCE_BLINDING_NONCE = 12,
    ISSUANCE_ASSET_ENTROPY = 13,
    UTXO_RANGEPROOF = 14,
    ISSUANCE_BLIND_VALUE_PROOF = 15,
    ISSUANCE_BLIND_INFLATION_KEYS_PROOF = 16
}
export declare const INPUT_PROPRIETARY_TYPE_NAMES: string[];
export declare enum OutputTypes {
    REDEEM_SCRIPT = 0,
    WITNESS_SCRIPT = 1,
    BIP32_DERIVATION = 2,
    AMOUNT = 3,
    SCRIPT = 4,
    TAP_INTERNAL_KEY = 5,
    TAP_TREE = 6,
    TAP_BIP32_DERIVATION = 7,
    PROPRIETARY = 252
}
export declare const OUTPUT_TYPE_NAMES: string[];
export declare enum OutputProprietaryTypes {
    VALUE_COMMITMENT = 1,
    ASSET = 2,
    ASSET_COMMITMENT = 3,
    VALUE_RANGEPROOF = 4,
    ASSET_SURJECTION_PROOF = 5,
    BLINDING_PUBKEY = 6,
    ECDH_PUBKEY = 7,
    BLINDER_INDEX = 8,
    BLIND_VALUE_PROOF = 9,
    BLIND_ASSET_PROOF = 10
}
export declare const OUTPUT_PROPRIETARY_TYPE_NAMES: string[];
