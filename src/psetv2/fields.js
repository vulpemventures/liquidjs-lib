'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.OutputProprietaryTypes =
  exports.OutputTypes =
  exports.InputProprietaryTypes =
  exports.InputTypes =
  exports.GLOBAL_PROPRIETARY_TYPE_NAMES =
  exports.GlobalProprietaryTypes =
  exports.GlobalTypes =
  exports.separator =
    void 0;
exports.separator = 0x00;
var GlobalTypes;
(function (GlobalTypes) {
  GlobalTypes[(GlobalTypes['XPUB'] = 1)] = 'XPUB';
  GlobalTypes[(GlobalTypes['TX_VERSION'] = 2)] = 'TX_VERSION';
  GlobalTypes[(GlobalTypes['FALLBACK_LOCKTIME'] = 3)] = 'FALLBACK_LOCKTIME';
  GlobalTypes[(GlobalTypes['INPUT_COUNT'] = 4)] = 'INPUT_COUNT';
  GlobalTypes[(GlobalTypes['OUTPUT_COUNT'] = 5)] = 'OUTPUT_COUNT';
  GlobalTypes[(GlobalTypes['TX_MODIFIABLE'] = 6)] = 'TX_MODIFIABLE';
  GlobalTypes[(GlobalTypes['SIGHASH_SINGLE_INPUTS'] = 7)] =
    'SIGHASH_SINGLE_INPUTS';
  GlobalTypes[(GlobalTypes['VERSION'] = 251)] = 'VERSION';
  GlobalTypes[(GlobalTypes['PROPRIETARY'] = 252)] = 'PROPRIETARY';
})((GlobalTypes = exports.GlobalTypes || (exports.GlobalTypes = {})));
var GlobalProprietaryTypes;
(function (GlobalProprietaryTypes) {
  GlobalProprietaryTypes[(GlobalProprietaryTypes['SCALAR'] = 0)] = 'SCALAR';
  GlobalProprietaryTypes[(GlobalProprietaryTypes['TX_MODIFIABLE'] = 1)] =
    'TX_MODIFIABLE';
})(
  (GlobalProprietaryTypes =
    exports.GlobalProprietaryTypes || (exports.GlobalProprietaryTypes = {})),
);
exports.GLOBAL_PROPRIETARY_TYPE_NAMES = ['scalar', 'txModifiable'];
var InputTypes;
(function (InputTypes) {
  InputTypes[(InputTypes['NON_WITNESS_UTXO'] = 0)] = 'NON_WITNESS_UTXO';
  InputTypes[(InputTypes['WITNESS_UTXO'] = 1)] = 'WITNESS_UTXO';
  InputTypes[(InputTypes['PARTIAL_SIG'] = 2)] = 'PARTIAL_SIG';
  InputTypes[(InputTypes['SIGHASH_TYPE'] = 3)] = 'SIGHASH_TYPE';
  InputTypes[(InputTypes['REDEEM_SCRIPT'] = 4)] = 'REDEEM_SCRIPT';
  InputTypes[(InputTypes['WITNESS_SCRIPT'] = 5)] = 'WITNESS_SCRIPT';
  InputTypes[(InputTypes['BIP32_DERIVATION'] = 6)] = 'BIP32_DERIVATION';
  InputTypes[(InputTypes['FINAL_SCRIPTSIG'] = 7)] = 'FINAL_SCRIPTSIG';
  InputTypes[(InputTypes['FINAL_SCRIPTWITNESS'] = 8)] = 'FINAL_SCRIPTWITNESS';
  InputTypes[(InputTypes['POR_COMMITMENT'] = 9)] = 'POR_COMMITMENT';
  InputTypes[(InputTypes['RIPEMD_160'] = 10)] = 'RIPEMD_160';
  InputTypes[(InputTypes['SHA_256'] = 11)] = 'SHA_256';
  InputTypes[(InputTypes['HASH_160'] = 12)] = 'HASH_160';
  InputTypes[(InputTypes['HASH_256'] = 13)] = 'HASH_256';
  InputTypes[(InputTypes['PREVIOUS_TXID'] = 14)] = 'PREVIOUS_TXID';
  InputTypes[(InputTypes['PREVIOUS_TXINDEX'] = 15)] = 'PREVIOUS_TXINDEX';
  InputTypes[(InputTypes['SEQUENCE'] = 16)] = 'SEQUENCE';
  InputTypes[(InputTypes['REQUIRED_TIME_LOCKTIME'] = 17)] =
    'REQUIRED_TIME_LOCKTIME';
  InputTypes[(InputTypes['REQUIRED_HEIGHT_LOCKTIME'] = 18)] =
    'REQUIRED_HEIGHT_LOCKTIME';
  InputTypes[(InputTypes['TAP_KEY_SIG'] = 19)] = 'TAP_KEY_SIG';
  InputTypes[(InputTypes['TAP_SCRIPT_SIG'] = 20)] = 'TAP_SCRIPT_SIG';
  InputTypes[(InputTypes['TAP_LEAF_SCRIPT'] = 21)] = 'TAP_LEAF_SCRIPT';
  InputTypes[(InputTypes['TAP_BIP32_DERIVATION'] = 22)] =
    'TAP_BIP32_DERIVATION';
  InputTypes[(InputTypes['TAP_INTERNAL_KEY'] = 23)] = 'TAP_INTERNAL_KEY';
  InputTypes[(InputTypes['TAP_MERKLE_ROOT'] = 24)] = 'TAP_MERKLE_ROOT';
  InputTypes[(InputTypes['PROPRIETARY'] = 252)] = 'PROPRIETARY';
})((InputTypes = exports.InputTypes || (exports.InputTypes = {})));
var InputProprietaryTypes;
(function (InputProprietaryTypes) {
  InputProprietaryTypes[(InputProprietaryTypes['ISSUANCE_VALUE'] = 0)] =
    'ISSUANCE_VALUE';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_VALUE_COMMITMENT'] = 1)
  ] = 'ISSUANCE_VALUE_COMMITMENT';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_VALUE_RANGEPROOF'] = 2)
  ] = 'ISSUANCE_VALUE_RANGEPROOF';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_INFLATION_KEYS_RANGEPROOF'] = 3)
  ] = 'ISSUANCE_INFLATION_KEYS_RANGEPROOF';
  InputProprietaryTypes[(InputProprietaryTypes['PEGIN_TX'] = 4)] = 'PEGIN_TX';
  InputProprietaryTypes[(InputProprietaryTypes['PEGIN_TXOUT_PROOF'] = 5)] =
    'PEGIN_TXOUT_PROOF';
  InputProprietaryTypes[(InputProprietaryTypes['PEGIN_GENESIS_HASH'] = 6)] =
    'PEGIN_GENESIS_HASH';
  InputProprietaryTypes[(InputProprietaryTypes['PEGIN_CLAIM_SCRIPT'] = 7)] =
    'PEGIN_CLAIM_SCRIPT';
  InputProprietaryTypes[(InputProprietaryTypes['PEGIN_VALUE'] = 8)] =
    'PEGIN_VALUE';
  InputProprietaryTypes[(InputProprietaryTypes['PEGIN_WITNESS'] = 9)] =
    'PEGIN_WITNESS';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_INFLATION_KEYS'] = 10)
  ] = 'ISSUANCE_INFLATION_KEYS';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_INFLATION_KEYS_COMMITMENT'] = 11)
  ] = 'ISSUANCE_INFLATION_KEYS_COMMITMENT';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_BLINDING_NONCE'] = 12)
  ] = 'ISSUANCE_BLINDING_NONCE';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_ASSET_ENTROPY'] = 13)
  ] = 'ISSUANCE_ASSET_ENTROPY';
  InputProprietaryTypes[(InputProprietaryTypes['UTXO_RANGEPROOF'] = 14)] =
    'UTXO_RANGEPROOF';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_BLIND_VALUE_PROOF'] = 15)
  ] = 'ISSUANCE_BLIND_VALUE_PROOF';
  InputProprietaryTypes[
    (InputProprietaryTypes['ISSUANCE_BLIND_INFLATION_KEYS_PROOF'] = 16)
  ] = 'ISSUANCE_BLIND_INFLATION_KEYS_PROOF';
  InputProprietaryTypes[(InputProprietaryTypes['EXPLICIT_VALUE'] = 17)] =
    'EXPLICIT_VALUE';
  InputProprietaryTypes[(InputProprietaryTypes['VALUE_PROOF'] = 18)] =
    'VALUE_PROOF';
  InputProprietaryTypes[(InputProprietaryTypes['EXPLICIT_ASSET'] = 19)] =
    'EXPLICIT_ASSET';
  InputProprietaryTypes[(InputProprietaryTypes['ASSET_PROOF'] = 20)] =
    'ASSET_PROOF';
  InputProprietaryTypes[(InputProprietaryTypes['BLINDED_ISSUANCE'] = 21)] =
    'BLINDED_ISSUANCE';
})(
  (InputProprietaryTypes =
    exports.InputProprietaryTypes || (exports.InputProprietaryTypes = {})),
);
var OutputTypes;
(function (OutputTypes) {
  OutputTypes[(OutputTypes['REDEEM_SCRIPT'] = 0)] = 'REDEEM_SCRIPT';
  OutputTypes[(OutputTypes['WITNESS_SCRIPT'] = 1)] = 'WITNESS_SCRIPT';
  OutputTypes[(OutputTypes['BIP32_DERIVATION'] = 2)] = 'BIP32_DERIVATION';
  OutputTypes[(OutputTypes['AMOUNT'] = 3)] = 'AMOUNT';
  OutputTypes[(OutputTypes['SCRIPT'] = 4)] = 'SCRIPT';
  OutputTypes[(OutputTypes['TAP_INTERNAL_KEY'] = 5)] = 'TAP_INTERNAL_KEY';
  OutputTypes[(OutputTypes['TAP_TREE'] = 6)] = 'TAP_TREE';
  OutputTypes[(OutputTypes['TAP_BIP32_DERIVATION'] = 7)] =
    'TAP_BIP32_DERIVATION';
  OutputTypes[(OutputTypes['PROPRIETARY'] = 252)] = 'PROPRIETARY';
})((OutputTypes = exports.OutputTypes || (exports.OutputTypes = {})));
var OutputProprietaryTypes;
(function (OutputProprietaryTypes) {
  OutputProprietaryTypes[(OutputProprietaryTypes['VALUE_COMMITMENT'] = 1)] =
    'VALUE_COMMITMENT';
  OutputProprietaryTypes[(OutputProprietaryTypes['ASSET'] = 2)] = 'ASSET';
  OutputProprietaryTypes[(OutputProprietaryTypes['ASSET_COMMITMENT'] = 3)] =
    'ASSET_COMMITMENT';
  OutputProprietaryTypes[(OutputProprietaryTypes['VALUE_RANGEPROOF'] = 4)] =
    'VALUE_RANGEPROOF';
  OutputProprietaryTypes[
    (OutputProprietaryTypes['ASSET_SURJECTION_PROOF'] = 5)
  ] = 'ASSET_SURJECTION_PROOF';
  OutputProprietaryTypes[(OutputProprietaryTypes['BLINDING_PUBKEY'] = 6)] =
    'BLINDING_PUBKEY';
  OutputProprietaryTypes[(OutputProprietaryTypes['ECDH_PUBKEY'] = 7)] =
    'ECDH_PUBKEY';
  OutputProprietaryTypes[(OutputProprietaryTypes['BLINDER_INDEX'] = 8)] =
    'BLINDER_INDEX';
  OutputProprietaryTypes[(OutputProprietaryTypes['BLIND_VALUE_PROOF'] = 9)] =
    'BLIND_VALUE_PROOF';
  OutputProprietaryTypes[(OutputProprietaryTypes['BLIND_ASSET_PROOF'] = 10)] =
    'BLIND_ASSET_PROOF';
})(
  (OutputProprietaryTypes =
    exports.OutputProprietaryTypes || (exports.OutputProprietaryTypes = {})),
);
