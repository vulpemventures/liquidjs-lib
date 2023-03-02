'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.testnet = exports.regtest = exports.liquid = void 0;
const strToGenesisHash = (str) => Buffer.from(str, 'hex').reverse();
const RegtestGenesisBlockHash = strToGenesisHash(
  '00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21',
);
const TestnetGenesisBlockHash = strToGenesisHash(
  'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1',
);
const LiquidGenesisBlockHash = strToGenesisHash(
  '1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003',
);
exports.liquid = {
  messagePrefix: '\x18Liquid Signed Message:\n',
  bech32: 'ex',
  blech32: 'lq',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 57,
  scriptHash: 39,
  wif: 0x80,
  confidentialPrefix: 12,
  assetHash: '6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d',
  genesisBlockHash: LiquidGenesisBlockHash,
  name: 'liquid',
};
exports.regtest = {
  messagePrefix: '\x18Liquid Signed Message:\n',
  bech32: 'ert',
  blech32: 'el',
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 235,
  scriptHash: 75,
  wif: 0xef,
  confidentialPrefix: 4,
  assetHash: '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
  genesisBlockHash: RegtestGenesisBlockHash,
  name: 'regtest',
};
exports.testnet = {
  ...exports.regtest,
  bech32: 'tex',
  blech32: 'tlq',
  pubKeyHash: 36,
  scriptHash: 19,
  confidentialPrefix: 23,
  assetHash: '144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49',
  genesisBlockHash: TestnetGenesisBlockHash,
  name: 'testnet',
};
