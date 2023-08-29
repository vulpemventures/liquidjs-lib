# LiquidJS

![Build & Test](https://github.com/vulpemventures/liquidjs-lib/actions/workflows/ci.yml/badge.svg)
[![code style: prettier](https://img.shields.io/badge/code_style-prettier-ff69b4.svg?style=flat-square)](https://github.com/prettier/prettier)

The following library forks `bitcoinjs/bitcoinjs-lib` and contains modifications that are necessary for support of elements-based blockchains such as [Blockstream Liquid](https://blockstream.com/liquid)

Released under the terms of the [MIT LICENSE](LICENSE).

## Examples

The below examples are implemented as integration tests (as in [bitcoinjs-lib](https://github.com/bitcoinjs/bitcoinjs-lib#examples)).

- [Create a 1-to-1 Transaction](./test/integration/transaction.spec.ts#L29)
- [Create a 1-to-1 confidential Transaction](./test/integration/transaction.spec.ts#L113)
- [Create (and broadcast via 3PBP) a typical Transaction](./test/integration/transaction.spec.ts#L381)
- [Create (and broadcast via 3PBP) a confidential Transaction](./test/integration/transaction.spec.ts#L470)
- [Create (and broadcast via 3PBP) a Transaction with an OP_RETURN output](./test/integration/transaction.spec.ts#L530)
- [Create (and broadcast via 3PBP) a Transaction, with a 2-of-4 P2SH(multisig) input](./test/integration/transaction.spec.ts#L569)
- [Create (and broadcast via 3PBP) a Transaction, with a SegWit P2SH(P2WPKH) input](./test/integration/transaction.spec.ts#L623)
- [Create (and broadcast via 3PBP) a confidential Transaction, with a SegWit P2SH(P2WPKH) input](./test/integration/transaction.spec.ts#L665)
- [Create (and broadcast via 3PBP) a Transaction, with a SegWit P2WPKH input](./test/integration/transaction.spec.ts#L781)
- [Create (and broadcast via 3PBP) a confidential Transaction, with a SegWit P2WPKH input](./test/integration/transaction.spec.ts#L781)
- [Create (and broadcast via 3PBP) a Transaction, with a SegWit P2PK input](./test/integration/transaction.spec.ts#L933)
- [Create (and broadcast via 3PBP) a confidential Transaction, with a SegWit P2PK input](./test/integration/transaction.spec.ts#L979)
- [Create (and broadcast via 3PBP) a Transaction, with a SegWit 3-of-4 P2SH(P2WSH(multisig) input](./test/integration/transaction.spec.ts#L1100)
- [Create (and broadcast via 3PBP) a confidential Transaction, with a SegWit 3-of-4 P2SH(P2WSH(multisig) input](./test/integration/transaction.spec.ts#L1160)
- [Create (and broadcast via 3PBP) a Transaction and sign with an HDSigner interface (bip32)](./test/integration/transaction.spec.ts#L1385)
- [Create (and broadcast via 3PBP) a confidential Transaction and sign with an HDSigner interface (bip32)](./test/integration/transaction.spec.ts#L1454)

## Bundle

```sh
$ browserify src/index.js --standalone liquid > bundle.js
```
