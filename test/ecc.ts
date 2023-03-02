import ECPairFactory from 'ecpair';
const ecclib = require('tiny-secp256k1');

export const ECPair = ECPairFactory(ecclib);
export const ecc = ecclib;
