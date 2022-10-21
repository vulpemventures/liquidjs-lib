import ECPairFactory from 'ecpair';
const ecclib = require('tiny-secp256k1');
import secp256k1 from '@vulpemventures/secp256k1-zkp';
import { Confidential } from '../ts_src';

export const ECPair = ECPairFactory(ecclib);
export const ecc = ecclib;
export const confidential = new Confidential(secp256k1());
