"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const baddress = require("../address");
const bcrypto = require("../crypto");
const networks_1 = require("../networks");
const bscript = require("../script");
const lazy = require("./lazy");
const typef = require('typeforce');
const OPS = bscript.OPS;
const ecc = require('tiny-secp256k1');
const bech32 = require('bech32');
const EMPTY_BUFFER = Buffer.alloc(0);
// witness: {signature} {pubKey}
// input: <>
// output: OP_0 {pubKeyHash}
function p2wpkh(a, opts) {
    if (!a.address &&
        !a.hash &&
        !a.output &&
        !a.pubkey &&
        !a.witness &&
        !a.confidentialAddress)
        throw new TypeError('Not enough data');
    opts = Object.assign({ validate: true }, opts || {});
    typef({
        address: typef.maybe(typef.String),
        hash: typef.maybe(typef.BufferN(20)),
        input: typef.maybe(typef.BufferN(0)),
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.BufferN(22)),
        pubkey: typef.maybe(ecc.isPoint),
        signature: typef.maybe(bscript.isCanonicalScriptSignature),
        witness: typef.maybe(typef.arrayOf(typef.Buffer)),
    }, a);
    const network = a.network || networks_1.liquid;
    const _address = lazy.value(() => {
        const result = bech32.decode(a.address);
        const version = result.words.shift();
        const data = bech32.fromWords(result.words);
        return {
            version,
            prefix: result.prefix,
            data: Buffer.from(data),
        };
    });
    const _confidentialAddress = lazy.value(() => {
        const result = baddress.fromBlech32(a.confidentialAddress);
        return {
            blindingKey: result.pubkey,
            unconfidentialAddress: baddress.toBech32(result.data.slice(2), result.version, network.bech32),
        };
    });
    const o = { name: 'p2wpkh', network };
    lazy.prop(o, 'address', () => {
        if (!o.hash)
            return;
        const words = bech32.toWords(o.hash);
        words.unshift(0x00);
        return bech32.encode(network.bech32, words);
    });
    lazy.prop(o, 'hash', () => {
        if (a.output)
            return a.output.slice(2, 22);
        if (a.address)
            return _address().data;
        if (a.pubkey || o.pubkey)
            return bcrypto.hash160(a.pubkey || o.pubkey);
        if (a.confidentialAddress) {
            const addr = _confidentialAddress().unconfidentialAddress;
            return baddress.fromBech32(addr).data;
        }
    });
    lazy.prop(o, 'output', () => {
        if (!o.hash)
            return;
        return bscript.compile([OPS.OP_0, o.hash]);
    });
    lazy.prop(o, 'pubkey', () => {
        if (a.pubkey)
            return a.pubkey;
        if (!a.witness)
            return;
        return a.witness[1];
    });
    lazy.prop(o, 'signature', () => {
        if (!a.witness)
            return;
        return a.witness[0];
    });
    lazy.prop(o, 'input', () => {
        if (!o.witness)
            return;
        return EMPTY_BUFFER;
    });
    lazy.prop(o, 'witness', () => {
        if (!a.pubkey)
            return;
        if (!a.signature)
            return;
        return [a.signature, a.pubkey];
    });
    lazy.prop(o, 'blindkey', () => {
        if (a.confidentialAddress)
            return _confidentialAddress().blindingKey;
        if (a.blindkey)
            return a.blindkey;
    });
    lazy.prop(o, 'confidentialAddress', () => {
        if (!o.address)
            return;
        if (!o.blindkey)
            return;
        const res = baddress.fromBech32(o.address);
        const data = Buffer.concat([
            Buffer.from([res.version, res.data.length]),
            res.data,
        ]);
        return baddress.toBlech32(data, o.blindkey, o.network.blech32);
    });
    // extended validation
    if (opts.validate) {
        let hash = Buffer.from([]);
        let blindkey = Buffer.from([]);
        if (a.address) {
            if (network && network.bech32 !== _address().prefix)
                throw new TypeError('Invalid prefix or Network mismatch');
            if (_address().version !== 0x00)
                throw new TypeError('Invalid address version');
            if (_address().data.length !== 20)
                throw new TypeError('Invalid address data');
            hash = _address().data;
        }
        if (a.hash) {
            if (hash.length > 0 && !hash.equals(a.hash))
                throw new TypeError('Hash mismatch');
            else
                hash = a.hash;
        }
        if (a.output) {
            if (a.output.length !== 22 ||
                a.output[0] !== OPS.OP_0 ||
                a.output[1] !== 0x14)
                throw new TypeError('Output is invalid');
            if (hash.length > 0 && !hash.equals(a.output.slice(2)))
                throw new TypeError('Hash mismatch');
            else
                hash = a.output.slice(2);
        }
        if (a.pubkey) {
            const pkh = bcrypto.hash160(a.pubkey);
            if (hash.length > 0 && !hash.equals(pkh))
                throw new TypeError('Hash mismatch');
            else
                hash = pkh;
        }
        if (a.witness) {
            if (a.witness.length !== 2)
                throw new TypeError('Witness is invalid');
            if (!bscript.isCanonicalScriptSignature(a.witness[0]))
                throw new TypeError('Witness has invalid signature');
            if (!ecc.isPoint(a.witness[1]))
                throw new TypeError('Witness has invalid pubkey');
            if (a.signature && !a.signature.equals(a.witness[0]))
                throw new TypeError('Signature mismatch');
            if (a.pubkey && !a.pubkey.equals(a.witness[1]))
                throw new TypeError('Pubkey mismatch');
            const pkh = bcrypto.hash160(a.witness[1]);
            if (hash.length > 0 && !hash.equals(pkh))
                throw new TypeError('Hash mismatch');
        }
        if (a.confidentialAddress) {
            if (a.address &&
                a.address !== _confidentialAddress().unconfidentialAddress)
                throw new TypeError('Address mismatch');
            if (blindkey.length > 0 &&
                !blindkey.equals(_confidentialAddress().blindingKey))
                throw new TypeError('Blindkey mismatch');
            else
                blindkey = _confidentialAddress().blindingKey;
        }
        if (a.blindkey) {
            if (!ecc.isPoint(a.blindkey))
                throw new TypeError('Blindkey is invalid');
            if (blindkey.length > 0 && !blindkey.equals(a.blindkey))
                throw new TypeError('Blindkey mismatch');
            else
                blindkey = a.blindkey;
        }
    }
    return Object.assign(o, a);
}
exports.p2wpkh = p2wpkh;
