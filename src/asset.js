"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AssetHash = void 0;
class AssetHash {
    constructor(prefix, value) {
        this.prefix = prefix;
        this.value = value;
    }
    static fromHex(hex, isConfidential) {
        const prefix = isConfidential
            ? AssetHash.CONFIDENTIAL_ASSET_PREFIX
            : AssetHash.UNCONFIDENTIAL_ASSET_PREFIX;
        const value = Buffer.from(hex, 'hex').reverse();
        return new AssetHash(prefix, value);
    }
    static fromBytes(bytes) {
        if (bytes.length !== 1 + 32) {
            throw new Error('Invalid asset hash length');
        }
        const prefix = bytes.slice(0, 1);
        const value = bytes.slice(1);
        return new AssetHash(prefix, value);
    }
    get hex() {
        return reverseWithoutMutate(this.value).toString('hex');
    }
    get bytes() {
        return Buffer.concat([this.prefix, this.value]);
    }
}
exports.AssetHash = AssetHash;
AssetHash.CONFIDENTIAL_ASSET_PREFIX = Buffer.of(0x0a);
AssetHash.UNCONFIDENTIAL_ASSET_PREFIX = Buffer.of(0x01);
function reverseWithoutMutate(buf) {
    return buf.slice().reverse();
}
