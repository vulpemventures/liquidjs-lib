'use strict';
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.taggedHash =
  exports.hash256 =
  exports.hash160 =
  exports.sha256 =
  exports.sha1 =
  exports.ripemd160 =
    void 0;
const create_hash_1 = __importDefault(require('create-hash'));
function ripemd160(buffer) {
  try {
    return (0, create_hash_1.default)('rmd160').update(buffer).digest();
  } catch (err) {
    return (0, create_hash_1.default)('ripemd160').update(buffer).digest();
  }
}
exports.ripemd160 = ripemd160;
function sha1(buffer) {
  return (0, create_hash_1.default)('sha1').update(buffer).digest();
}
exports.sha1 = sha1;
function sha256(buffer) {
  return (0, create_hash_1.default)('sha256').update(buffer).digest();
}
exports.sha256 = sha256;
function hash160(buffer) {
  return ripemd160(sha256(buffer));
}
exports.hash160 = hash160;
function hash256(buffer) {
  return sha256(sha256(buffer));
}
exports.hash256 = hash256;
const TAGS = [
  'BIP0340/challenge',
  'BIP0340/aux',
  'BIP0340/nonce',
  'TapLeaf',
  'TapLeaf/elements',
  'TapBranch/elements',
  'TapSighash',
  'TapSighash/elements',
  'TapTweak',
  'TapTweak/elements',
  'KeyAgg list',
  'KeyAgg coefficient',
];
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES = Object.fromEntries(
  TAGS.map((tag) => {
    const tagHash = sha256(Buffer.from(tag, 'utf-8'));
    return [tag, Buffer.concat([tagHash, tagHash])];
  }),
);
function taggedHash(prefix, data) {
  return sha256(Buffer.concat([TAGGED_HASH_PREFIXES[prefix], data]));
}
exports.taggedHash = taggedHash;
