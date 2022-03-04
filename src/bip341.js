'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.taprootSignKey = exports.taprootSignScriptStack = exports.taprootOutputScript = exports.taprootTreeHelper = void 0;
const crypto_1 = require('./crypto');
const tiny_secp256k1_1 = require('tiny-secp256k1');
const bufferutils_1 = require('./bufferutils');
const ecpair_1 = require('./ecpair');
const LEAF_VERSION_TAPSCRIPT = 0xc4;
function tapLeafHash(leaf) {
  const leafVersion = leaf.leafVersion || LEAF_VERSION_TAPSCRIPT;
  const script = Buffer.from(leaf.scriptHex, 'hex');
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
    1 + (0, bufferutils_1.varSliceSize)(script),
  );
  bufferWriter.writeUInt8(leafVersion);
  bufferWriter.writeVarSlice(script);
  return (0, crypto_1.taggedHash)('TapLeaf/elements', bufferWriter.end());
}
function isLeaf(node) {
  return typeof node === 'object' && !Array.isArray(node);
}
// recursively build the Taproot tree from a ScriptTree structure
// for each leaf, will compute the corresponding control block
function taprootTreeHelper(scripts) {
  if (isLeaf(scripts)) {
    // if the tree is a leaf, we redirect to length 1 case
    return taprootTreeHelper([scripts]);
  }
  switch (scripts.length) {
    case 0:
      return { leaves: [], hash: Buffer.alloc(32) };
    case 1:
      // Leaf
      const leaf = scripts[0];
      if (!isLeaf(leaf)) {
        // check if its a branch
        return taprootTreeHelper(leaf);
      }
      const version = leaf.leafVersion || LEAF_VERSION_TAPSCRIPT;
      if ((version & 1) !== 0) {
        throw new Error('Invalid leaf version');
      }
      if (!leaf.name) {
        return { leaves: [], hash: tapLeafHash(leaf) };
      }
      return {
        leaves: [
          {
            name: leaf.name,
            scriptHex: leaf.scriptHex,
            leafVersion: version,
            controlBlock: Buffer.alloc(0),
          },
        ],
        hash: tapLeafHash(leaf),
      };
    default:
      // 2 or more entries
      const middleIndex = Math.ceil(scripts.length / 2);
      const left = taprootTreeHelper(scripts.slice(0, middleIndex));
      const right = taprootTreeHelper(scripts.slice(middleIndex));
      const finalLeftLeaves = [];
      const finalRightLeaves = [];
      for (const l of left.leaves) {
        finalLeftLeaves.push({
          ...l,
          controlBlock: Buffer.concat([l.controlBlock, right.hash]),
        });
      }
      for (const l of right.leaves) {
        finalRightLeaves.push({
          ...l,
          controlBlock: Buffer.concat([l.controlBlock, left.hash]),
        });
      }
      const hashes = [left.hash, right.hash];
      // check if left is greater than right
      if (left.hash.compare(right.hash) > 0) {
        hashes.reverse();
      }
      return {
        leaves: [...finalLeftLeaves, ...finalRightLeaves],
        hash: (0, crypto_1.taggedHash)(
          'TapBranch/elements',
          Buffer.concat(hashes),
        ),
      };
  }
}
exports.taprootTreeHelper = taprootTreeHelper;
function tweakPublicKey(publicKey, hash) {
  const XOnlyPubKey = publicKey.slice(1, 33);
  const toTweak = Buffer.concat([XOnlyPubKey, hash]);
  const tweakHash = (0, crypto_1.taggedHash)('TapTweak/elements', toTweak);
  const tweaked = (0, tiny_secp256k1_1.xOnlyPointAddTweak)(
    XOnlyPubKey,
    tweakHash,
  );
  if (!tweaked) throw new Error('Invalid tweaked key');
  return tweaked;
}
// compute a segwit V1 output script
function taprootOutputScript(internalPublicKey, scriptTree) {
  let treeHash = Buffer.alloc(0);
  if (scriptTree) {
    treeHash = taprootTreeHelper(scriptTree).hash;
  }
  const { xOnlyPubkey } = tweakPublicKey(internalPublicKey, treeHash);
  return Buffer.concat([Buffer.from([0x51, 0x20]), xOnlyPubkey]);
}
exports.taprootOutputScript = taprootOutputScript;
/**
 * Compute the taproot part of the witness stack needed to spend a P2TR output via script path
 * TAPROOT_WITNESS = [SCRIPT, CONTROL_BLOCK]
 * WITNESS_STACK = [...INPUTS, TAPROOT_WITNESS] <- u need to add the script's inputs to the stack
 * @param internalPublicKey the taproot internal public key
 * @param scriptTree the taproot script tree using to recompute path to the leaf. Names have to be specified!
 * @param scriptName the leaf to use
 */
function taprootSignScriptStack(internalPublicKey, scriptTree, scriptName) {
  const taprootTree = taprootTreeHelper(scriptTree);
  const scriptLeaf = taprootTree.leaves.find(l => l.name === scriptName);
  if (!scriptLeaf) {
    throw new Error('Script not found');
  }
  const { parity } = tweakPublicKey(internalPublicKey, taprootTree.hash);
  const parityBit = Buffer.of(scriptLeaf.leafVersion + parity);
  const control = Buffer.concat([
    parityBit,
    internalPublicKey.slice(1),
    scriptLeaf.controlBlock,
  ]);
  return [Buffer.from(scriptLeaf.scriptHex, 'hex'), control];
}
exports.taprootSignScriptStack = taprootSignScriptStack;
// Order of the curve (N) - 1
const N_LESS_1 = Buffer.from(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
  'hex',
);
// 1 represented as 32 bytes BE
const ONE = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
// Compute the witness signature for a P2TR output (key path)
function taprootSignKey(messageHash, key) {
  if (!key.privateKey) {
    throw new Error('Private key is required');
  }
  const privateKey =
    key.publicKey[0] === 2
      ? key.privateKey
      : (0, tiny_secp256k1_1.privateAdd)(
          (0, tiny_secp256k1_1.privateSub)(N_LESS_1, key.privateKey),
          ONE,
        );
  const tweakHash = (0, crypto_1.taggedHash)(
    'TapTweak/elements',
    key.publicKey.slice(1, 33),
  );
  const newPrivateKey = (0, tiny_secp256k1_1.privateAdd)(privateKey, tweakHash);
  if (newPrivateKey === null) throw new Error('Invalid Tweak');
  const signed = (0, tiny_secp256k1_1.signSchnorr)(
    messageHash,
    newPrivateKey,
    Buffer.alloc(32),
  );
  const ok = (0, tiny_secp256k1_1.verifySchnorr)(
    messageHash,
    ecpair_1.ECPair.fromPrivateKey(Buffer.from(newPrivateKey)).publicKey.slice(
      1,
    ),
    signed,
  );
  if (!ok) throw new Error('Invalid Signature');
  return Buffer.from(signed);
}
exports.taprootSignKey = taprootSignKey;
