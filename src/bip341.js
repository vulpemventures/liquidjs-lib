'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.findScriptPath =
  exports.toHashTree =
  exports.tapLeafHash =
  exports.BIP341Factory =
  exports.LEAF_VERSION_TAPSCRIPT =
    void 0;
const crypto_1 = require('./crypto');
const ecpair_1 = require('ecpair');
const bufferutils_1 = require('./bufferutils');
exports.LEAF_VERSION_TAPSCRIPT = 0xc4;
function BIP341Factory(ecc) {
  return {
    taprootSignKey: taprootSignKey(ecc),
    taprootSignScriptStack: taprootSignScriptStack(ecc),
    taprootOutputScript: taprootOutputScript(ecc),
  };
}
exports.BIP341Factory = BIP341Factory;
// hash TaprootLeaf object, could be use to identify a leaf in a MAST tree
function tapLeafHash(leaf) {
  const leafVersion = leaf.version || exports.LEAF_VERSION_TAPSCRIPT;
  const script = Buffer.from(leaf.scriptHex, 'hex');
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
    1 + (0, bufferutils_1.varSliceSize)(script),
  );
  bufferWriter.writeUInt8(leafVersion);
  bufferWriter.writeVarSlice(script);
  return (0, crypto_1.taggedHash)('TapLeaf/elements', bufferWriter.end());
}
exports.tapLeafHash = tapLeafHash;
// recursively build the Taproot tree from a ScriptTree structure
function toHashTree(leaves, withScriptHex = false) {
  switch (leaves.length) {
    case 0:
      return { hash: Buffer.alloc(32) };
    case 1:
      const leaf = leaves[0];
      const version = leaf.version || exports.LEAF_VERSION_TAPSCRIPT;
      if ((version & 1) !== 0) {
        throw new Error('Invalid leaf version');
      }
      return {
        hash: tapLeafHash(leaf),
        scriptHex: withScriptHex ? leaf.scriptHex : undefined,
      };
    default:
      // 2 or more entries
      const middleIndex = Math.ceil(leaves.length / 2);
      const left = toHashTree(leaves.slice(0, middleIndex), withScriptHex);
      const right = toHashTree(leaves.slice(middleIndex), withScriptHex);
      let leftHash = left.hash;
      let rightHash = right.hash;
      // check if left is greater than right
      if (left.hash.compare(right.hash) > 0) {
        [leftHash, rightHash] = [rightHash, leftHash];
      }
      return {
        left,
        right,
        hash: (0, crypto_1.taggedHash)(
          'TapBranch/elements',
          Buffer.concat([leftHash, rightHash]),
        ),
      };
  }
}
exports.toHashTree = toHashTree;
/**
 * Given a MAST tree, it finds the path of a particular hash.
 * @param node - the root of the tree
 * @param hash - the hash to search for
 * @returns - and array of hashes representing the path, or an empty array if no pat is found
 */
function findScriptPath(node, hash) {
  if (node.left) {
    if (node.left.hash.equals(hash)) return node.right ? [node.right.hash] : [];
    const leftPath = findScriptPath(node.left, hash);
    if (leftPath.length)
      return node.right ? leftPath.concat([node.right.hash]) : leftPath;
  }
  if (node.right) {
    if (node.right.hash.equals(hash)) return node.left ? [node.left.hash] : [];
    const rightPath = findScriptPath(node.right, hash);
    if (rightPath.length)
      return node.left ? rightPath.concat([node.left.hash]) : rightPath;
  }
  return [];
}
exports.findScriptPath = findScriptPath;
function tweakPublicKey(publicKey, hash, ecc) {
  const XOnlyPubKey = publicKey.slice(1, 33);
  const toTweak = Buffer.concat([XOnlyPubKey, hash]);
  const tweakHash = (0, crypto_1.taggedHash)('TapTweak/elements', toTweak);
  const tweaked = ecc.xOnlyPointAddTweak(XOnlyPubKey, tweakHash);
  if (!tweaked) throw new Error('Invalid tweaked key');
  return tweaked;
}
// compute a segwit V1 output script
function taprootOutputScript(ecc) {
  return (internalPublicKey, tree) => {
    let treeHash = Buffer.alloc(0);
    if (tree) {
      treeHash = tree.hash;
    }
    const { xOnlyPubkey } = tweakPublicKey(internalPublicKey, treeHash, ecc);
    return Buffer.concat([Buffer.from([0x51, 0x20]), xOnlyPubkey]);
  };
}
/**
 * Compute the taproot part of the witness stack needed to spend a P2TR output via script path
 * TAPROOT_WITNESS = [SCRIPT, CONTROL_BLOCK]
 * WITNESS_STACK = [...INPUTS, TAPROOT_WITNESS] <- u need to add the script's inputs to the stack
 * @param internalPublicKey the taproot internal public key
 * @param leaf the leaf to use to sign the taproot coin
 * @param path the path to the leaf in the MAST tree see findScriptPath function
 */
function taprootSignScriptStack(ecc) {
  return (internalPublicKey, leaf, treeRootHash, path) => {
    const { parity } = tweakPublicKey(internalPublicKey, treeRootHash, ecc);
    const parityBit = Buffer.of(
      leaf.version || exports.LEAF_VERSION_TAPSCRIPT + parity,
    );
    const control = Buffer.concat([
      parityBit,
      internalPublicKey.slice(1),
      ...path,
    ]);
    return [Buffer.from(leaf.scriptHex, 'hex'), control];
  };
}
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
function taprootSignKey(ecc) {
  return (messageHash, key) => {
    const signingEcPair = (0, ecpair_1.ECPairFactory)(ecc).fromPrivateKey(key);
    const privateKey =
      signingEcPair.publicKey[0] === 2
        ? signingEcPair.privateKey
        : ecc.privateAdd(ecc.privateSub(N_LESS_1, key), ONE);
    const tweakHash = (0, crypto_1.taggedHash)(
      'TapTweak/elements',
      signingEcPair.publicKey.slice(1, 33),
    );
    const newPrivateKey = ecc.privateAdd(privateKey, tweakHash);
    if (newPrivateKey === null) throw new Error('Invalid Tweak');
    const signed = ecc.signSchnorr(
      messageHash,
      newPrivateKey,
      Buffer.alloc(32),
    );
    const ok = ecc.verifySchnorr(
      messageHash,
      (0, ecpair_1.ECPairFactory)(ecc)
        .fromPrivateKey(Buffer.from(newPrivateKey))
        .publicKey.slice(1),
      signed,
    );
    if (!ok) throw new Error('Invalid Signature');
    return Buffer.from(signed);
  };
}
