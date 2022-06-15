import { taggedHash } from './crypto';
import {
  ECPairFactory,
  TinySecp256k1Interface as ECPairSecp256k1Interface,
} from 'ecpair';
import { BufferWriter, varSliceSize } from './bufferutils';

export const LEAF_VERSION_TAPSCRIPT = 0xc4;

export interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}

export interface TinySecp256k1Interface extends ECPairSecp256k1Interface {
  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array,
  ): XOnlyPointAddTweakResult | null;
  privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
  privateSub(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
  signSchnorr(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
  verifySchnorr(h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean;
}

// All the "taproot" crypto functions
// Use factory to inject TinySecp256k1Interface lib
export interface BIP341API {
  // tweak the internal key and sign the message hash (schnorr)
  taprootSignKey(messageHash: Buffer, privateKey: Buffer): Buffer;
  // tweak the internal pubkey, and create the control block from the path + treeRootHash
  taprootSignScriptStack(
    internalPublicKey: Buffer,
    leaf: TaprootLeaf,
    treeRootHash: Buffer,
    path: Buffer[],
  ): Buffer[];
  // tweak the internal pubkey and return the P2TR output script (witness v1)
  taprootOutputScript(internalPublicKey: Buffer, tree?: HashTree): Buffer;
}

export function BIP341Factory(ecc: TinySecp256k1Interface): BIP341API {
  return {
    taprootSignKey: taprootSignKey(ecc),
    taprootSignScriptStack: taprootSignScriptStack(ecc),
    taprootOutputScript: taprootOutputScript(ecc),
  };
}

// Leaf is the base object representing a leaf in taproot tree
// if leafVersion is unspecified, will use LEAF_VERSION_TAPSCRIPT
export interface TaprootLeaf {
  scriptHex: string;
  version?: number;
}

// HashTree is the main Taproot structure representing a merkle binary tree
export interface HashTree {
  hash: Buffer;
  scriptHex?: string;
  left?: HashTree;
  right?: HashTree;
}

// hash TaprootLeaf object, could be use to identify a leaf in a MAST tree
export function tapLeafHash(leaf: TaprootLeaf): Buffer {
  const leafVersion = leaf.version || LEAF_VERSION_TAPSCRIPT;
  const script = Buffer.from(leaf.scriptHex, 'hex');

  const bufferWriter = BufferWriter.withCapacity(1 + varSliceSize(script));
  bufferWriter.writeUInt8(leafVersion);
  bufferWriter.writeVarSlice(script);
  return taggedHash('TapLeaf/elements', bufferWriter.end());
}

// recursively build the Taproot tree from a ScriptTree structure
export function toHashTree(
  leaves: TaprootLeaf[],
  withScriptHex = false,
): HashTree {
  switch (leaves.length) {
    case 0:
      return { hash: Buffer.alloc(32) };
    case 1:
      const leaf = leaves[0];
      const version = leaf.version || LEAF_VERSION_TAPSCRIPT;
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
        hash: taggedHash(
          'TapBranch/elements',
          Buffer.concat([leftHash, rightHash]),
        ),
      };
  }
}

/**
 * Given a MAST tree, it finds the path of a particular hash.
 * @param node - the root of the tree
 * @param hash - the hash to search for
 * @returns - and array of hashes representing the path, or an empty array if no pat is found
 */
export function findScriptPath(node: HashTree, hash: Buffer): Buffer[] {
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

function tweakPublicKey(
  publicKey: Buffer,
  hash: Buffer,
  ecc: TinySecp256k1Interface,
): XOnlyPointAddTweakResult {
  const XOnlyPubKey = publicKey.slice(1, 33);
  const toTweak = Buffer.concat([XOnlyPubKey, hash]);
  const tweakHash = taggedHash('TapTweak/elements', toTweak);
  const tweaked = ecc.xOnlyPointAddTweak(XOnlyPubKey, tweakHash);
  if (!tweaked) throw new Error('Invalid tweaked key');
  return tweaked;
}

// compute a segwit V1 output script
function taprootOutputScript(
  ecc: TinySecp256k1Interface,
): BIP341API['taprootOutputScript'] {
  return (internalPublicKey: Buffer, tree?: HashTree): Buffer => {
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
function taprootSignScriptStack(
  ecc: TinySecp256k1Interface,
): BIP341API['taprootSignScriptStack'] {
  return (
    internalPublicKey: Buffer,
    leaf: TaprootLeaf,
    treeRootHash: Buffer,
    path: Buffer[],
  ): Buffer[] => {
    const { parity } = tweakPublicKey(internalPublicKey, treeRootHash, ecc);
    const parityBit = Buffer.of(
      leaf.version || LEAF_VERSION_TAPSCRIPT + parity,
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
function taprootSignKey(
  ecc: TinySecp256k1Interface,
): BIP341API['taprootSignKey'] {
  return (messageHash: Buffer, key: Buffer): Buffer => {
    const signingEcPair = ECPairFactory(ecc).fromPrivateKey(key);

    const privateKey =
      signingEcPair.publicKey[0] === 2
        ? signingEcPair.privateKey
        : ecc.privateAdd(ecc.privateSub(N_LESS_1, key)!, ONE);
    const tweakHash = taggedHash(
      'TapTweak/elements',
      signingEcPair.publicKey.slice(1, 33),
    );
    const newPrivateKey = ecc.privateAdd(privateKey!, tweakHash);
    if (newPrivateKey === null) throw new Error('Invalid Tweak');
    const signed = ecc.signSchnorr(
      messageHash,
      newPrivateKey,
      Buffer.alloc(32),
    );

    const ok = ecc.verifySchnorr(
      messageHash,
      ECPairFactory(ecc)
        .fromPrivateKey(Buffer.from(newPrivateKey))
        .publicKey.slice(1),
      signed,
    );
    if (!ok) throw new Error('Invalid Signature');

    return Buffer.from(signed);
  };
}
