import { taggedHash } from './crypto';
import {
  privateAdd,
  privateSub,
  signSchnorr,
  verifySchnorr,
  xOnlyPointAddTweak,
} from 'tiny-secp256k1';
import { BufferWriter, varSliceSize } from './bufferutils';
import { ECPairInterface } from 'ecpair';
import { ECPair } from './ecpair';

const LEAF_VERSION_TAPSCRIPT = 0xc4;

// Leaf is the base object representing a leaf in taproot tree
// if name is unspecified, `taprootTreeHelper` will only return the hash (useful for create output script)
// if leafVersion is unspecified, will use LEAF_VERSION_TAPSCRIPT 
export interface Leaf {
  name?: string;
  scriptHex: string;
  leafVersion?: number;
}

// using as argument, "translated" into TaprootTree via taprootTreeHelper function
// order of elements in arrays is important! (taproot tree are binary trees)
export type ScriptTree = Leaf | ScriptTree[];

// leaf + force leafVersion to be defined + controlBlock
export interface TaprootLeaf extends Leaf {
  leafVersion: number;
  controlBlock: Buffer;
}

// a ScriptTree + all the control blocks for leaves + the root hash
export interface TaprootTree {
  leaves: TaprootLeaf[];
  hash: Buffer;
}

function tapLeafHash(leaf: Leaf): Buffer {
  const leafVersion = leaf.leafVersion || LEAF_VERSION_TAPSCRIPT;
  const script = Buffer.from(leaf.scriptHex, 'hex');

  const bufferWriter = BufferWriter.withCapacity(1 + varSliceSize(script));
  bufferWriter.writeUInt8(leafVersion);
  bufferWriter.writeVarSlice(script);
  return taggedHash('TapLeaf/elements', bufferWriter.end());
}

function isLeaf(node: ScriptTree): node is Leaf {
  return typeof node === 'object' && !Array.isArray(node);
}

// recursively build the Taproot tree from a ScriptTree structure
// for each leaf, will compute the corresponding control block
export function taprootTreeHelper(scripts: ScriptTree): TaprootTree {
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

      const finalLeftLeaves: TaprootLeaf[] = [];
      const finalRightLeaves: TaprootLeaf[] = [];

      for (const leaf of left.leaves) {
        finalLeftLeaves.push({
          ...leaf,
          controlBlock: Buffer.concat([leaf.controlBlock, right.hash]),
        });
      }

      for (const leaf of right.leaves) {
        finalRightLeaves.push({
          ...leaf,
          controlBlock: Buffer.concat([leaf.controlBlock, left.hash]),
        });
      }

      const hashes = [left.hash, right.hash];
      // check if left is greater than right
      if (left.hash.compare(right.hash) > 0) {
        hashes.reverse();
      }

      return {
        leaves: [...finalLeftLeaves, ...finalRightLeaves],
        hash: taggedHash('TapBranch/elements', Buffer.concat(hashes)),
      };
  }
}

function tweakPublicKey(publicKey: Buffer, hash: Buffer) {
  const XOnlyPubKey = publicKey.slice(1, 33);
  const toTweak = Buffer.concat([XOnlyPubKey, hash]);
  const tweakHash = taggedHash('TapTweak/elements', toTweak);
  const tweaked = xOnlyPointAddTweak(XOnlyPubKey, tweakHash);
  if (!tweaked) throw new Error('Invalid tweaked key');
  return tweaked;
}

// compute a segwit V1 output script
export function taprootOutputScript(
  internalPublicKey: Buffer,
  scriptTree?: ScriptTree,
): Buffer {
  let treeHash = Buffer.alloc(0);
  if (scriptTree) {
    treeHash = taprootTreeHelper(scriptTree).hash;
  }

  const { xOnlyPubkey } = tweakPublicKey(internalPublicKey, treeHash);
  return Buffer.concat([Buffer.from([0x51, 0x20]), xOnlyPubkey]);
}

/**
 * Compute the taproot part of the witness stack needed to spend a P2TR output via script path
 * TAPROOT_WITNESS = [SCRIPT, CONTROL_BLOCK]
 * WITNESS_STACK = [...INPUTS, TAPROOT_WITNESS] <- u need to add the script's inputs to the stack
 * @param internalPublicKey the taproot internal public key
 * @param scriptTree the taproot script tree using to recompute path to the leaf. Names have to be specified!
 * @param scriptName the leaf to use
 */
export function taprootSignScriptStack(
  internalPublicKey: Buffer,
  scriptTree: ScriptTree,
  scriptName: string,
): Buffer[] {
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
export function taprootSignKey(
  messageHash: Buffer,
  key: ECPairInterface,
): Buffer {
  if (!key.privateKey) {
    throw new Error('Private key is required');
  }

  const privateKey =
    key.publicKey[0] === 2
      ? key.privateKey
      : privateAdd(privateSub(N_LESS_1, key.privateKey)!, ONE)!;
  const tweakHash = taggedHash('TapTweak/elements', key.publicKey.slice(1, 33));
  const newPrivateKey = privateAdd(privateKey, tweakHash);
  if (newPrivateKey === null) throw new Error('Invalid Tweak');
  const signed = signSchnorr(messageHash, newPrivateKey, Buffer.alloc(32));

  const ok = verifySchnorr(
    messageHash,
    ECPair.fromPrivateKey(Buffer.from(newPrivateKey)).publicKey.slice(1),
    signed,
  );
  if (!ok) throw new Error('Invalid Signature');

  return Buffer.from(signed);
}
