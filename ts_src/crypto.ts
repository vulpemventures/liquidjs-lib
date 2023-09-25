import createHash from 'create-hash';

export function ripemd160(buffer: Buffer): Buffer {
  try {
    return createHash('rmd160').update(buffer).digest();
  } catch (err) {
    return createHash('ripemd160').update(buffer).digest();
  }
}

export function sha1(buffer: Buffer): Buffer {
  return createHash('sha1').update(buffer).digest();
}

export function sha256(buffer: Buffer): Buffer {
  return createHash('sha256').update(buffer).digest();
}

export function hash160(buffer: Buffer): Buffer {
  return ripemd160(sha256(buffer));
}

export function hash256(buffer: Buffer): Buffer {
  return sha256(sha256(buffer));
}

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
] as const;
export type TaggedHashPrefix = typeof TAGS[number];
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES = Object.fromEntries(
  TAGS.map((tag) => {
    const tagHash = sha256(Buffer.from(tag, 'utf-8'));
    return [tag, Buffer.concat([tagHash, tagHash])];
  }),
) as { [k in TaggedHashPrefix]: Buffer };

export function taggedHash(prefix: TaggedHashPrefix, data: Buffer): Buffer {
  return sha256(Buffer.concat([TAGGED_HASH_PREFIXES[prefix], data]));
}

/**
 * Serialize outpoint as txid | vout, sort them and sha256 the concatenated result
 * @param parameters list of outpoints (txid, vout)
 */
export function hashOutpoints(
  parameters: { txid: string; vout: number }[],
): Buffer {
  let bufferConcat = Buffer.alloc(0);
  const outpoints: Array<Buffer> = [];
  for (const parameter of parameters) {
    const voutBuffer = Buffer.allocUnsafe(4);
    voutBuffer.writeUint32BE(parameter.vout, 0);

    outpoints.push(
      Buffer.concat([
        Buffer.from(parameter.txid, 'hex').reverse(),
        voutBuffer.reverse(),
      ]),
    );
  }

  outpoints.sort(Buffer.compare);

  for (const outpoint of outpoints) {
    bufferConcat = Buffer.concat([bufferConcat, outpoint]);
  }
  return sha256(bufferConcat);
}
