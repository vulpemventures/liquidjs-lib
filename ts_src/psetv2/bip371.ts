import { TapLeafScript, TapScriptSig } from './interfaces';
import { PsetInput } from './input';
import { tapLeafHash } from '../bip341';
import { pubkeyPositionInScript } from './utils';

export const toXOnly = (pubkey: Buffer) => {
  switch (pubkey.length) {
    case 32:
      return pubkey;
    case 33:
      return Buffer.from(pubkey.slice(1));
    default:
      throw new Error('Invalid pubkey length');
  }
};

export function serializeTaprootSignature(
  sig: Buffer,
  sighashType?: number,
): Buffer {
  const sighashTypeByte = sighashType
    ? Buffer.from([sighashType!])
    : Buffer.from([]);

  return Buffer.concat([sig, sighashTypeByte]);
}

export function sortSignatures(
  input: PsetInput,
  tapLeaf: TapLeafScript,
): Buffer[] {
  const leafHash = tapLeafHash({
    scriptHex: tapLeaf.script.toString('hex'),
    version: tapLeaf.leafVersion,
  });

  return (input.tapScriptSig || [])
    .filter((tss) => tss.leafHash.equals(leafHash))
    .map((tss) => addPubkeyPositionInScript(tapLeaf.script, tss))
    .sort((t1, t2) => t2.positionInScript - t1.positionInScript)
    .map((t) => t.signature) as Buffer[];
}

function addPubkeyPositionInScript(
  script: Buffer,
  tss: TapScriptSig,
): TapScriptSigWitPosition {
  return Object.assign(
    {
      positionInScript: pubkeyPositionInScript(tss.pubkey, script),
    },
    tss,
  ) as TapScriptSigWitPosition;
}

/**
 * Find tapleaf by hash, or get the signed tapleaf with the shortest path.
 */
export function findTapLeafToFinalize(
  input: PsetInput,
  inputIndex: number,
  leafHashToFinalize?: Buffer,
): TapLeafScript {
  if (!input.tapScriptSig || !input.tapScriptSig.length)
    throw new Error(
      `Can not finalize taproot input #${inputIndex}. No tapleaf script signature provided.`,
    );
  const tapLeaf = (input.tapLeafScript || [])
    .sort((a, b) => a.controlBlock.length - b.controlBlock.length)
    .find((leaf) =>
      canFinalizeLeaf(leaf, input.tapScriptSig!, leafHashToFinalize),
    );

  if (!tapLeaf)
    throw new Error(
      `Can not finalize taproot input #${inputIndex}. Signature for tapleaf script not found.`,
    );

  return tapLeaf;
}

function canFinalizeLeaf(
  leaf: TapLeafScript,
  tapScriptSig: TapScriptSig[],
  hash?: Buffer,
): boolean {
  const leafHash = tapLeafHash({
    scriptHex: leaf.script.toString('hex'),
    version: leaf.leafVersion,
  });
  const whiteListedHash = !hash || hash.equals(leafHash);
  return (
    whiteListedHash &&
    tapScriptSig!.find((tss) => tss.leafHash.equals(leafHash)) !== undefined
  );
}

interface TapScriptSigWitPosition extends TapScriptSig {
  positionInScript: number;
}
