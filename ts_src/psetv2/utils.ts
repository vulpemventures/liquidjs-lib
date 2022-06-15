import { payments } from '..';
import { varuint } from '../bufferutils';
import { hash160 } from '../crypto';
import * as bscript from '../script';
import { PartialSig } from './interfaces';

export function getPayment(
  script: Buffer,
  scriptType: ScriptType,
  partialSig: PartialSig[],
): payments.Payment {
  switch (scriptType) {
    case 'p2ms':
      const sigs = getSortedSigs(script, partialSig);
      return payments.p2ms({
        output: script,
        signatures: sigs,
      });
    case 'p2pk':
      return payments.p2pk({
        output: script,
        signature: partialSig[0].signature,
      });
    case 'p2pkh':
      return payments.p2pkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
    case 'p2wpkh':
      return payments.p2wpkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
    default:
      throw new Error('unknown script');
  }
}

export function hasSigs(
  neededSigs: number,
  partialSig?: any[],
  pubkeys?: Buffer[],
): boolean {
  if (!partialSig) return false;
  let sigs: any;
  if (pubkeys) {
    sigs = pubkeys
      .map(pkey => {
        const pubkey = compressPubkey(pkey);
        return partialSig.find(pSig => pSig.pubkey.equals(pubkey));
      })
      .filter(v => !!v);
  } else {
    sigs = partialSig;
  }
  if (sigs.length > neededSigs) throw new Error('Too many signatures');
  return sigs.length === neededSigs;
}

function getSortedSigs(script: Buffer, partialSig: PartialSig[]): Buffer[] {
  const p2ms = payments.p2ms({ output: script });
  // for each pubkey in order of p2ms script
  return p2ms
    .pubkeys!.map(pk => {
      // filter partialSig array by pubkey being equal
      return (
        partialSig.filter(ps => {
          return ps.pubkey.equals(pk);
        })[0] || {}
      ).signature;
      // Any pubkey without a match will return undefined
      // this last filter removes all the undefined items in the array.
    })
    .filter(v => !!v);
}

export function witnessStackToScriptWitness(witness: Buffer[]): Buffer {
  let buffer = Buffer.allocUnsafe(0);

  function writeSlice(slice: Buffer): void {
    buffer = Buffer.concat([buffer, Buffer.from(slice)]);
  }

  function writeVarInt(i: number): void {
    const currentLen = buffer.length;
    const varintLen = varuint.encodingLength(i);

    buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)]);
    varuint.encode(i, buffer, currentLen);
  }

  function writeVarSlice(slice: Buffer): void {
    writeVarInt(slice.length);
    writeSlice(slice);
  }

  function writeVector(vector: Buffer[]): void {
    writeVarInt(vector.length);
    vector.forEach(writeVarSlice);
  }

  writeVector(witness);

  return buffer;
}

export function scriptWitnessToWitnessStack(buffer: Buffer): Buffer[] {
  let offset = 0;

  function readSlice(n: number): Buffer {
    offset += n;
    return buffer.slice(offset - n, offset);
  }

  function readVarInt(): number {
    const vi = varuint.decode(buffer, offset);
    offset += (varuint.decode as any).bytes;
    return vi;
  }

  function readVarSlice(): Buffer {
    return readSlice(readVarInt());
  }

  function readVector(): Buffer[] {
    const count = readVarInt();
    const vector: Buffer[] = [];
    for (let i = 0; i < count; i++) vector.push(readVarSlice());
    return vector;
  }

  return readVector();
}

function compressPubkey(pubkey: Buffer): Buffer {
  if (pubkey.length === 65) {
    const parity = pubkey[64] & 1;
    const newKey = pubkey.slice(0, 33);
    newKey[0] = 2 | parity;
    return newKey;
  }
  return pubkey.slice();
}

type ScriptType =
  | 'p2pk'
  | 'p2pkh'
  | 'p2ms'
  | 'p2sh'
  | 'p2wpkh'
  | 'p2wsh'
  | 'p2tr'
  | 'nonstandard';

export function classifyScript(script: Buffer): ScriptType {
  if (isP2PK(script)) return 'p2pk';
  if (isP2PKH(script)) return 'p2pkh';
  if (isP2MS(script)) return 'p2ms';
  if (isP2SH(script)) return 'p2sh';
  if (isP2WPKH(script)) return 'p2wpkh';
  if (isP2WSH(script)) return 'p2wsh';
  return 'nonstandard';
}

function isPaymentFactory(payment: any): (script: Buffer) => boolean {
  return (script: Buffer): boolean => {
    try {
      payment({ output: script });
      return true;
    } catch (err) {
      return false;
    }
  };
}

export const isP2MS = isPaymentFactory(payments.p2ms);
export const isP2PK = isPaymentFactory(payments.p2pk);
export const isP2PKH = isPaymentFactory(payments.p2pkh);
export const isP2WPKH = isPaymentFactory(payments.p2wpkh);
export const isP2WSH = isPaymentFactory(payments.p2wsh);
export const isP2SH = isPaymentFactory(payments.p2sh);
// TODO: use payment factory once in place. For now, let's check
// if the script starts with OP_1.
export const isP2TR = (script: Buffer): boolean => script[0] === 0x01;

export function pubkeyPositionInScript(pubkey: Buffer, script: Buffer): number {
  const pubkeyHash = hash160(pubkey);
  const pubkeyXOnly = pubkey.slice(1, 33); // slice before calling?

  const decompiled = bscript.decompile(script);
  if (decompiled === null) throw new Error('Unknown script error');

  return decompiled.findIndex(element => {
    if (typeof element === 'number') return false;
    return (
      element.equals(pubkey) ||
      element.equals(pubkeyHash) ||
      element.equals(pubkeyXOnly)
    );
  });
}
