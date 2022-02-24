import * as bcrypto from '../crypto';
import { liquid as LIQUID_NETWORK } from '../networks';
import * as bscript from '../script';
import { isPoint, typeforce as typef } from '../types';
import {
  Payment,
  PaymentFunction,
  PaymentOpts,
  Stack,
  StackFunction,
} from './index';
import * as lazy from './lazy';
import * as bs58check from 'bs58check';
const OPS = bscript.OPS;

function stacksEqual(a: Buffer[], b: Buffer[]): boolean {
  if (a.length !== b.length) return false;

  return a.every((x, i) => {
    return x.equals(b[i]);
  });
}

// input: [redeemScriptSig ...] {redeemScript}
// witness: <?>
// output: OP_HASH160 {hash160(redeemScript)} OP_EQUAL
export function p2sh(a: Payment, opts?: PaymentOpts): Payment {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.redeem &&
    !a.input &&
    !a.confidentialAddress
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});

  typef(
    {
      network: typef.maybe(typef.Object),

      address: typef.maybe(typef.String),
      hash: typef.maybe(typef.BufferN(20)),
      output: typef.maybe(typef.BufferN(23)),

      redeem: typef.maybe({
        network: typef.maybe(typef.Object),
        output: typef.maybe(typef.Buffer),
        input: typef.maybe(typef.Buffer),
        witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      }),
      input: typef.maybe(typef.Buffer),
      witness: typef.maybe(typef.arrayOf(typef.Buffer)),
      blindkey: typef.maybe(isPoint),
      confidentialAddress: typef.maybe(typef.String),
    },
    a,
  );

  let network = a.network;
  if (!network) {
    network = (a.redeem && a.redeem.network) || LIQUID_NETWORK;
  }

  const o: Payment = { network };

  const _address = lazy.value(() => {
    const payload = bs58check.decode(a.address!);
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });
  const _chunks = lazy.value(() => {
    return bscript.decompile(a.input!);
  }) as StackFunction;
  const _redeem = lazy.value(
    (): Payment => {
      const chunks = _chunks();
      return {
        network,
        output: chunks[chunks.length - 1] as Buffer,
        input: bscript.compile(chunks.slice(0, -1)),
        witness: a.witness || [],
      };
    },
  ) as PaymentFunction;
  const _confidentialAddress = lazy.value(() => {
    const payload = bs58check.decode(a.confidentialAddress!);
    const blindkey = payload.slice(2, 35);
    const unconfidentialAddressBuffer = Buffer.concat([
      Buffer.from([payload.readUInt8(1)]),
      payload.slice(35),
    ]);
    const unconfidentialAddress = bs58check.encode(unconfidentialAddressBuffer);
    return { blindkey, unconfidentialAddress };
  });

  // output dependents
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;

    const payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(o.network!.scriptHash, 0);
    o.hash.copy(payload, 1);
    return bs58check.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    // in order of least effort
    if (a.output) return a.output.slice(2, 22);
    if (a.address) return _address().hash;
    if (o.redeem && o.redeem.output) return bcrypto.hash160(o.redeem.output);
    if (a.confidentialAddress) {
      const address = _confidentialAddress().unconfidentialAddress;
      return bs58check.decode(address).slice(1);
    }
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript.compile([OPS.OP_HASH160, o.hash, OPS.OP_EQUAL]);
  });

  // input dependents
  lazy.prop(o, 'redeem', () => {
    if (!a.input) return;
    return _redeem();
  });
  lazy.prop(o, 'input', () => {
    if (!a.redeem || !a.redeem.input || !a.redeem.output) return;
    return bscript.compile(
      ([] as Stack).concat(
        bscript.decompile(a.redeem.input) as Stack,
        a.redeem.output,
      ),
    );
  });
  lazy.prop(o, 'witness', () => {
    if (o.redeem && o.redeem.witness) return o.redeem.witness;
    if (o.input) return [];
  });
  lazy.prop(o, 'name', () => {
    const nameParts = ['p2sh'];
    if (o.redeem !== undefined && o.redeem.name !== undefined)
      nameParts.push(o.redeem.name!);
    return nameParts.join('-');
  });
  lazy.prop(o, 'blindkey', () => {
    if (a.confidentialAddress) return _confidentialAddress().blindkey;
    if (a.blindkey) return a.blindkey;
  });
  lazy.prop(o, 'confidentialAddress', () => {
    if (!o.address) return;
    if (!o.blindkey) return;
    const payload = bs58check.decode(o.address!);
    const confidentialAddress = Buffer.concat([
      Buffer.from([network!.confidentialPrefix, payload.readUInt8(0)]),
      o.blindkey!,
      Buffer.from(payload.slice(1)),
    ]);
    return bs58check.encode(confidentialAddress);
  });

  if (opts.validate) {
    let hash: Buffer = Buffer.from([]);
    let blindkey: Buffer = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.scriptHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }

    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }

    if (a.output) {
      if (
        a.output.length !== 23 ||
        a.output[0] !== OPS.OP_HASH160 ||
        a.output[1] !== 0x14 ||
        a.output[22] !== OPS.OP_EQUAL
      )
        throw new TypeError('Output is invalid');

      const hash2 = a.output.slice(2, 22);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }

    // inlined to prevent 'no-inner-declarations' failing
    const checkRedeem = (redeem: Payment): void => {
      // is the redeem output empty/invalid?
      if (redeem.output) {
        const decompile = bscript.decompile(redeem.output);
        if (!decompile || decompile.length < 1)
          throw new TypeError('Redeem.output too short');

        // match hash against other sources
        const hash2 = bcrypto.hash160(redeem.output);
        if (hash.length > 0 && !hash.equals(hash2))
          throw new TypeError('Hash mismatch');
        else hash = hash2;
      }

      if (redeem.input) {
        const hasInput = redeem.input.length > 0;
        const hasWitness = redeem.witness && redeem.witness.length > 0;
        if (!hasInput && !hasWitness) throw new TypeError('Empty input');
        if (hasInput && hasWitness)
          throw new TypeError('Input and witness provided');
        if (hasInput) {
          const richunks = bscript.decompile(redeem.input) as Stack;
          if (!bscript.isPushOnly(richunks))
            throw new TypeError('Non push-only scriptSig');
        }
      }
    };

    if (a.input) {
      const chunks = _chunks();
      if (!chunks || chunks.length < 1) throw new TypeError('Input too short');
      if (!Buffer.isBuffer(_redeem().output))
        throw new TypeError('Input is invalid');

      checkRedeem(_redeem());
    }

    if (a.redeem) {
      if (a.redeem.network && a.redeem.network !== network)
        throw new TypeError('Network mismatch');
      if (a.input) {
        const redeem = _redeem();
        if (a.redeem.output && !a.redeem.output.equals(redeem.output!))
          throw new TypeError('Redeem.output mismatch');
        if (a.redeem.input && !a.redeem.input.equals(redeem.input!))
          throw new TypeError('Redeem.input mismatch');
      }

      checkRedeem(a.redeem);
    }

    if (a.witness) {
      if (
        a.redeem &&
        a.redeem.witness &&
        !stacksEqual(a.redeem.witness, a.witness)
      )
        throw new TypeError('Witness and redeem.witness mismatch');
    }

    if (a.confidentialAddress) {
      if (
        a.address &&
        a.address !== _confidentialAddress().unconfidentialAddress
      )
        throw new TypeError('Address mismatch');
      if (
        blindkey.length > 0 &&
        !blindkey.equals(_confidentialAddress().blindkey as Buffer)
      )
        throw new TypeError('Blindkey mismatch');
      else blindkey = _confidentialAddress().blindkey;
    }

    if (a.blindkey) {
      if (!isPoint(a.blindkey)) throw new TypeError('Blindkey is invalid');
      if (blindkey.length > 0 && !blindkey.equals(a.blindkey))
        throw new TypeError('Blindkey mismatch');
      else blindkey = a.blindkey;
    }
  }

  return Object.assign(o, a);
}
