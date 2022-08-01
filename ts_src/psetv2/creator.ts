import { Global } from './globals';
import { Pset } from './pset';
import { Input as PsetInput } from './input';
import { Output as PsetOutput } from './output';
import { reverseBuffer } from '../bufferutils';
import { fromConfidential, isConfidential, toOutputScript } from '../address';
import { AssetHash } from '../asset';
import { Transaction } from '../transaction';
import { OPS } from '../ops';
import BitSet from 'bitset';

export class Input {
  txid: string;
  txIndex: number;
  sequence: number;
  heightLocktime: number;
  timeLocktime: number;

  constructor(
    txid: string,
    txIndex: number,
    sequence?: number,
    heightLocktime?: number,
    timeLocktime?: number,
  ) {
    this.txid = txid;
    this.txIndex = txIndex;
    this.sequence = sequence || Transaction.DEFAULT_SEQUENCE;
    this.heightLocktime = heightLocktime || 0;
    this.timeLocktime = timeLocktime || 0;
  }

  validate(): void {
    if (this.txid.length === 0) {
      throw new Error('missing prevout txid');
    }
    if (this.txid.length !== 64) {
      throw new Error('invalid prevout txid length');
    }
    if (this.txIndex < 0) {
      throw new Error('missing prevout tx index');
    }
  }

  toPartialInput(): PsetInput {
    const prevTxid = reverseBuffer(Buffer.from(this.txid, 'hex'));
    const input = new PsetInput(prevTxid, this.txIndex, this.sequence);
    input.requiredHeightLocktime = this.heightLocktime;
    input.requiredTimeLocktime = this.timeLocktime;
    return input;
  }
}

export class Output {
  asset: string;
  amount: number;
  address?: string;
  blinderIndex?: number;

  constructor(
    asset: string,
    amount: number,
    address?: string,
    blinderIndex?: number,
  ) {
    this.asset = asset;
    this.amount = amount;
    this.address = address;
    this.blinderIndex = blinderIndex;
  }

  validate(): void {
    if (this.asset.length === 0) {
      throw new Error('missing asset');
    }
    if (Buffer.from(this.asset, 'hex').length !== 32) {
      throw new Error('invalid asset length');
    }
    if (
      this.address! &&
      isConfidential(this.address!) &&
      (this.blinderIndex === undefined || this.blinderIndex! < 0)
    ) {
      throw new Error('missing blinder index for confidential output');
    }
  }

  toPartialOutput(): PsetOutput {
    let script = Buffer.from([]);
    if (this.address! && this.address!.length > 0) {
      script =
        this.amount > 0
          ? toOutputScript(this.address)
          : Buffer.of(OPS.OP_RETURN);
    }
    const asset = AssetHash.fromHex(this.asset);
    const output = new PsetOutput(
      this.amount,
      asset.bytesWithoutPrefix,
      script,
    );
    if (this.address! && isConfidential(this.address!)) {
      const { blindingKey } = fromConfidential(this.address!);
      output.blinderIndex = this.blinderIndex!;
      output.blindingPubkey = blindingKey;
    }
    return output;
  }
}

export class Creator {
  static newPset(args: {
    inputs?: Input[];
    outputs?: Output[];
    locktime?: number;
  }): Pset {
    const txModifiable = new BitSet(0);
    txModifiable.set(0);
    txModifiable.set(1);

    const globals = new Global(2, 0, 0, 2);
    globals.txModifiable = txModifiable;
    globals.xpubs = [];
    globals.scalars = [];
    globals.proprietaryData = [];
    globals.unknowns = [];

    const pset = new Pset(globals);

    args.inputs! &&
      args.inputs!.forEach(input => {
        input.validate();
        pset.addInput(input.toPartialInput());
      });

    args.outputs! &&
      args.outputs!.forEach(output => {
        output.validate();
        pset.addOutput(output.toPartialOutput());
      });

    return pset;
  }
}
