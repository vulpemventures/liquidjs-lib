import * as crypto from './crypto';
import { Secp256k1Interface as ZKPInterface } from './secp256k1-zkp';
import { Output, ZERO } from './transaction';
import { ElementsValue } from './value';

export interface UnblindOutputResult {
  value: string;
  valueBlindingFactor: Buffer;
  asset: Buffer;
  assetBlindingFactor: Buffer;
}

export interface RangeProofInfoResult {
  ctExp: number;
  ctBits: number;
  minValue: number;
  maxValue: number;
}

export class Confidential {
  constructor(private zkp: ZKPInterface) {}

  nonceHash(pubkey: Buffer, privkey: Buffer): Buffer {
    return crypto.sha256(Buffer.from(this.zkp.ecdh(pubkey, privkey)));
  }

  valueBlindingFactor(
    inValues: string[],
    outValues: string[],
    inAssetBlinders: Buffer[],
    outAssetBlinders: Buffer[],
    inValueBlinders: Buffer[],
    outValueBlinders: Buffer[],
  ): Buffer {
    const values = inValues.concat(outValues);
    const nInputs = inValues.length;
    const assetBlinders = inAssetBlinders.concat(outAssetBlinders);
    const valueBlinders = inValueBlinders.concat(outValueBlinders);
    return Buffer.from(
      this.zkp.pedersen.blindGeneratorBlindSum(
        values,
        assetBlinders,
        valueBlinders,
        nInputs,
      ),
    );
  }

  valueCommitment(value: string, generator: Buffer, blinder: Buffer): Buffer {
    const { pedersen } = this.zkp;
    return Buffer.from(pedersen.commitment(value, generator, blinder));
  }

  assetCommitment(asset: Buffer, factor: Buffer): Buffer {
    const { generator } = this.zkp;
    return Buffer.from(generator.generateBlinded(asset, factor));
  }

  unblindOutputWithKey(
    out: Output,
    blindingPrivKey: Buffer,
  ): UnblindOutputResult {
    const nonce = this.nonceHash(out.nonce, blindingPrivKey);
    return this.unblindOutputWithNonce(out, nonce);
  }

  unblindOutputWithNonce(out: Output, nonce: Buffer): UnblindOutputResult {
    if (!out.rangeProof || out.rangeProof.length === 0) {
      throw new Error('Missing rangeproof to rewind');
    }
    const secp = this.zkp;
    const { value, blinder, message } = secp.rangeproof.rewind(
      out.rangeProof!,
      out.value,
      out.asset,
      nonce,
      out.script,
    );

    return {
      value,
      asset: Buffer.from(message.slice(0, 32)),
      valueBlindingFactor: Buffer.from(blinder),
      assetBlindingFactor: Buffer.from(message.slice(32)),
    };
  }

  rangeProofInfo(proof: Buffer): RangeProofInfoResult {
    const { rangeproof } = this.zkp;
    const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
    return {
      minValue: parseInt(minValue, 10),
      maxValue: parseInt(maxValue, 10),
      ctExp: parseInt(exp, 10),
      ctBits: parseInt(mantissa, 10),
    };
  }

  /**
   *  nonceHash from blinding key + ephemeral key and then rangeProof computation
   */
  rangeProofWithNonceHash(
    blindingPubkey: Buffer,
    ephemeralPrivkey: Buffer,
    value: string,
    asset: Buffer,
    valueCommitment: Buffer,
    assetCommitment: Buffer,
    valueBlinder: Buffer,
    assetBlinder: Buffer,
    scriptPubkey: Buffer,
    minValue?: string,
    exp?: string,
    minBits?: string,
  ): Buffer {
    const nonce = this.nonceHash(blindingPubkey, ephemeralPrivkey);
    return this.rangeProof(
      value,
      asset,
      valueCommitment,
      assetCommitment,
      valueBlinder,
      assetBlinder,
      nonce,
      scriptPubkey,
      minValue,
      exp,
      minBits,
    );
  }

  rangeProofVerify(
    proof: Buffer,
    valueCommitment: Buffer,
    assetCommitment: Buffer,
    script?: Buffer,
  ): boolean {
    const { rangeproof } = this.zkp;
    return rangeproof.verify(proof, valueCommitment, assetCommitment, script);
  }

  /**
   *  rangeProof computation without nonceHash step.
   */
  rangeProof(
    value: string,
    asset: Buffer,
    valueCommitment: Buffer,
    assetCommitment: Buffer,
    valueBlinder: Buffer,
    assetBlinder: Buffer,
    nonce: Buffer,
    scriptPubkey: Buffer,
    minValue: string = '1',
    exp: string = '0',
    minBits: string = '52',
  ): Buffer {
    const { rangeproof } = this.zkp;

    const message = Buffer.concat([asset, assetBlinder]);

    return Buffer.from(
      rangeproof.sign(
        value,
        valueCommitment,
        assetCommitment,
        valueBlinder,
        nonce,
        parseInt(value, 10) === 0 ? '0' : minValue,
        exp,
        minBits,
        message,
        scriptPubkey,
      ),
    );
  }

  surjectionProof(
    outputAsset: Buffer,
    outputAssetBlindingFactor: Buffer,
    inputAssets: Buffer[],
    inputAssetBlindingFactors: Buffer[],
    seed: Buffer,
  ): Buffer {
    const { generator, surjectionproof } = this.zkp;
    const outputGenerator = generator.generateBlinded(
      outputAsset,
      outputAssetBlindingFactor,
    );

    const inputGenerators = inputAssets.map((v, i) =>
      generator.generateBlinded(v, inputAssetBlindingFactors[i]),
    );
    const maxIterations = 100;

    const init = surjectionproof.initialize(
      inputAssets,
      outputAsset,
      maxIterations,
      seed,
    );

    return Buffer.from(
      surjectionproof.generate(
        init.proof,
        inputGenerators,
        outputGenerator,
        init.inputIndex,
        inputAssetBlindingFactors[init.inputIndex],
        outputAssetBlindingFactor,
      ),
    );
  }

  surjectionProofVerify(
    inAssets: Buffer[],
    inAssetBlinders: Buffer[],
    outAsset: Buffer,
    outAssetBlinder: Buffer,
    proof: Buffer,
  ): boolean {
    const { generator, surjectionproof } = this.zkp;
    const inGenerators = inAssets.map((v, i) =>
      generator.generateBlinded(v, inAssetBlinders[i]),
    );
    const outGenerator = generator.generateBlinded(outAsset, outAssetBlinder);
    return surjectionproof.verify(proof, inGenerators, outGenerator);
  }

  blindValueProof(
    value: string,
    valueCommitment: Buffer,
    assetCommitment: Buffer,
    valueBlinder: Buffer,
    nonce: Buffer,
  ): Buffer {
    const { rangeproof } = this.zkp;
    return Buffer.from(
      rangeproof.sign(
        value,
        valueCommitment,
        assetCommitment,
        valueBlinder,
        nonce,
        value,
        '-1',
      ),
    );
  }

  blindAssetProof(
    asset: Buffer,
    assetCommitment: Buffer,
    assetBlinder: Buffer,
  ): Buffer {
    const { generator, surjectionproof } = this.zkp;

    const maxIterations = 100;
    const gen = generator.generate(asset);
    const init = surjectionproof.initialize(
      [asset],
      asset,
      maxIterations,
      ZERO,
    );

    return Buffer.from(
      surjectionproof.generate(
        init.proof,
        [gen],
        assetCommitment,
        init.inputIndex,
        ZERO,
        assetBlinder,
      ),
    );
  }

  assetBlindProofVerify(
    asset: Buffer,
    assetCommitment: Buffer,
    proof: Buffer,
  ): boolean {
    const { generator, surjectionproof } = this.zkp;
    const inGenerators = [generator.generate(asset)];
    const outGenerator = assetCommitment;
    return surjectionproof.verify(proof, inGenerators, outGenerator);
  }
}

export function confidentialValueToSatoshi(value: Buffer): number {
  return ElementsValue.fromBytes(value).number;
}

export function satoshiToConfidentialValue(amount: number): Buffer {
  return ElementsValue.fromNumber(amount).bytes;
}
