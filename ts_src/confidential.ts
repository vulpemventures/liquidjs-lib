import * as crypto from './crypto';
import { Output, ZERO } from './transaction';
import secp256k1 from '@vulpemventures/secp256k1-zkp';
import {
  Pset,
  IssuanceBlindingArgs,
  OutputBlindingArgs,
  OwnedInput,
  PsetBlindingGenerator,
  PsetBlindingValidator,
} from './psetv2';
import { Slip77Interface, SLIP77Factory } from 'slip77';
import { ElementsValue } from './value';
import { ECPairFactory, TinySecp256k1Interface } from 'ecpair';
const _randomBytes = require('randombytes');
const ecc = require('tiny-secp256k1');

const secp256k1Promise = secp256k1();

async function nonceHash(pubkey: Buffer, privkey: Buffer): Promise<Buffer> {
  const { ecdh } = await secp256k1Promise;
  return crypto.sha256(ecdh(pubkey, privkey));
}

export async function valueBlindingFactor(
  inValues: string[],
  outValues: string[],
  inGenerators: Buffer[],
  outGenerators: Buffer[],
  inFactors: Buffer[],
  outFactors: Buffer[],
): Promise<Buffer> {
  const { pedersen } = await secp256k1Promise;
  const values = inValues.concat(outValues);
  const nInputs = inValues.length;
  const generators = inGenerators.concat(outGenerators);
  const factors = inFactors.concat(outFactors);
  return pedersen.blindGeneratorBlindSum(values, nInputs, generators, factors);
}

export async function valueCommitment(
  value: string,
  gen: Buffer,
  factor: Buffer,
): Promise<Buffer> {
  const { generator, pedersen } = await secp256k1Promise;
  const generatorParsed = generator.parse(gen);
  const commit = pedersen.commit(factor, value, generatorParsed);
  return pedersen.commitSerialize(commit);
}

export async function assetCommitment(
  asset: Buffer,
  factor: Buffer,
): Promise<Buffer> {
  const { generator } = await secp256k1Promise;
  const gen = generator.generateBlinded(asset, factor);
  return generator.serialize(gen);
}

export interface UnblindOutputResult {
  value: string;
  valueBlindingFactor: Buffer;
  asset: Buffer;
  assetBlindingFactor: Buffer;
}

export async function unblindOutputWithKey(
  out: Output,
  blindingPrivKey: Buffer,
): Promise<UnblindOutputResult> {
  const nonce = await nonceHash(out.nonce, blindingPrivKey);
  return unblindOutputWithNonce(out, nonce);
}

export async function unblindOutputWithNonce(
  out: Output,
  nonce: Buffer,
): Promise<UnblindOutputResult> {
  const secp = await secp256k1Promise;
  const gen = secp.generator.parse(out.asset);
  const { value, blindFactor, message } = secp.rangeproof.rewind(
    out.value,
    out.rangeProof!,
    nonce,
    gen,
    out.script,
  );

  return {
    value,
    asset: message.slice(0, 32),
    valueBlindingFactor: blindFactor,
    assetBlindingFactor: message.slice(32),
  };
}

export interface RangeProofInfoResult {
  ctExp: number;
  ctBits: number;
  minValue: number;
  maxValue: number;
}

export async function rangeProofInfo(
  proof: Buffer,
): Promise<RangeProofInfoResult> {
  const { rangeproof } = await secp256k1Promise;
  const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
  return {
    minValue: parseInt(minValue, 10),
    maxValue: parseInt(maxValue, 10),
    ctExp: exp,
    ctBits: parseInt(mantissa, 10),
  };
}

/**
 *  nonceHash from blinding key + ephemeral key and then rangeProof computation
 */
export async function rangeProofWithNonceHash(
  value: string,
  blindingPubkey: Buffer,
  ephemeralPrivkey: Buffer,
  asset: Buffer,
  assetBlindingFactor: Buffer,
  valueBlindFactor: Buffer,
  valueCommit: Buffer,
  scriptPubkey: Buffer,
  minValue?: string,
  exp?: number,
  minBits?: number,
): Promise<Buffer> {
  const nonce = await nonceHash(blindingPubkey, ephemeralPrivkey);
  return rangeProof(
    value,
    nonce,
    asset,
    assetBlindingFactor,
    valueBlindFactor,
    valueCommit,
    scriptPubkey,
    minValue,
    exp,
    minBits,
  );
}

export async function rangeProofVerify(
  valueCommit: Buffer,
  assetCommit: Buffer,
  proof: Buffer,
  script?: Buffer,
): Promise<boolean> {
  const { generator, pedersen, rangeproof } = await secp256k1Promise;
  const gen = generator.parse(assetCommit);
  const commit = pedersen.commitParse(valueCommit);
  return rangeproof.verify(commit, proof, gen, script);
}

/**
 *  rangeProof computation without nonceHash step.
 */
export async function rangeProof(
  value: string,
  nonce: Buffer,
  asset: Buffer,
  assetBlindingFactor: Buffer,
  valueBlindFactor: Buffer,
  valueCommit: Buffer,
  scriptPubkey: Buffer,
  minValue?: string,
  exp?: number,
  minBits?: number,
): Promise<Buffer> {
  const { generator, pedersen, rangeproof } = await secp256k1Promise;

  const gen = generator.generateBlinded(asset, assetBlindingFactor);
  const message = Buffer.concat([asset, assetBlindingFactor]);
  const commit = pedersen.commitParse(valueCommit);

  const mv = value === '0' ? '0' : minValue ? minValue : '1';
  const e = exp ? exp : 0;
  const mb = minBits ? minBits : 52;

  return rangeproof.sign(
    commit,
    valueBlindFactor,
    nonce,
    value,
    gen,
    mv,
    e,
    mb,
    message,
    scriptPubkey,
  );
}

export async function surjectionProof(
  outputAsset: Buffer,
  outputAssetBlindingFactor: Buffer,
  inputAssets: Buffer[],
  inputAssetBlindingFactors: Buffer[],
  seed: Buffer,
): Promise<Buffer> {
  const { generator, surjectionproof } = await secp256k1Promise;
  const outputGenerator = generator.generateBlinded(
    outputAsset,
    outputAssetBlindingFactor,
  );

  const inputGenerators = inputAssets.map((v, i) =>
    generator.generateBlinded(v, inputAssetBlindingFactors[i]),
  );
  const nInputsToUse = inputAssets.length > 3 ? 3 : inputAssets.length;
  const maxIterations = 100;

  const init = surjectionproof.initialize(
    inputAssets,
    nInputsToUse,
    outputAsset,
    maxIterations,
    seed,
  );

  const proof = surjectionproof.generate(
    init.proof,
    inputGenerators,
    outputGenerator,
    init.inputIndex,
    inputAssetBlindingFactors[init.inputIndex],
    outputAssetBlindingFactor,
  );

  return surjectionproof.serialize(proof);
}

export async function surjectionProofVerify(
  inAssets: Buffer[],
  inAssetBlinders: Buffer[],
  outAsset: Buffer,
  outAssetBlinder: Buffer,
  proof: Buffer,
): Promise<boolean> {
  const { generator, surjectionproof } = await secp256k1Promise;
  const inGenerators = inAssets.map((v, i) =>
    generator.generateBlinded(v, inAssetBlinders[i]),
  );
  const outGenerator = generator.generateBlinded(outAsset, outAssetBlinder);
  const sProof = surjectionproof.parse(proof);
  return surjectionproof.verify(sProof, inGenerators, outGenerator);
}

export async function blindValueProof(
  value: string,
  valueCommit: Buffer,
  assetCommit: Buffer,
  valueBlinder: Buffer,
  opts?: RngOpts,
): Promise<Buffer> {
  const { generator, pedersen, rangeproof } = await secp256k1Promise;

  const gen = generator.parse(assetCommit);
  const commit = pedersen.commitParse(valueCommit);
  const nonce = randomBytes(opts);

  return rangeproof.sign(commit, valueBlinder, nonce, value, gen, value, -1);
}

export async function blindAssetProof(
  asset: Buffer,
  assetCommit: Buffer,
  assetBlinder: Buffer,
): Promise<Buffer> {
  const { generator, surjectionproof } = await secp256k1Promise;

  const nInputsToUse = 1;
  const maxIterations = 100;

  const init = surjectionproof.initialize(
    [asset],
    nInputsToUse,
    asset,
    maxIterations,
    ZERO,
  );

  const gen = generator.generate(asset);
  const assetGen = generator.parse(assetCommit);

  const proof = surjectionproof.generate(
    init.proof,
    [gen],
    assetGen,
    init.inputIndex,
    ZERO,
    assetBlinder,
  );

  return surjectionproof.serialize(proof);
}

export async function assetBlindProofVerify(
  asset: Buffer,
  assetCommit: Buffer,
  proof: Buffer,
): Promise<boolean> {
  const { generator, surjectionproof } = await secp256k1Promise;
  const inGenerators = [generator.generate(asset)];
  const outGenerator = generator.parse(assetCommit);
  const sProof = surjectionproof.parse(proof);
  return surjectionproof.verify(sProof, inGenerators, outGenerator);
}

interface RngOpts {
  rng?(arg0: number): Buffer;
}

export type KeysGenerator = (
  opts?: RngOpts,
) => { publicKey: Buffer; privateKey: Buffer };

export class ZKPValidator implements PsetBlindingValidator {
  async verifyValueRangeProof(
    valueCommit: Buffer,
    assetCommit: Buffer,
    proof: Buffer,
    script: Buffer,
  ): Promise<boolean> {
    try {
      return await rangeProofVerify(valueCommit, assetCommit, proof, script);
    } catch (ignore) {
      return false;
    }
  }

  async verifyAssetSurjectionProof(
    inAssets: Buffer[],
    inAssetBlinders: Buffer[],
    outAsset: Buffer,
    outAssetBlinder: Buffer,
    proof: Buffer,
  ): Promise<boolean> {
    try {
      return await surjectionProofVerify(
        inAssets,
        inAssetBlinders,
        outAsset,
        outAssetBlinder,
        proof,
      );
    } catch (ignore) {
      return false;
    }
  }

  async verifyBlindValueProof(
    valueCommit: Buffer,
    assetCommit: Buffer,
    proof: Buffer,
  ): Promise<boolean> {
    try {
      return await rangeProofVerify(valueCommit, assetCommit, proof);
    } catch (ignore) {
      return false;
    }
  }

  async verifyBlindAssetProof(
    asset: Buffer,
    assetCommit: Buffer,
    proof: Buffer,
  ): Promise<boolean> {
    try {
      return await assetBlindProofVerify(asset, assetCommit, proof);
    } catch (ignore) {
      return false;
    }
  }
}

export class ZKPGenerator implements PsetBlindingGenerator {
  static fromOwnedInputs(ownedInputs: OwnedInput[]): ZKPGenerator {
    const bg = new ZKPGenerator();
    bg.ownedInputs = ownedInputs;
    return bg;
  }

  static fromInBlindingKeys(inBlindingKeys: Buffer[]): ZKPGenerator {
    const bg = new ZKPGenerator();
    bg.inBlindingKeys = inBlindingKeys;
    return bg;
  }

  static fromMasterBlindingKey(masterKey: Buffer): ZKPGenerator {
    const bg = new ZKPGenerator();
    bg.masterBlindingKey = SLIP77Factory(ecc).fromMasterBlindingKey(masterKey);
    return bg;
  }

  static ECCKeysGenerator(ec: TinySecp256k1Interface): KeysGenerator {
    return (opts?: RngOpts) => {
      const privateKey = randomBytes(opts);
      const publicKey = ECPairFactory(ec).fromPrivateKey(privateKey).publicKey;
      return {
        privateKey,
        publicKey,
      };
    };
  }

  ownedInputs?: OwnedInput[];
  inBlindingKeys?: Buffer[];
  masterBlindingKey?: Slip77Interface;
  opts?: RngOpts;

  private constructor() {}

  async computeAndAddToScalarOffset(
    scalar: Buffer,
    value: string,
    assetBlinder: Buffer,
    valueBlinder: Buffer,
  ): Promise<Buffer> {
    // If both asset and value blinders are null, 0 is added to the offset, so nothing actually happens
    if (assetBlinder.equals(ZERO) && valueBlinder.equals(ZERO)) {
      return scalar.slice();
    }

    const scalarOffset = await this.calculateScalarOffset(
      value,
      assetBlinder,
      valueBlinder,
    );

    // When we start out, the result (a) is 0, so just set it to the scalar we just computed.
    if (scalar.equals(ZERO)) {
      return scalarOffset;
    }

    const { ec } = await secp256k1Promise;
    const negScalarOffset = ec.prvkeyNegate(scalarOffset);

    if (scalar.equals(negScalarOffset)) {
      return ZERO;
    }

    return ec.prvkeyTweakAdd(scalar, scalarOffset);
  }

  async subtractScalars(
    inputScalar: Buffer,
    outputScalar: Buffer,
  ): Promise<Buffer> {
    if (outputScalar.equals(ZERO)) {
      return inputScalar.slice();
    }
    const { ec } = await secp256k1Promise;
    const negOutputScalar = ec.prvkeyNegate(outputScalar);
    if (inputScalar.equals(ZERO)) {
      return negOutputScalar;
    }
    return ec.prvkeyTweakAdd(inputScalar, negOutputScalar);
  }

  async lastValueCommitment(
    value: string,
    asset: Buffer,
    blinder: Buffer,
  ): Promise<Buffer> {
    return valueCommitment(value, asset, blinder);
  }

  async lastBlindValueProof(
    value: string,
    valueCommit: Buffer,
    assetCommit: Buffer,
    blinder: Buffer,
  ): Promise<Buffer> {
    return blindValueProof(value, valueCommit, assetCommit, blinder);
  }

  async lastValueRangeProof(
    value: string,
    asset: Buffer,
    valueCommit: Buffer,
    valueBlinder: Buffer,
    assetBlinder: Buffer,
    script: Buffer,
    nonce: Buffer,
  ): Promise<Buffer> {
    return rangeProof(
      value,
      nonce,
      asset,
      assetBlinder,
      valueBlinder,
      valueCommit,
      script,
    );
  }

  async unblindInputs(pset: Pset, inIndexes?: number[]): Promise<OwnedInput[]> {
    validatePset(pset);
    if (inIndexes!) {
      validateInIndexes(pset, inIndexes);
    }

    const inputIndexes =
      inIndexes || Array.from({ length: pset.globals.inputCount }, (_, i) => i);

    if (this.ownedInputs! && this.ownedInputs!.length > 0) {
      return this.ownedInputs!;
    }

    const revealedInputs = await Promise.all(
      inputIndexes.map(async i => {
        const prevout = pset.inputs[i].getUtxo();
        const revealedInput = await this.unblindUtxo(prevout!);
        revealedInput.index = i;
        return revealedInput;
      }),
    );
    this.ownedInputs = revealedInputs;
    return revealedInputs;
  }

  async blindIssuances(
    pset: Pset,
    blindingKeysByIndex: Record<number, Buffer>,
  ): Promise<IssuanceBlindingArgs[]> {
    validatePset(pset);
    validateBlindingKeysByIndex(pset, blindingKeysByIndex);

    return Promise.all(
      Object.entries(blindingKeysByIndex).map(async ([i, key]) => {
        const input = pset.inputs[parseInt(i, 10)];

        let blindingArgs = {} as IssuanceBlindingArgs;
        if (input.issuanceValue! > 0) {
          const value = input.issuanceValue!.toString(10);
          const asset = input.getIssuanceAssetHash()!;
          const blinder = randomBytes(this.opts);
          const assetCommit = await assetCommitment(asset, ZERO);
          const valueCommit = await valueCommitment(
            value,
            assetCommit,
            blinder,
          );
          const blindproof = await blindValueProof(
            value,
            valueCommit,
            assetCommit,
            blinder,
          );
          const rangeproof = await rangeProof(
            value,
            key,
            asset,
            ZERO,
            blinder,
            valueCommit,
            Buffer.from([]),
          );

          blindingArgs = {
            ...blindingArgs,
            index: parseInt(i, 10),
            issuanceAsset: asset,
            issuanceValueCommitment: valueCommit,
            issuanceValueRangeProof: rangeproof,
            issuanceValueBlindProof: blindproof,
            issuanceValueBlinder: blinder,
          };
        }

        if (input.issuanceInflationKeys! > 0) {
          const token = input.issuanceInflationKeys!.toString(10);
          const asset = input.getIssuanceInflationKeysHash(true)!;
          const blinder = randomBytes(this.opts);
          const assetCommit = await assetCommitment(asset, ZERO);
          const tokenCommit = await valueCommitment(
            token,
            assetCommit,
            blinder,
          );
          const blindproof = await blindValueProof(
            token,
            tokenCommit,
            assetCommit,
            blinder,
          );
          const rangeproof = await rangeProof(
            token,
            key,
            asset,
            ZERO,
            blinder,
            tokenCommit,
            Buffer.from([]),
          );

          blindingArgs = {
            ...blindingArgs,
            issuanceToken: asset,
            issuanceTokenCommitment: tokenCommit,
            issuanceTokenRangeProof: rangeproof,
            issuanceTokenBlindProof: blindproof,
            issuanceTokenBlinder: blinder,
          };
        }

        return blindingArgs;
      }),
    );
  }

  async blindOutputs(
    pset: Pset,
    keysGenerator: KeysGenerator,
    outIndexes?: number[],
    blindedIssuances?: IssuanceBlindingArgs[],
  ): Promise<OutputBlindingArgs[]> {
    validatePset(pset);
    if (outIndexes!) {
      validateOutIndexes(pset, outIndexes);
    }
    if (blindedIssuances! && blindedIssuances!.length > 0) {
      validateBlindedIssuances(pset, blindedIssuances);
    }

    const outputIndexes =
      outIndexes! && outIndexes.length > 0
        ? outIndexes
        : pset.outputs.reduce(
            (arr: number[], out, i) => (
              out.needsBlinding() && arr.push(i), arr
            ),
            [],
          );

    const { assets, assetBlinders } = await this.getInputAssetsAndBlinders(
      pset,
      blindedIssuances,
    );

    return Promise.all(
      outputIndexes.map(async i => {
        const output = pset.outputs[i];
        const assetBlinder = randomBytes(this.opts);
        const valueBlinder = randomBytes(this.opts);
        const seed = randomBytes(this.opts);
        const value = output.value!.toString(10);
        const assetCommit = await assetCommitment(output.asset!, assetBlinder);
        const valueCommit = await valueCommitment(
          value,
          assetCommit,
          valueBlinder,
        );
        const ephemeralKeyPair = keysGenerator();
        const nonceCommitment = ephemeralKeyPair.publicKey;
        const ecdhNonce = await nonceHash(
          output.blindingPubkey!,
          ephemeralKeyPair.privateKey,
        );
        const script = output.script || Buffer.from([]);
        const rangeproof = await rangeProof(
          value,
          ecdhNonce,
          output.asset!,
          assetBlinder,
          valueBlinder,
          valueCommit,
          script,
        );
        const surjectionproof = await surjectionProof(
          output.asset!,
          assetBlinder,
          assets,
          assetBlinders,
          seed,
        );
        const valueBlindProof = await blindValueProof(
          value,
          valueCommit,
          assetCommit,
          valueBlinder,
        );
        const assetBlindProof = await blindAssetProof(
          output.asset!,
          assetCommit,
          assetBlinder,
        );

        return {
          index: i,
          nonce: ecdhNonce,
          nonceCommitment,
          valueCommitment: valueCommit,
          assetCommitment: assetCommit,
          valueRangeProof: rangeproof,
          assetSurjectionProof: surjectionproof,
          valueBlindProof,
          assetBlindProof,
          valueBlinder,
          assetBlinder,
        };
      }),
    );
  }

  private async calculateScalarOffset(
    value: string,
    assetBlinder: Buffer,
    valueBlinder: Buffer,
  ): Promise<Buffer> {
    if (assetBlinder.equals(ZERO)) {
      return valueBlinder.slice();
    }
    if (value === '0') {
      return valueBlinder.slice();
    }

    const { ec } = await secp256k1Promise;
    const val = Buffer.alloc(32, 0);
    val.writeBigUInt64BE(BigInt(value), 24);
    const result = ec.prvkeyTweakMul(assetBlinder, val);
    if (valueBlinder.length === 0) {
      throw new Error('Missing value blinder');
    }

    const negVb = ec.prvkeyNegate(valueBlinder);

    if (negVb.equals(result)) {
      return ZERO;
    }

    return ec.prvkeyTweakAdd(result, valueBlinder);
  }

  private async unblindUtxo(out: Output): Promise<OwnedInput> {
    if (out.nonce.length === 1) {
      return {
        index: 0,
        value: ElementsValue.fromBytes(out.value).number.toString(10),
        asset: out.asset.slice(1),
        valueBlinder: ZERO,
        assetBlinder: ZERO,
      };
    }

    if (!this.inBlindingKeys && !this.masterBlindingKey) {
      throw new Error(
        'Missing either input private blinding keys or SLIP-77 master blinding key',
      );
    }

    const keys = this.inBlindingKeys
      ? this.inBlindingKeys
      : [this.masterBlindingKey!.derive(out.script).privateKey!];

    for (const key of keys) {
      try {
        const revealed = await unblindOutputWithKey(out, key);
        return {
          index: 0,
          value: revealed.value,
          asset: revealed.asset,
          valueBlinder: revealed.valueBlindingFactor,
          assetBlinder: revealed.assetBlindingFactor,
        };
      } catch (ignore) {}
    }

    throw new Error('Could not unblind output with any blinding key');
  }

  private async getInputAssetsAndBlinders(
    pset: Pset,
    issuanceBlindingArgs?: IssuanceBlindingArgs[],
  ): Promise<{
    assets: Buffer[];
    assetBlinders: Buffer[];
  }> {
    const unblindedIns = await this.maybeUnblindInUtxos(pset);
    pset.inputs.forEach((input, i) => {
      if (input.hasIssuance()) {
        unblindedIns.push({
          value: '',
          valueBlindingFactor: Buffer.from([]),
          asset: input.getIssuanceAssetHash()!,
          assetBlindingFactor: ZERO,
        });
        if (input.issuanceInflationKeys! > 0) {
          const isBlindedIssuance =
            issuanceBlindingArgs! &&
            issuanceBlindingArgs.find(({ index }) => index === i) !== undefined;
          unblindedIns.push({
            value: '',
            valueBlindingFactor: Buffer.from([]),
            asset: input.getIssuanceInflationKeysHash(isBlindedIssuance)!,
            assetBlindingFactor: ZERO,
          });
        }
      }
    });

    const assets = [] as Buffer[];
    const assetBlinders = [] as Buffer[];

    unblindedIns.forEach(({ asset, assetBlindingFactor }) => {
      assets.push(asset);
      assetBlinders.push(assetBlindingFactor);
    });

    return { assets, assetBlinders };
  }

  private async maybeUnblindInUtxos(
    pset: Pset,
  ): Promise<UnblindOutputResult[]> {
    if (this.ownedInputs! && this.ownedInputs!.length > 0) {
      return pset.inputs.map((input, i) => {
        const ownedInput = this.ownedInputs!.find(({ index }) => index === i);
        if (ownedInput!) {
          return {
            value: '',
            valueBlindingFactor: Buffer.from([]),
            asset: ownedInput!.asset,
            assetBlindingFactor: ownedInput!.assetBlinder,
          };
        }
        return {
          value: '',
          valueBlindingFactor: Buffer.from([]),
          asset: input.getUtxo()!.asset,
          assetBlindingFactor: ZERO,
        };
      });
    }

    if (!this.inBlindingKeys && !this.masterBlindingKey) {
      throw new Error(
        'Missing either input private blinding keys or SLIP-77 master blinding key',
      );
    }

    return Promise.all(
      pset.inputs.map(async input => {
        const prevout = input.getUtxo()!;
        try {
          const revealed = await this.unblindUtxo(prevout);
          return {
            value: revealed.value,
            asset: revealed.asset,
            valueBlindingFactor: revealed.valueBlinder,
            assetBlindingFactor: revealed.assetBlinder,
          };
        } catch (ignore) {
          return {
            value: '',
            asset: prevout.asset,
            valueBlindingFactor: Buffer.from([]),
            assetBlindingFactor: ZERO,
          };
        }
      }),
    );
  }
}

function validatePset(pset: Pset): void {
  pset.sanityCheck();

  pset.inputs.forEach((input, i) => {
    if (!input.getUtxo()) {
      throw new Error('Missing (non-)witness utxo for input ' + i);
    }
  });
}

function validateInIndexes(pset: Pset, inIndexes: number[]): void {
  if (inIndexes.length > 0) {
    inIndexes.forEach(i => {
      if (i < 0 || i >= pset.globals.inputCount) {
        throw new Error('Input index out of range');
      }
    });
  }
}

function validateOutIndexes(pset: Pset, outIndexes: number[]): void {
  if (outIndexes.length > 0) {
    outIndexes.forEach(i => {
      if (i < 0 || i >= pset.globals.outputCount) {
        throw new Error('Output index out of range');
      }
    });
  }
}

function validateBlindingKeysByIndex(
  pset: Pset,
  keys: Record<number, Buffer>,
): void {
  Object.entries(keys).forEach(([k, v]) => {
    const i = parseInt(k, 10);
    if (i < 0 || i >= pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    if (!pset.inputs[i].hasIssuance()) {
      throw new Error('Input does not have any issuance to blind');
    }
    if (v.length !== 32) {
      throw new Error('Invalid private blinding key length for input ' + i);
    }
  });
}

function validateBlindedIssuances(
  pset: Pset,
  blindedIssuances: IssuanceBlindingArgs[],
): void {
  if (blindedIssuances.length > 0) {
    blindedIssuances.forEach(issuance => {
      if (issuance.index < 0 || issuance.index >= pset.globals.inputCount) {
        throw new Error('Input index of blinded issuance is out of range');
      }
    });
  }
}

function randomBytes(options?: RngOpts): Buffer {
  if (options === undefined) options = {};
  const rng = options.rng || _randomBytes;
  return rng(32);
}
