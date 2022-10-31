import {
  Confidential,
  UnblindOutputResult,
  ZKPInterface,
} from '../confidential';
import { Output, ZERO } from '../transaction';
import { ElementsValue } from '../value';
import { randomBytes } from './utils';
import type { Slip77Interface } from 'slip77';
import type { RngOpts } from './interfaces';
import type { KeysGenerator, Pset } from './pset';
import type {
  IssuanceBlindingArgs,
  OutputBlindingArgs,
  OwnedInput,
} from './blinder';

export class ZKPValidator {
  private confidential: Confidential;

  constructor(zkpLib: ZKPInterface) {
    this.confidential = new Confidential(zkpLib);
  }

  verifyValueRangeProof(
    valueCommit: Buffer,
    assetCommit: Buffer,
    proof: Buffer,
    script: Buffer,
  ): boolean {
    try {
      return this.confidential.rangeProofVerify(
        valueCommit,
        assetCommit,
        proof,
        script,
      );
    } catch (ignore) {
      return false;
    }
  }

  verifyAssetSurjectionProof(
    inAssets: Buffer[],
    inAssetBlinders: Buffer[],
    outAsset: Buffer,
    outAssetBlinder: Buffer,
    proof: Buffer,
  ): boolean {
    try {
      return this.confidential.surjectionProofVerify(
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

  verifyBlindValueProof(
    valueCommit: Buffer,
    assetCommit: Buffer,
    proof: Buffer,
  ): boolean {
    try {
      return this.confidential.rangeProofVerify(
        valueCommit,
        assetCommit,
        proof,
      );
    } catch (ignore) {
      return false;
    }
  }

  verifyBlindAssetProof(
    asset: Buffer,
    assetCommit: Buffer,
    proof: Buffer,
  ): boolean {
    try {
      return this.confidential.assetBlindProofVerify(asset, assetCommit, proof);
    } catch (ignore) {
      return false;
    }
  }
}

type ZKPGeneratorOption = (g: ZKPGenerator) => void;
export class ZKPGenerator {
  private ownedInputs?: OwnedInput[];
  private inBlindingKeys?: Buffer[];
  private masterBlindingKey?: Slip77Interface;
  private opts?: RngOpts;
  private confidential: Confidential;

  constructor(private zkp: ZKPInterface, ...options: ZKPGeneratorOption[]) {
    this.confidential = new Confidential(zkp);
    for (const option of options) {
      option(this);
    }
  }

  static WithBlindingKeysOfInputs(
    inBlindingKeys: Buffer[],
  ): ZKPGeneratorOption {
    return (g: ZKPGenerator): void => {
      g.inBlindingKeys = inBlindingKeys;
    };
  }

  static WithMasterBlindingKey(masterKey: Slip77Interface): ZKPGeneratorOption {
    return (g: ZKPGenerator): void => {
      g.masterBlindingKey = masterKey;
    };
  }

  static WithOwnedInputs(ownedInputs: OwnedInput[]): ZKPGeneratorOption {
    return (g: ZKPGenerator): void => {
      g.ownedInputs = ownedInputs;
    };
  }

  computeAndAddToScalarOffset(
    scalar: Buffer,
    value: string,
    assetBlinder: Buffer,
    valueBlinder: Buffer,
  ): Buffer {
    // If both asset and value blinders are null, 0 is added to the offset, so nothing actually happens
    if (assetBlinder.equals(ZERO) && valueBlinder.equals(ZERO)) {
      return scalar.slice();
    }

    const scalarOffset = this.calculateScalarOffset(
      value,
      assetBlinder,
      valueBlinder,
    );

    // When we start out, the result (a) is 0, so just set it to the scalar we just computed.
    if (scalar.equals(ZERO)) {
      return scalarOffset;
    }

    const { ec } = this.zkp;
    const negScalarOffset = ec.prvkeyNegate(scalarOffset);

    if (scalar.equals(negScalarOffset)) {
      return ZERO;
    }

    return ec.prvkeyTweakAdd(scalar, scalarOffset);
  }

  subtractScalars(inputScalar: Buffer, outputScalar: Buffer): Buffer {
    if (outputScalar.equals(ZERO)) {
      return inputScalar.slice();
    }
    const { ec } = this.zkp;
    const negOutputScalar = ec.prvkeyNegate(outputScalar);
    if (inputScalar.equals(ZERO)) {
      return negOutputScalar;
    }
    return ec.prvkeyTweakAdd(inputScalar, negOutputScalar);
  }

  lastValueCommitment(value: string, asset: Buffer, blinder: Buffer): Buffer {
    return this.confidential.valueCommitment(value, asset, blinder);
  }

  lastBlindValueProof(
    value: string,
    valueCommit: Buffer,
    assetCommit: Buffer,
    blinder: Buffer,
  ): Buffer {
    const nonce = randomBytes(this.opts);
    return this.confidential.blindValueProof(
      value,
      valueCommit,
      assetCommit,
      blinder,
      nonce,
    );
  }

  lastValueRangeProof(
    value: string,
    asset: Buffer,
    valueCommit: Buffer,
    valueBlinder: Buffer,
    assetBlinder: Buffer,
    script: Buffer,
    nonce: Buffer,
  ): Buffer {
    return this.confidential.rangeProof(
      value,
      nonce,
      asset,
      assetBlinder,
      valueBlinder,
      valueCommit,
      script,
    );
  }

  unblindInputs(pset: Pset, inIndexes?: number[]): OwnedInput[] {
    validatePset(pset);
    if (inIndexes) {
      validateInIndexes(pset, inIndexes);
    }

    const inputIndexes =
      inIndexes || Array.from({ length: pset.globals.inputCount }, (_, i) => i);

    if (this.ownedInputs && this.ownedInputs.length > 0) {
      return this.ownedInputs;
    }

    const revealedInputs = inputIndexes.map((i) => {
      const prevout = pset.inputs[i].getUtxo();
      const revealedInput = this.unblindUtxo(prevout!);
      revealedInput.index = i;
      return revealedInput;
    });
    this.ownedInputs = revealedInputs;
    return revealedInputs;
  }

  blindIssuances(
    pset: Pset,
    blindingKeysByIndex: Record<number, Buffer>,
  ): IssuanceBlindingArgs[] {
    validatePset(pset);
    validateBlindingKeysByIndex(pset, blindingKeysByIndex);

    return Object.entries(blindingKeysByIndex).map(([i, key]) => {
      const input = pset.inputs[parseInt(i, 10)];

      let blindingArgs = {} as IssuanceBlindingArgs;
      if (input.issuanceValue! > 0) {
        const value = input.issuanceValue!.toString(10);
        const asset = input.getIssuanceAssetHash()!;
        const blinder = randomBytes(this.opts);

        const assetCommit = this.confidential.assetCommitment(asset, ZERO);
        const valueCommit = this.confidential.valueCommitment(
          value,
          assetCommit,
          blinder,
        );
        const nonce = randomBytes(this.opts);
        const blindproof = this.confidential.blindValueProof(
          value,
          valueCommit,
          assetCommit,
          blinder,
          nonce,
        );
        const rangeproof = this.confidential.rangeProof(
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
        const assetCommit = this.confidential.assetCommitment(asset, ZERO);
        const tokenCommit = this.confidential.valueCommitment(
          token,
          assetCommit,
          blinder,
        );
        const nonce = randomBytes(this.opts);
        const blindproof = this.confidential.blindValueProof(
          token,
          tokenCommit,
          assetCommit,
          blinder,
          nonce,
        );
        const rangeproof = this.confidential.rangeProof(
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
    });
  }

  blindOutputs(
    pset: Pset,
    keysGenerator: KeysGenerator,
    outIndexes?: number[],
  ): OutputBlindingArgs[] {
    validatePset(pset);
    if (outIndexes) {
      validateOutIndexes(pset, outIndexes);
    }

    const outputIndexes =
      outIndexes && outIndexes.length > 0
        ? outIndexes
        : pset.outputs.reduce(
            (arr: number[], out, i) => (
              out.needsBlinding() && arr.push(i), arr
            ),
            [],
          );

    const { assets, assetBlinders } = this.getInputAssetsAndBlinders(pset);

    return outputIndexes.map((i) => {
      const output = pset.outputs[i];
      const assetBlinder = randomBytes(this.opts);
      const valueBlinder = randomBytes(this.opts);
      const seed = randomBytes(this.opts);
      const value = output.value!.toString(10);
      const assetCommit = this.confidential.assetCommitment(
        output.asset!,
        assetBlinder,
      );
      const valueCommit = this.confidential.valueCommitment(
        value,
        assetCommit,
        valueBlinder,
      );
      const ephemeralKeyPair = keysGenerator();
      const nonceCommitment = ephemeralKeyPair.publicKey;
      const ecdhNonce = this.confidential.nonceHash(
        output.blindingPubkey!,
        ephemeralKeyPair.privateKey,
      );
      const script = output.script || Buffer.from([]);
      const rangeproof = this.confidential.rangeProof(
        value,
        ecdhNonce,
        output.asset!,
        assetBlinder,
        valueBlinder,
        valueCommit,
        script,
      );
      const surjectionproof = this.confidential.surjectionProof(
        output.asset!,
        assetBlinder,
        assets,
        assetBlinders,
        seed,
      );
      const nonce = randomBytes(this.opts);
      const valueBlindProof = this.confidential.blindValueProof(
        value,
        valueCommit,
        assetCommit,
        valueBlinder,
        nonce,
      );
      const assetBlindProof = this.confidential.blindAssetProof(
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
    });
  }

  private calculateScalarOffset(
    value: string,
    assetBlinder: Buffer,
    valueBlinder: Buffer,
  ): Buffer {
    if (assetBlinder.equals(ZERO)) {
      return valueBlinder.slice();
    }
    if (value === '0') {
      return valueBlinder.slice();
    }

    const { ec } = this.zkp;
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

  private unblindUtxo(out: Output): OwnedInput {
    if (out.nonce.length === 1) {
      return {
        index: 0,
        value: ElementsValue.fromBytes(out.value).number.toString(10),
        asset: out.asset.slice(1),
        valueBlindingFactor: ZERO,
        assetBlindingFactor: ZERO,
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
        const revealed = this.confidential.unblindOutputWithKey(out, key);
        return {
          index: 0,
          value: revealed.value,
          asset: revealed.asset,
          valueBlindingFactor: revealed.valueBlindingFactor,
          assetBlindingFactor: revealed.assetBlindingFactor,
        };
      } catch (ignore) {}
    }

    throw new Error('Could not unblind output with any blinding key');
  }

  private getInputAssetsAndBlinders(pset: Pset): {
    assets: Buffer[];
    assetBlinders: Buffer[];
  } {
    const assets: Buffer[] = [];
    const assetBlinders: Buffer[] = [];

    const unblindedIns = this.maybeUnblindInUtxos(pset);

    for (const unblindedIn of unblindedIns) {
      assets.push(unblindedIn.asset);
      assetBlinders.push(unblindedIn.assetBlindingFactor);
    }

    pset.inputs.forEach((input, i) => {
      if (input.hasIssuance() || input.hasReissuance()) {
        const issAssetHash = input.getIssuanceAssetHash();
        if (!issAssetHash)
          throw new Error(
            `something went wrong while getting the issuance asset hash on input #${i}`,
          );

        assets.push(issAssetHash);
        assetBlinders.push(ZERO);

        if (!input.hasReissuance() && input.issuanceInflationKeys! > 0) {
          const blindedIssuance = input.blindedIssuance;
          if (blindedIssuance === undefined)
            throw new Error(`input #${i} is missing blindedIssuance field`);

          const inflationTokenAssetHash =
            input.getIssuanceInflationKeysHash(blindedIssuance);
          if (!inflationTokenAssetHash)
            throw new Error(
              `something went wrong computing the issuance inflation keys hash on input #${i}`,
            );

          assets.push(inflationTokenAssetHash);
          assetBlinders.push(ZERO);
        }
      }
    });

    return { assets, assetBlinders };
  }

  private maybeUnblindInUtxos(pset: Pset): UnblindOutputResult[] {
    if (this.ownedInputs! && this.ownedInputs!.length > 0) {
      return pset.inputs.map((input, i) => {
        const ownedInput = this.ownedInputs!.find(({ index }) => index === i);
        if (ownedInput!) {
          return {
            value: '',
            valueBlindingFactor: Buffer.from([]),
            asset: ownedInput!.asset,
            assetBlindingFactor: ownedInput!.assetBlindingFactor,
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

    return pset.inputs.map((input) => {
      const prevout = input.getUtxo()!;
      try {
        const revealed = this.unblindUtxo(prevout);
        return {
          value: revealed.value,
          asset: revealed.asset,
          valueBlindingFactor: revealed.valueBlindingFactor,
          assetBlindingFactor: revealed.assetBlindingFactor,
        };
      } catch (ignore) {
        return {
          value: '',
          asset: prevout.asset,
          valueBlindingFactor: Buffer.from([]),
          assetBlindingFactor: ZERO,
        };
      }
    });
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
    inIndexes.forEach((i) => {
      if (i < 0 || i >= pset.globals.inputCount) {
        throw new Error('Input index out of range');
      }
    });
  }
}

function validateOutIndexes(pset: Pset, outIndexes: number[]): void {
  if (outIndexes.length > 0) {
    outIndexes.forEach((i) => {
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
    if (!pset.inputs[i].hasIssuance() && !pset.inputs[i].hasReissuance()) {
      throw new Error(
        'Input does not have any issuance or reissuance to blind',
      );
    }
    if (v.length !== 32) {
      throw new Error('Invalid private blinding key length for input ' + i);
    }
  });
}
