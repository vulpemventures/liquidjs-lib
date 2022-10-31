import { UnblindOutputResult } from '../confidential';
import { ZERO } from '../transaction';
import { Pset } from './pset';
import { ZKPGenerator, ZKPValidator } from './zkp';

export interface IssuanceBlindingArgs {
  index: number;
  issuanceAsset: Buffer;
  issuanceToken: Buffer;
  issuanceValueCommitment: Buffer;
  issuanceTokenCommitment: Buffer;
  issuanceValueRangeProof: Buffer;
  issuanceTokenRangeProof: Buffer;
  issuanceValueBlindProof: Buffer;
  issuanceTokenBlindProof: Buffer;
  issuanceValueBlinder: Buffer;
  issuanceTokenBlinder: Buffer;
}

export interface OutputBlindingArgs {
  index: number;
  nonce: Buffer;
  nonceCommitment: Buffer;
  valueCommitment: Buffer;
  assetCommitment: Buffer;
  valueRangeProof: Buffer;
  assetSurjectionProof: Buffer;
  valueBlindProof: Buffer;
  assetBlindProof: Buffer;
  valueBlinder: Buffer;
  assetBlinder: Buffer;
}

export type OwnedInput = { index: number } & UnblindOutputResult;

export class Blinder {
  pset: Pset;
  ownedInputs: OwnedInput[];
  blindingValidator: ZKPValidator;
  blindingGenerator: ZKPGenerator;

  constructor(
    pset: Pset,
    ownedInputs: OwnedInput[],
    validator: ZKPValidator,
    generator: ZKPGenerator,
  ) {
    if (ownedInputs.length === 0) {
      throw new Error('Missing owned inputs');
    }
    pset.sanityCheck();
    this.pset = pset;
    this.ownedInputs = ownedInputs;
    this.blindingValidator = validator;
    this.blindingGenerator = generator;
  }

  blindNonLast(args: {
    issuanceBlindingArgs?: IssuanceBlindingArgs[];
    outputBlindingArgs: OutputBlindingArgs[];
  }): void {
    this.blind(args, false);
  }

  blindLast(args: {
    issuanceBlindingArgs?: IssuanceBlindingArgs[];
    outputBlindingArgs: OutputBlindingArgs[];
  }): void {
    this.blind(args, true);
  }

  private blind(
    args: {
      issuanceBlindingArgs?: IssuanceBlindingArgs[];
      outputBlindingArgs: OutputBlindingArgs[];
    },
    lastBlinder: boolean,
  ): void {
    if (this.pset.isFullyBlinded()) {
      return;
    }

    const { issuanceBlindingArgs, outputBlindingArgs } = args;
    if (outputBlindingArgs.length === 0) {
      throw new Error('missing outputs blinding args');
    }

    if (issuanceBlindingArgs! && issuanceBlindingArgs!.length > 0) {
      issuanceBlindingArgs.forEach((arg) =>
        this.validateIssuanceBlindingArgs(arg),
      );
    }

    const sortedOutputBlindingArgs = outputBlindingArgs.sort(
      (a, b) => a.index - b.index,
    );
    sortedOutputBlindingArgs.forEach((arg, i) => {
      const isLastBlinder =
        lastBlinder && i === sortedOutputBlindingArgs.length - 1;
      this.validateOutputBlindingArgs(arg, isLastBlinder);
    });

    this.validateBlindingData(
      lastBlinder,
      outputBlindingArgs,
      issuanceBlindingArgs,
    );

    const inputScalar = this.calculateInputScalar(issuanceBlindingArgs);
    const outputScalar = this.calculateOutputScalar(sortedOutputBlindingArgs);

    const pset = this.pset.copy();

    if (issuanceBlindingArgs!) {
      issuanceBlindingArgs.forEach(
        ({
          index,
          issuanceValueCommitment,
          issuanceValueRangeProof,
          issuanceValueBlindProof,
          issuanceTokenCommitment,
          issuanceTokenRangeProof,
          issuanceTokenBlindProof,
        }) => {
          pset.inputs[index].issuanceValueCommitment = issuanceValueCommitment;
          pset.inputs[index].issuanceValueRangeproof = issuanceValueRangeProof;
          pset.inputs[index].issuanceBlindValueProof = issuanceValueBlindProof;
          pset.inputs[index].issuanceInflationKeysCommitment =
            issuanceTokenCommitment;
          pset.inputs[index].issuanceInflationKeysRangeproof =
            issuanceTokenRangeProof;
          pset.inputs[index].issuanceBlindInflationKeysProof =
            issuanceTokenBlindProof;
        },
      );
    }

    for (let i = 0; i < sortedOutputBlindingArgs.length; i++) {
      const {
        index,
        assetBlinder,
        assetCommitment,
        assetSurjectionProof,
        assetBlindProof,
        valueBlinder,
        nonceCommitment,
        nonce,
      } = sortedOutputBlindingArgs[i];
      let { valueCommitment, valueRangeProof, valueBlindProof } =
        sortedOutputBlindingArgs[i];
      const targetOutput = pset.outputs[index];
      const value = targetOutput.value.toString(10);
      if (lastBlinder && i === sortedOutputBlindingArgs.length - 1) {
        const lastValueBlinder = this.calculateLastValueBlinder(
          valueBlinder,
          outputScalar,
          inputScalar,
        );

        valueCommitment = this.blindingGenerator.lastValueCommitment(
          value,
          assetCommitment,
          lastValueBlinder,
        );
        valueRangeProof = this.blindingGenerator.lastValueRangeProof(
          value,
          targetOutput.asset!,
          valueCommitment,
          lastValueBlinder,
          assetBlinder,
          targetOutput.script! || Buffer.alloc(0),
          nonce,
        );
        valueBlindProof = this.blindingGenerator.lastBlindValueProof(
          value,
          valueCommitment,
          assetCommitment,
          lastValueBlinder,
        );
      }

      pset.outputs[index].valueCommitment = valueCommitment;
      pset.outputs[index].valueRangeproof = valueRangeProof;
      pset.outputs[index].blindValueProof = valueBlindProof;
      pset.outputs[index].assetCommitment = assetCommitment;
      pset.outputs[index].assetSurjectionProof = assetSurjectionProof;
      pset.outputs[index].blindAssetProof = assetBlindProof;
      pset.outputs[index].ecdhPubkey = nonceCommitment;
      pset.outputs[index].blinderIndex = undefined;
    }

    if (!lastBlinder) {
      if (!pset.globals.scalars) {
        pset.globals.scalars = [];
      }
      pset.globals.scalars!.push(outputScalar);
    } else {
      pset.globals.scalars = undefined;
    }

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  private calculateInputScalar(
    issuanceBlindingArgs?: IssuanceBlindingArgs[],
  ): Buffer {
    let scalar = Buffer.from(ZERO);
    for (const input of this.ownedInputs) {
      scalar = this.blindingGenerator.computeAndAddToScalarOffset(
        scalar,
        input.value,
        input.assetBlindingFactor,
        input.valueBlindingFactor,
      );

      const pInput = this.pset.inputs[input.index];
      if (pInput.hasIssuance() || pInput.hasReissuance()) {
        const issuance =
          issuanceBlindingArgs! &&
          issuanceBlindingArgs.find(({ index }) => index === input.index);
        if (issuance!) {
          const valueBlinder =
            issuance.issuanceValueBlinder! &&
            issuance.issuanceValueBlinder!.length > 0
              ? issuance.issuanceValueBlinder!
              : ZERO;
          scalar = this.blindingGenerator.computeAndAddToScalarOffset(
            scalar,
            pInput.issuanceValue ? pInput.issuanceValue!.toString(10) : '0',
            ZERO,
            valueBlinder,
          );
          if (pInput.issuanceInflationKeys! > 0) {
            const tokenBlinder =
              issuance.issuanceTokenBlinder! &&
              issuance.issuanceTokenBlinder!.length > 0
                ? issuance.issuanceTokenBlinder!
                : ZERO;
            scalar = this.blindingGenerator.computeAndAddToScalarOffset(
              scalar,
              pInput.issuanceInflationKeys!.toString(10),
              ZERO,
              tokenBlinder,
            );
          }
        }
      }
    }
    return scalar;
  }

  private calculateOutputScalar(
    outputBlindingArgs: OutputBlindingArgs[],
  ): Buffer {
    let scalar = Buffer.from(ZERO);
    for (const args of outputBlindingArgs) {
      const output = this.pset.outputs[args.index];
      scalar = this.blindingGenerator.computeAndAddToScalarOffset(
        scalar,
        output.value.toString(10),
        args.assetBlinder,
        args.valueBlinder,
      );
    }
    return scalar;
  }

  private calculateLastValueBlinder(
    valueBlinder: Buffer,
    outputScalar: Buffer,
    inputScalar: Buffer,
  ): Buffer {
    const offset = this.blindingGenerator.subtractScalars(
      outputScalar,
      inputScalar,
    );
    let lastValueBlinder = this.blindingGenerator.subtractScalars(
      valueBlinder,
      offset,
    );
    if (this.pset.globals.scalars!) {
      for (const scalar of this.pset.globals.scalars!) {
        lastValueBlinder = this.blindingGenerator.subtractScalars(
          lastValueBlinder,
          scalar,
        );
      }
    }
    return lastValueBlinder;
  }

  private validateIssuanceBlindingArgs(args: IssuanceBlindingArgs): void {
    const {
      index,
      issuanceAsset,
      issuanceToken,
      issuanceValueCommitment,
      issuanceTokenCommitment,
      issuanceValueRangeProof,
      issuanceTokenRangeProof,
      issuanceValueBlindProof,
      issuanceTokenBlindProof,
      issuanceValueBlinder,
      issuanceTokenBlinder,
    } = args;
    if (index < 0 || index >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }

    const targetInput = this.pset.inputs[index];
    if (!targetInput.hasIssuance() && !targetInput.hasReissuance()) {
      throw new Error('Missing issuance on target input');
    }
    if (issuanceAsset.length === 0) {
      throw new Error('Missing issuance asset');
    }
    if (issuanceAsset.length !== 32) {
      throw new Error('Invalid issuance asset length');
    }
    if (issuanceValueCommitment.length === 0) {
      throw new Error('Missing issuance value commitment');
    }
    if (issuanceValueCommitment.length !== 33) {
      throw new Error('Invalid issuance value commitment length');
    }
    if (issuanceValueBlinder.length === 0) {
      throw new Error('Missing issuance value blinder');
    }
    if (issuanceValueBlinder.length !== 32) {
      throw new Error('Invalid issuance value blinder length');
    }
    if (issuanceValueRangeProof.length === 0) {
      throw new Error('Missing issuance value range proof');
    }
    if (issuanceValueBlindProof.length === 0) {
      throw new Error('Missing issuance blind value proof');
    }

    if (targetInput.issuanceInflationKeys! > 0) {
      if (issuanceToken.length === 0) {
        throw new Error('Missing issuance token');
      }
      if (issuanceToken.length !== 32) {
        throw new Error('Invalid issuance token length');
      }
      if (issuanceTokenCommitment.length === 0) {
        throw new Error('Missing issuance token commitment');
      }
      if (issuanceTokenCommitment.length !== 33) {
        throw new Error('Invalid issuance token commitment length');
      }
      if (issuanceTokenBlinder.length === 0) {
        throw new Error('Missing issuance token blinder');
      }
      if (issuanceTokenBlinder.length !== 32) {
        throw new Error('Invalid issuance token blinder length');
      }
      if (issuanceTokenRangeProof.length === 0) {
        throw new Error('Missing issuance token range proof');
      }
      if (issuanceTokenBlindProof.length === 0) {
        throw new Error('Missing issuance blind token value proof');
      }
    }
  }

  private async validateOutputBlindingArgs(
    args: OutputBlindingArgs,
    lastBlinder: boolean,
  ): Promise<void> {
    const {
      index,
      nonce,
      nonceCommitment,
      valueCommitment,
      assetCommitment,
      valueRangeProof,
      assetSurjectionProof,
      valueBlindProof,
      assetBlindProof,
      valueBlinder,
      assetBlinder,
    } = args;
    if (index < 0 || index >= this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }

    const targetOutput = this.pset.outputs[index];
    if (!targetOutput.needsBlinding()) {
      throw new Error(
        'Target output does not need blinding (does not have a blinding pubkey set)',
      );
    }
    if (!this.ownOutput(targetOutput.blinderIndex!)) {
      throw new Error('Output is not owned by this blinder');
    }
    if (nonce.length === 0) {
      throw new Error('Missing nonce');
    }
    if (nonce.length !== 32) {
      throw new Error('Invalid nonce length');
    }
    if (nonceCommitment.length === 0) {
      throw new Error('Missing nonce commitment');
    }
    if (nonceCommitment.length !== 33) {
      throw new Error('Invalid nonce commitment length');
    }
    if (valueBlinder.length === 0) {
      throw new Error('Missing value blinder');
    }
    if (valueBlinder.length !== 32) {
      throw new Error('Invalid value blinder length');
    }
    if (assetBlinder.length === 0) {
      throw new Error('Missing asset blinder');
    }
    if (assetBlinder.length !== 32) {
      throw new Error('Invalid asset blinder length');
    }
    if (assetCommitment.length === 0) {
      throw new Error('Missing asset commitment');
    }
    if (assetCommitment.length !== 33) {
      throw new Error('Invalid asset commitment length');
    }
    if (assetSurjectionProof.length === 0) {
      throw new Error('Missing asset surjection proof');
    }
    if (assetBlindProof.length === 0) {
      throw new Error('Missing blind asset proof');
    }
    if (!lastBlinder) {
      if (valueCommitment.length === 0) {
        throw new Error('Missing value commitment');
      }
      if (valueCommitment.length !== 33) {
        throw new Error('Invalid value commitment length');
      }
      if (valueRangeProof.length === 0) {
        throw new Error('Missing value range proof');
      }
      if (valueBlindProof.length === 0) {
        throw new Error('Missing blind value proof');
      }
    }
  }

  private ownOutput(blinderIndex: number): boolean {
    return (
      this.ownedInputs.find(({ index }) => index === blinderIndex) !== undefined
    );
  }

  private validateBlindingData(
    isLastBlinder: boolean,
    outputBlindingArgs: OutputBlindingArgs[],
    issuanceBlindingArgs?: IssuanceBlindingArgs[],
  ): void {
    const inAssetsAndBlinders = this.pset.inputs.map((input, i) => {
      const ownedInput = this.ownedInputs.find(({ index }) => index === i);
      return ownedInput!
        ? {
            asset: ownedInput.asset,
            assetBlinder: ownedInput.assetBlindingFactor,
          }
        : {
            asset: input.getUtxo()!.asset,
            assetBlinder: ZERO,
          };
    });
    this.pset.inputs.forEach((input, i) => {
      if (input.hasIssuance() || input.hasReissuance()) {
        inAssetsAndBlinders.push({
          asset: input.getIssuanceAssetHash()!,
          assetBlinder: ZERO,
        });
        if (input.issuanceInflationKeys! > 0) {
          const blindedIssuance =
            issuanceBlindingArgs! &&
            issuanceBlindingArgs!.find(({ index }) => index === i) !==
              undefined;
          inAssetsAndBlinders.push({
            asset: input.getIssuanceInflationKeysHash(blindedIssuance)!,
            assetBlinder: ZERO,
          });
        }
      }
    });

    const inputAssets = inAssetsAndBlinders.map((v) => v.asset);
    const inputAssetBlinders = inAssetsAndBlinders.map((v) => v.assetBlinder);
    for (let i = 0; i < outputBlindingArgs.length; i++) {
      const {
        index,
        assetBlinder,
        assetCommitment,
        assetSurjectionProof,
        assetBlindProof,
        valueCommitment,
        valueRangeProof,
        valueBlindProof,
      } = outputBlindingArgs[i];
      const targetOutput = this.pset.outputs[index];
      const lastBlinder = isLastBlinder && i === outputBlindingArgs.length - 1;

      if (
        !this.blindingValidator.verifyAssetSurjectionProof(
          inputAssets,
          inputAssetBlinders,
          targetOutput.asset!,
          assetBlinder,
          assetSurjectionProof,
        )
      ) {
        throw new Error('Invalid output asset surjection proof');
      }
      if (
        !this.blindingValidator.verifyBlindAssetProof(
          targetOutput.asset!,
          assetCommitment,
          assetBlindProof,
        )
      ) {
        throw new Error('Invalid output asset blind proof');
      }
      if (!lastBlinder) {
        if (
          !this.blindingValidator.verifyValueRangeProof(
            valueCommitment,
            assetCommitment,
            valueRangeProof,
            targetOutput.script!,
          )
        ) {
          throw new Error('Invalid output value range proof');
        }
        if (
          !this.blindingValidator.verifyBlindValueProof(
            valueCommitment,
            assetCommitment,
            valueBlindProof,
          )
        ) {
          throw new Error('Invalid output value blind proof');
        }
      }
    }
  }
}
