import { TxOutput } from '..';
import {
  fromConfidential,
  getNetwork,
  isConfidential,
  toOutputScript,
} from '../address';
import { AssetHash } from '../asset';
import {
  calculateAsset,
  calculateReissuanceToken,
  generateEntropy,
  IssuanceContract,
  newIssuance,
} from '../issuance';
import { Transaction } from '../transaction';
import { CreatorInput, CreatorOutput } from './creator';
import {
  Bip32Derivation,
  PartialSig,
  TapBip32Derivation,
  TapInternalKey,
  TapLeafScript,
  TapMerkleRoot,
  TapScriptSig,
  TapTree,
} from './interfaces';
import { Pset, ValidateSigFunction } from './pset';
import * as bscript from '../script';

export interface IssuanceOpts {
  assetAmount?: number;
  tokenAmount?: number;
  contract?: IssuanceContract;
  assetAddress?: string;
  tokenAddress?: string;
  blindedIssuance?: boolean;
}

export interface ReissuanceOpts {
  entropy: string | Buffer;
  assetAmount: number;
  assetAddress: string;
  tokenAmount: number;
  tokenAddress: string;
  tokenAssetBlinder: string | Buffer;
}

export interface UpdaterInput {
  txid: string;
  txIndex: number;
  sequence?: number;
  heightLocktime?: number;
  timeLocktime?: number;
  witnessUtxo?: TxOutput;
  nonWitnessUtxo?: Transaction;
  sighashType?: number;
  tapInternalKey?: TapInternalKey;
  tapLeafScript?: TapLeafScript;
  tapMerkleRoot?: TapMerkleRoot;
  issaunceOpts?: IssuanceOpts;
  reissuanceOpts?: ReissuanceOpts;
  explicitValue?: number;
  explicitValueProof?: Buffer;
  explicitAsset?: Buffer;
  explicitAssetProof?: Buffer;
}

export interface UpdaterOutput {
  asset: string;
  amount: number;
  script?: Buffer;
  blindingPublicKey?: Buffer;
  blinderIndex?: number;
}

export class Updater {
  pset: Pset;

  constructor(pset: Pset) {
    pset.sanityCheck();
    this.pset = pset;
  }

  addInputs(ins: UpdaterInput[]): this {
    const pset = this.pset.copy();

    ins.forEach((input) => {
      const creatorInput = new CreatorInput(
        input.txid,
        input.txIndex,
        input.sequence,
        input.heightLocktime,
        input.timeLocktime,
      );
      creatorInput.validate();
      pset.addInput(creatorInput.toPartialInput());

      // we know at this point, index can't be negative
      const inputIndex = pset.inputs.length - 1;

      if (input.witnessUtxo)
        this.addInWitnessUtxo(inputIndex, input.witnessUtxo);

      if (input.witnessUtxo && input.witnessUtxo.rangeProof) {
        this.addInUtxoRangeProof(inputIndex, input.witnessUtxo.rangeProof);
      }

      if (input.nonWitnessUtxo)
        this.addInNonWitnessUtxo(inputIndex, input.nonWitnessUtxo);

      if (input.nonWitnessUtxo && input.nonWitnessUtxo.outs[input.txIndex]) {
        const previousOutput = input.nonWitnessUtxo.outs[input.txIndex];
        if (previousOutput.rangeProof)
          this.addInUtxoRangeProof(inputIndex, previousOutput.rangeProof);
      }

      if (input.sighashType !== undefined)
        this.addInSighashType(inputIndex, input.sighashType);

      if (input.tapInternalKey)
        this.addInTapInternalKey(inputIndex, input.tapInternalKey);

      if (input.tapLeafScript)
        this.addInTapLeafScript(inputIndex, input.tapLeafScript);

      if (input.tapMerkleRoot)
        this.addInTapMerkleRoot(inputIndex, input.tapMerkleRoot);

      if (input.issaunceOpts)
        this.addInIssuance(inputIndex, input.issaunceOpts);

      if (input.reissuanceOpts)
        this.addInReissuance(inputIndex, input.reissuanceOpts);

      if (input.explicitAsset) {
        this.addInExplicitAsset(
          inputIndex,
          input.explicitAsset,
          input.explicitAssetProof ?? Buffer.alloc(0),
        );
      }

      if (input.explicitValue) {
        this.addInExplicitValue(
          inputIndex,
          input.explicitValue,
          input.explicitValueProof ?? Buffer.alloc(0),
        );
      }
    });

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addOutputs(outs: UpdaterOutput[]): this {
    const pset = this.pset.copy();

    outs.forEach((output) => {
      const creatorOutput = new CreatorOutput(
        output.asset,
        output.amount,
        output.script,
        output.blindingPublicKey,
        output.blinderIndex,
      );
      creatorOutput.validate();
      pset.addOutput(creatorOutput.toPartialOutput());
    });

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInNonWitnessUtxo(inIndex: number, nonWitnessUtxo: Transaction): this {
    this.validateInputIndex(inIndex);
    const pset = this.pset.copy();
    const txid = nonWitnessUtxo.getHash(false);
    if (!txid.equals(pset.inputs[inIndex].previousTxid)) {
      throw new Error('Non-witness utxo hash does not match prevout txid');
    }
    pset.inputs[inIndex].nonWitnessUtxo = nonWitnessUtxo;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInWitnessUtxo(inIndex: number, witnessUtxo: TxOutput): this {
    this.validateInputIndex(inIndex);
    const pset = this.pset.copy();
    pset.inputs[inIndex].witnessUtxo = witnessUtxo;
    pset.inputs[inIndex].utxoRangeProof = witnessUtxo.rangeProof;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInRedeemScript(inIndex: number, redeemScript: Buffer): this {
    this.validateInputIndex(inIndex);
    const pset = this.pset.copy();
    pset.inputs[inIndex].redeemScript = redeemScript;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInWitnessScript(inIndex: number, witnessScript: Buffer): this {
    this.validateInputIndex(inIndex);

    const pset = this.pset.copy();
    pset.inputs[inIndex].witnessScript = witnessScript;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInBIP32Derivation(inIndex: number, d: Bip32Derivation): this {
    this.validateInputIndex(inIndex);

    if (d.pubkey.length !== 33) {
      throw new Error('Invalid pubkey length');
    }

    const pset = this.pset.copy();
    if (!pset.inputs[inIndex].bip32Derivation) {
      pset.inputs[inIndex].bip32Derivation = [];
    }
    if (
      pset.inputs[inIndex].bip32Derivation!.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('Duplicated bip32 derivation pubkey');
    }
    pset.inputs[inIndex].bip32Derivation!.push(d);
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInSighashType(inIndex: number, sighashType: number): this {
    this.validateInputIndex(inIndex);

    if (sighashType < 0) {
      throw new Error('Invalid sighash type');
    }

    const pset = this.pset.copy();
    pset.inputs[inIndex].sighashType = sighashType;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInUtxoRangeProof(inIndex: number, proof: Buffer): this {
    this.validateInputIndex(inIndex);

    const pset = this.pset.copy();
    pset.inputs[inIndex].utxoRangeProof = proof;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInIssuance(inIndex: number, args: IssuanceOpts): this {
    this.validateIssuanceInput(inIndex);
    validateAddInIssuanceArgs(args);

    const pset = this.pset.copy();

    const assetAmount = args.assetAmount || 0;
    const tokenAmount = args.tokenAmount || 0;
    const issuance = newIssuance(assetAmount, tokenAmount, args.contract);

    pset.inputs[inIndex].issuanceValue = assetAmount;
    pset.inputs[inIndex].issuanceInflationKeys = tokenAmount;
    pset.inputs[inIndex].issuanceAssetEntropy = issuance.assetEntropy;
    pset.inputs[inIndex].issuanceBlindingNonce = issuance.assetBlindingNonce;
    pset.inputs[inIndex].blindedIssuance =
      args.blindedIssuance !== undefined ? args.blindedIssuance : true;

    const entropy = generateEntropy(
      {
        txHash: pset.inputs[inIndex].previousTxid,
        vout: pset.inputs[inIndex].previousTxIndex,
      },
      issuance.assetEntropy,
    );

    if (assetAmount > 0) {
      const issuedAsset = AssetHash.fromBytes(calculateAsset(entropy)).hex;

      let blinderIndex: number | undefined;
      let blindingPublicKey: Buffer | undefined;
      if (args.assetAddress && isConfidential(args.assetAddress)) {
        blinderIndex = inIndex;
        blindingPublicKey = fromConfidential(args.assetAddress).blindingKey;
      }

      const output = new CreatorOutput(
        issuedAsset,
        assetAmount,
        // Why this should be undefined? should'nt be always be mandatory?
        toOutputScript(args.assetAddress!),
        blindingPublicKey,
        blinderIndex,
      );
      pset.addOutput(output.toPartialOutput());
    }

    if (tokenAmount > 0) {
      const reissuanceToken = AssetHash.fromBytes(
        calculateReissuanceToken(entropy, args.blindedIssuance),
      ).hex;

      let blinderIndex: number | undefined;
      let blindingPublicKey: Buffer | undefined;
      if (args.tokenAddress && isConfidential(args.tokenAddress)) {
        blinderIndex = inIndex;
        blindingPublicKey = fromConfidential(args.tokenAddress).blindingKey;
      }
      const output = new CreatorOutput(
        reissuanceToken,
        tokenAmount,
        toOutputScript(args.tokenAddress!),
        blindingPublicKey,
        blinderIndex,
      );
      pset.addOutput(output.toPartialOutput());
    }

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInReissuance(inIndex: number, args: ReissuanceOpts): this {
    this.validateReissuanceInput(inIndex);
    validateAddInReissuanceArgs(args);

    const pset = this.pset.copy();

    const entropy =
      typeof args.entropy === 'string'
        ? Buffer.from(args.entropy, 'hex').reverse()
        : args.entropy;
    const blindingNonce =
      typeof args.tokenAssetBlinder === 'string'
        ? Buffer.from(args.tokenAssetBlinder, 'hex').reverse()
        : args.tokenAssetBlinder;
    const asset = AssetHash.fromBytes(calculateAsset(entropy)).hex;
    const reissuanceToken = AssetHash.fromBytes(
      calculateReissuanceToken(entropy, true),
    ).hex;

    pset.inputs[inIndex].issuanceAssetEntropy = entropy;
    pset.inputs[inIndex].issuanceBlindingNonce = blindingNonce;
    pset.inputs[inIndex].issuanceValue = args.assetAmount;
    pset.inputs[inIndex].issuanceInflationKeys = 0;

    const assetBlindingPublicKey = fromConfidential(
      args.assetAddress,
    ).blindingKey;
    const assetOutput = new CreatorOutput(
      asset,
      args.assetAmount,
      toOutputScript(args.assetAddress),
      assetBlindingPublicKey,
      inIndex,
    );

    const tokenBlindingPublicKey = fromConfidential(
      args.tokenAddress,
    ).blindingKey;
    const tokenOutput = new CreatorOutput(
      reissuanceToken,
      args.tokenAmount,
      toOutputScript(args.tokenAddress),
      tokenBlindingPublicKey,
      inIndex,
    );
    pset.addOutput(assetOutput.toPartialOutput());
    pset.addOutput(tokenOutput.toPartialOutput());

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInPartialSignature(
    inIndex: number,
    ps: PartialSig,
    validator: ValidateSigFunction,
  ): this {
    this.validateInputIndex(inIndex);

    // ensure the pubkey and signature are valid
    validatePartialSignature(ps);

    // check for duplicates
    if (
      (this.pset.inputs[inIndex].partialSigs || []).some(({ pubkey }) =>
        pubkey.equals(ps.pubkey),
      )
    ) {
      throw new Error('Duplicated signature pubkey');
    }

    const pset = this.pset.copy();

    // validate signature against input's preimage and pubkey
    const sighashType = ps.signature.slice(-1)[0];
    const preimage = pset.getInputPreimage(inIndex, sighashType);
    const { signature } = bscript.signature.decode(ps.signature);
    if (!validator(ps.pubkey, preimage, signature)) {
      throw new Error('Invalid signature');
    }

    if (!pset.inputs[inIndex].partialSigs) {
      pset.inputs[inIndex].partialSigs = [];
    }
    pset.inputs[inIndex].partialSigs!.push(ps);

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInTimeLocktime(inIndex: number, locktime: number): this {
    this.validateInputIndex(inIndex);
    if (locktime < 0) {
      throw new Error('Invalid required time locktime');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].requiredTimeLocktime = locktime;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInHeightLocktime(inIndex: number, locktime: number): this {
    this.validateInputIndex(inIndex);

    if (locktime < 0) {
      throw new Error('Invalid required height locktime');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].requiredHeightLocktime = locktime;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInTapKeySig(
    inIndex: number,
    sig: Buffer,
    genesisBlockHash: Buffer,
    validator: ValidateSigFunction,
  ): this {
    this.validateInputIndex(inIndex);

    if (sig.length !== 64 && sig.length !== 65) {
      throw new Error('Invalid taproot key signature length');
    }
    if (genesisBlockHash.length !== 32) {
      throw new Error('Invalid genesis block hash length');
    }

    const pset = this.pset.copy();
    const input = pset.inputs[inIndex];

    if (!input.getUtxo()) {
      throw new Error('Missing input witness utxo');
    }
    if (input.sighashType === undefined) {
      throw new Error('Missing input sighash type');
    }

    const tweakedKey = input.getUtxo()!.script.slice(2);
    const sighash = pset.getInputPreimage(
      inIndex,
      input.sighashType!,
      genesisBlockHash,
    );
    if (!validator(tweakedKey, sighash, sig)) {
      throw new Error(`Invalid taproot key signature for input ${inIndex}`);
    }

    pset.inputs[inIndex].tapKeySig = sig;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInTapScriptSig(
    inIndex: number,
    sig: TapScriptSig,
    genesisBlockHash: Buffer,
    validator: ValidateSigFunction,
  ): this {
    this.validateInputIndex(inIndex);

    if (sig.pubkey.length !== 32) {
      throw new Error('Invalid xonly pubkey length');
    }
    if (sig.leafHash.length !== 32) {
      throw new Error('Invalid leaf hash length');
    }
    if (sig.signature.length !== 64 && sig.signature.length !== 65) {
      throw new Error('Invalid signature length');
    }
    if (genesisBlockHash.length !== 32) {
      throw new Error('Invalid genesis block hash length');
    }

    const pset = this.pset.copy();
    const input = pset.inputs[inIndex];

    if (input.sighashType === undefined) {
      throw new Error('Missing input sighash type');
    }

    const sighash = pset.getInputPreimage(
      inIndex,
      input.sighashType!,
      genesisBlockHash,
      sig.leafHash,
    );

    if (!validator(sig.pubkey, sighash, sig.signature)) {
      throw new Error(`Invalid taproot script signature for input ${inIndex}`);
    }

    if (!pset.inputs[inIndex].tapScriptSig) {
      pset.inputs[inIndex].tapScriptSig = [];
    }
    pset.inputs[inIndex].tapScriptSig!.push(sig);
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInTapLeafScript(inIndex: number, tapLeafScript: TapLeafScript): this {
    this.validateInputIndex(inIndex);

    const pset = this.pset.copy();
    if (!pset.inputs[inIndex].tapLeafScript) {
      pset.inputs[inIndex].tapLeafScript = [];
    }
    pset.inputs[inIndex].tapLeafScript!.push(tapLeafScript);
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInTapBIP32Derivation(inIndex: number, d: TapBip32Derivation): this {
    this.validateInputIndex(inIndex);

    if (d.pubkey.length !== 33) {
      throw new Error('Invalid input taproot pubkey length');
    }

    const pset = this.pset.copy();
    if (!pset.inputs[inIndex].tapBip32Derivation) {
      pset.inputs[inIndex].tapBip32Derivation = [];
    }
    if (
      pset.inputs[inIndex].bip32Derivation!.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('Duplicated taproot bip32 derivation pubkey');
    }
    pset.inputs[inIndex].tapBip32Derivation!.push(d);
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInTapInternalKey(inIndex: number, tapInternalKey: TapInternalKey): this {
    this.validateInputIndex(inIndex);

    if (tapInternalKey.length !== 32) {
      throw new Error('Invalid taproot internal key length');
    }
    if (
      this.pset.inputs[inIndex].tapInternalKey &&
      this.pset.inputs[inIndex].tapInternalKey!.length > 0
    ) {
      throw new Error('Duplicated taproot internal key');
    }

    const pset = this.pset.copy();
    pset.inputs[inIndex].tapInternalKey = tapInternalKey;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInTapMerkleRoot(inIndex: number, tapMerkleRoot: TapMerkleRoot): this {
    this.validateInputIndex(inIndex);

    if (tapMerkleRoot.length !== 32) {
      throw new Error('Invalid taproot merkle root length');
    }
    if (
      this.pset.inputs[inIndex].tapMerkleRoot &&
      this.pset.inputs[inIndex].tapMerkleRoot!.length > 0
    ) {
      throw new Error('Duplicated taproot merkle root');
    }

    const pset = this.pset.copy();
    pset.inputs[inIndex].tapMerkleRoot = tapMerkleRoot;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInExplicitValue(
    inIndex: number,
    explicitValue: number,
    explicitValueProof: Buffer,
  ): this {
    this.validateInputIndex(inIndex);

    const pset = this.pset.copy();
    pset.inputs[inIndex].explicitValue = explicitValue;
    pset.inputs[inIndex].explicitValueProof = explicitValueProof;

    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addInExplicitAsset(
    inIndex: number,
    explicitAsset: Buffer,
    explicitAssetProof: Buffer,
  ): this {
    this.validateInputIndex(inIndex);

    const pset = this.pset.copy();
    pset.inputs[inIndex].explicitAsset = explicitAsset;
    pset.inputs[inIndex].explicitAssetProof = explicitAssetProof;

    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }

  addOutBIP32Derivation(outIndex: number, d: Bip32Derivation): this {
    this.validateOutputIndex(outIndex);

    if (d.pubkey.length !== 33) {
      throw new Error('Invalid pubkey length');
    }

    const pset = this.pset.copy();
    if (!pset.outputs[outIndex].bip32Derivation) {
      pset.outputs[outIndex].bip32Derivation = [];
    }
    if (
      pset.outputs[outIndex].bip32Derivation!.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('Duplicated bip32 derivation pubkey');
    }
    pset.outputs[outIndex].bip32Derivation!.push(d);
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addOutRedeemScript(outIndex: number, redeemScript: Buffer): this {
    this.validateOutputIndex(outIndex);

    const pset = this.pset.copy();
    pset.outputs[outIndex].redeemScript = redeemScript;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addOutWitnessScript(outIndex: number, witnessScript: Buffer): this {
    this.validateOutputIndex(outIndex);

    const pset = this.pset.copy();
    pset.outputs[outIndex].witnessScript = witnessScript;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addOutTapInternalKey(outIndex: number, tapInternalKey: TapInternalKey): this {
    this.validateOutputIndex(outIndex);

    if (tapInternalKey.length !== 32) {
      throw new Error('Invalid taproot internal key length');
    }
    if (
      this.pset.outputs[outIndex].tapInternalKey &&
      this.pset.outputs[outIndex].tapInternalKey!.length > 0
    ) {
      throw new Error('Duplicated taproot internal key');
    }

    const pset = this.pset.copy();
    pset.outputs[outIndex].tapInternalKey = tapInternalKey;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addOutTapTree(outIndex: number, tapTree: TapTree): this {
    this.validateOutputIndex(outIndex);

    if (this.pset.outputs[outIndex].tapTree) {
      throw new Error('Duplicated taproot tree');
    }

    const pset = this.pset.copy();
    pset.outputs[outIndex].tapTree = tapTree;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  addOutTapBIP32Derivation(outIndex: number, d: TapBip32Derivation): this {
    this.validateOutputIndex(outIndex);

    if (d.pubkey.length !== 33) {
      throw new Error('Invalid output taproot pubkey length');
    }

    const pset = this.pset.copy();
    if (!pset.outputs[outIndex].tapBip32Derivation) {
      pset.outputs[outIndex].tapBip32Derivation = [];
    }
    if (
      pset.outputs[outIndex].bip32Derivation!.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('Duplicated taproot bip32 derivation pubkey');
    }
    pset.outputs[outIndex].tapBip32Derivation!.push(d);
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  private validateIssuanceInput(inIndex: number): void {
    this.validateInputIndex(inIndex);

    const input = this.pset.inputs[inIndex];
    if (input.issuanceAssetEntropy && input.issuanceAssetEntropy.length > 0) {
      throw new Error('Input ' + inIndex + ' already has an issuance');
    }
  }

  private validateReissuanceInput(inIndex: number): void {
    this.validateInputIndex(inIndex);

    const input = this.pset.inputs[inIndex];
    if (input.issuanceAssetEntropy && input.issuanceAssetEntropy.length > 0) {
      throw new Error(`Input ${inIndex} already has an issuance`);
    }
    const prevout = input.getUtxo();
    if (!prevout) {
      throw new Error('Input is missing prevout (non-)witness utxo');
    }
    if (prevout.nonce.length <= 1) {
      throw new Error('Input prevout (non-)witness utxo must be confidential');
    }
  }

  private validateOutputIndex(outIndex: number): void {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }
  }

  private validateInputIndex(inIndex: number): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
  }
}

function validateAddInIssuanceArgs(args: IssuanceOpts): void {
  const assetAmount = args.assetAmount || 0;
  const tokenAmount = args.tokenAmount || 0;
  if (assetAmount <= 0 && tokenAmount <= 0) {
    throw new Error('Either asset or token amounts must be a positive number');
  }

  if (assetAmount > 0) {
    if (!args.assetAddress || args.assetAddress!.length === 0) {
      throw new Error(
        'Asset address must be defined if asset amount is non-zero',
      );
    }
  }
  if (tokenAmount > 0) {
    if (!args.tokenAddress || args.tokenAddress!.length === 0) {
      throw new Error(
        'Token address must be defined if token amount is non-zero',
      );
    }
  }

  if (!matchAddressesType(args.assetAddress, args.tokenAddress)) {
    throw new Error(
      'Asset and token addresses must be of same network and both unconfidential or confidential',
    );
  }
}

function validateAddInReissuanceArgs(args: ReissuanceOpts): void {
  const entropy =
    typeof args.entropy === 'string'
      ? Buffer.from(args.entropy, 'hex').reverse()
      : args.entropy;
  if (entropy.length !== 32) {
    throw new Error('Invalid entropy length');
  }
  const blinder =
    typeof args.tokenAssetBlinder === 'string'
      ? Buffer.from(args.tokenAssetBlinder, 'hex').reverse()
      : args.tokenAssetBlinder;
  if (blinder.length !== 32) {
    throw new Error('Invalid token asset blinder length');
  }
  if (args.assetAmount <= 0) {
    throw new Error('Asset amount must be a positive number');
  }
  if (args.tokenAmount <= 0) {
    throw new Error('Token amount must be a positive number');
  }
  if (args.assetAddress.length === 0) {
    throw new Error('Missing asset address');
  }
  if (args.tokenAddress.length === 0) {
    throw new Error('Missing token address');
  }

  if (!matchAddressesType(args.assetAddress, args.tokenAddress)) {
    throw new Error(
      'Asset and token addresses must be both of same network and both confidential',
    );
  }
  if (!isConfidential(args.assetAddress)) {
    throw new Error('Asset and token addresses must be both confidential');
  }
}

function matchAddressesType(addrA?: string, addrB?: string): boolean {
  if (!addrA || addrA!.length === 0 || !addrB || addrB!.length === 0) {
    return true;
  }

  const netA = getNetwork(addrA);
  const netB = getNetwork(addrB);
  if (netA.name !== netB.name) {
    return false;
  }

  const isConfidentialA = isConfidential(addrA);
  const isConfidentialB = isConfidential(addrB);
  if (isConfidentialA !== isConfidentialB) {
    return false;
  }

  return true;
}

function validatePartialSignature(psig: PartialSig): void {
  if (psig.pubkey.length !== 33) {
    throw new Error('Invalid pubkey length');
  }
  bscript.signature.decode(psig.signature);
}
