'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function (o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.Updater = void 0;
const address_1 = require('../address');
const asset_1 = require('../asset');
const issuance_1 = require('../issuance');
const creator_1 = require('./creator');
const bscript = __importStar(require('../script'));
class Updater {
  constructor(pset) {
    pset.sanityCheck();
    this.pset = pset;
  }
  addInputs(ins) {
    const pset = this.pset.copy();
    ins.forEach((input) => {
      const creatorInput = new creator_1.CreatorInput(
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
    });
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addOutputs(outs) {
    const pset = this.pset.copy();
    outs.forEach((output) => {
      const creatorOutput = new creator_1.CreatorOutput(
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
  addInNonWitnessUtxo(inIndex, nonWitnessUtxo) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
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
  addInWitnessUtxo(inIndex, witnessUtxo) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].witnessUtxo = witnessUtxo;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInRedeemScript(inIndex, redeemScript) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].redeemScript = redeemScript;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInWitnessScript(inIndex, witnessScript) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].witnessScript = witnessScript;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInBIP32Derivation(inIndex, d) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    if (d.pubkey.length !== 33) {
      throw new Error('Invalid pubkey length');
    }
    const pset = this.pset.copy();
    if (!pset.inputs[inIndex].bip32Derivation) {
      pset.inputs[inIndex].bip32Derivation = [];
    }
    if (
      pset.inputs[inIndex].bip32Derivation.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('Duplicated bip32 derivation pubkey');
    }
    pset.inputs[inIndex].bip32Derivation.push(d);
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInSighashType(inIndex, sighashType) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
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
  addInUtxoRangeProof(inIndex, proof) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].utxoRangeProof = proof;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInIssuance(inIndex, args) {
    this.validateIssuanceInput(inIndex);
    validateAddInIssuanceArgs(args);
    const pset = this.pset.copy();
    const assetAmount = args.assetAmount || 0;
    const tokenAmount = args.tokenAmount || 0;
    const issuance = (0, issuance_1.newIssuance)(
      assetAmount,
      tokenAmount,
      args.contract,
    );
    pset.inputs[inIndex].issuanceValue = assetAmount;
    pset.inputs[inIndex].issuanceInflationKeys = tokenAmount;
    pset.inputs[inIndex].issuanceAssetEntropy = issuance.assetEntropy;
    pset.inputs[inIndex].issuanceBlindingNonce = issuance.assetBlindingNonce;
    const entropy = (0, issuance_1.generateEntropy)(
      {
        txHash: pset.inputs[inIndex].previousTxid,
        vout: pset.inputs[inIndex].previousTxIndex,
      },
      issuance.assetEntropy,
    );
    if (assetAmount > 0) {
      const issuedAsset = asset_1.AssetHash.fromBytes(
        (0, issuance_1.calculateAsset)(entropy),
      ).hex;
      let blinderIndex;
      let blindingPublicKey;
      if (
        args.assetAddress &&
        (0, address_1.isConfidential)(args.assetAddress)
      ) {
        blinderIndex = inIndex;
        blindingPublicKey = (0, address_1.fromConfidential)(
          args.assetAddress,
        ).blindingKey;
      }
      const output = new creator_1.CreatorOutput(
        issuedAsset,
        assetAmount,
        // Why this should be undefined? should'nt be always be mandatory?
        (0, address_1.toOutputScript)(args.assetAddress),
        blindingPublicKey,
        blinderIndex,
      );
      pset.addOutput(output.toPartialOutput());
    }
    if (tokenAmount > 0) {
      const reissuanceToken = asset_1.AssetHash.fromBytes(
        (0, issuance_1.calculateReissuanceToken)(entropy, args.blindedIssuance),
      ).hex;
      let blinderIndex;
      let blindingPublicKey;
      if (
        args.tokenAddress &&
        (0, address_1.isConfidential)(args.tokenAddress)
      ) {
        blinderIndex = inIndex;
        blindingPublicKey = (0, address_1.fromConfidential)(
          args.tokenAddress,
        ).blindingKey;
      }
      const output = new creator_1.CreatorOutput(
        reissuanceToken,
        tokenAmount,
        (0, address_1.toOutputScript)(args.tokenAddress),
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
  addInReissuance(inIndex, args) {
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
    const asset = asset_1.AssetHash.fromBytes(
      (0, issuance_1.calculateAsset)(entropy),
    ).hex;
    const reissuanceToken = asset_1.AssetHash.fromBytes(
      (0, issuance_1.calculateReissuanceToken)(entropy, true),
    ).hex;
    pset.inputs[inIndex].issuanceAssetEntropy = entropy;
    pset.inputs[inIndex].issuanceBlindingNonce = blindingNonce;
    pset.inputs[inIndex].issuanceValue = args.assetAmount;
    pset.inputs[inIndex].issuanceInflationKeys = 0;
    const assetBlindingPublicKey = (0, address_1.fromConfidential)(
      args.assetAddress,
    ).blindingKey;
    const assetOutput = new creator_1.CreatorOutput(
      asset,
      args.assetAmount,
      (0, address_1.toOutputScript)(args.assetAddress),
      assetBlindingPublicKey,
      inIndex,
    );
    const tokenBlindingPublicKey = (0, address_1.fromConfidential)(
      args.tokenAddress,
    ).blindingKey;
    const tokenOutput = new creator_1.CreatorOutput(
      reissuanceToken,
      args.tokenAmount,
      (0, address_1.toOutputScript)(args.tokenAddress),
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
  addInPartialSignature(inIndex, ps, validator) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }
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
    pset.inputs[inIndex].partialSigs.push(ps);
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInTimeLocktime(inIndex, locktime) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
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
  addInHeightLocktime(inIndex, locktime) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
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
  addInTapKeySig(inIndex, sig, genesisBlockHash, validator) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
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
    const tweakedKey = input.getUtxo().script.slice(2);
    const sighash = pset.getInputPreimage(
      inIndex,
      input.sighashType,
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
  addInTapScriptSig(inIndex, sig, genesisBlockHash, validator) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
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
      input.sighashType,
      genesisBlockHash,
      sig.leafHash,
    );
    if (!validator(sig.pubkey, sighash, sig.signature)) {
      throw new Error(`Invalid taproot script signature for input ${inIndex}`);
    }
    if (!pset.inputs[inIndex].tapScriptSig) {
      pset.inputs[inIndex].tapScriptSig = [];
    }
    pset.inputs[inIndex].tapScriptSig.push(sig);
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInTapLeafScript(inIndex, tapLeafScript) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const pset = this.pset.copy();
    if (!pset.inputs[inIndex].tapLeafScript) {
      pset.inputs[inIndex].tapLeafScript = [];
    }
    pset.inputs[inIndex].tapLeafScript.push(tapLeafScript);
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInTapBIP32Derivation(inIndex, d) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    if (d.pubkey.length !== 33) {
      throw new Error('Invalid input taproot pubkey length');
    }
    const pset = this.pset.copy();
    if (!pset.inputs[inIndex].tapBip32Derivation) {
      pset.inputs[inIndex].tapBip32Derivation = [];
    }
    if (
      pset.inputs[inIndex].bip32Derivation.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('Duplicated taproot bip32 derivation pubkey');
    }
    pset.inputs[inIndex].tapBip32Derivation.push(d);
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInTapInternalKey(inIndex, tapInternalKey) {
    if (inIndex < 0 || inIndex > this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    if (tapInternalKey.length !== 32) {
      throw new Error('Invalid taproot internal key length');
    }
    if (
      this.pset.inputs[inIndex].tapInternalKey &&
      this.pset.inputs[inIndex].tapInternalKey.length > 0
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
  addInTapMerkleRoot(inIndex, tapMerkleRoot) {
    if (inIndex < 0 || inIndex > this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    if (tapMerkleRoot.length !== 32) {
      throw new Error('Invalid taproot merkle root length');
    }
    if (
      this.pset.inputs[inIndex].tapMerkleRoot &&
      this.pset.inputs[inIndex].tapMerkleRoot.length > 0
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
  addOutBIP32Derivation(outIndex, d) {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }
    if (d.pubkey.length !== 33) {
      throw new Error('Invalid pubkey length');
    }
    const pset = this.pset.copy();
    if (!pset.outputs[outIndex].bip32Derivation) {
      pset.outputs[outIndex].bip32Derivation = [];
    }
    if (
      pset.outputs[outIndex].bip32Derivation.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('Duplicated bip32 derivation pubkey');
    }
    pset.outputs[outIndex].bip32Derivation.push(d);
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addOutRedeemScript(outIndex, redeemScript) {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }
    const pset = this.pset.copy();
    pset.outputs[outIndex].redeemScript = redeemScript;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addOutWitnessScript(outIndex, witnessScript) {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }
    const pset = this.pset.copy();
    pset.outputs[outIndex].witnessScript = witnessScript;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addOutTapInternalKey(outIndex, tapInternalKey) {
    if (outIndex < 0 || outIndex > this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }
    if (tapInternalKey.length !== 32) {
      throw new Error('Invalid taproot internal key length');
    }
    if (
      this.pset.outputs[outIndex].tapInternalKey &&
      this.pset.outputs[outIndex].tapInternalKey.length > 0
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
  addOutTapTree(outIndex, tapTree) {
    if (outIndex < 0 || outIndex > this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }
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
  addOutTapBIP32Derivation(outIndex, d) {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }
    if (d.pubkey.length !== 33) {
      throw new Error('Invalid output taproot pubkey length');
    }
    const pset = this.pset.copy();
    if (!pset.outputs[outIndex].tapBip32Derivation) {
      pset.outputs[outIndex].tapBip32Derivation = [];
    }
    if (
      pset.outputs[outIndex].bip32Derivation.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('Duplicated taproot bip32 derivation pubkey');
    }
    pset.outputs[outIndex].tapBip32Derivation.push(d);
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  validateIssuanceInput(inIndex) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const input = this.pset.inputs[inIndex];
    if (input.issuanceAssetEntropy && input.issuanceAssetEntropy.length > 0) {
      throw new Error('Input ' + inIndex + ' already has an issuance');
    }
  }
  validateReissuanceInput(inIndex) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
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
}
exports.Updater = Updater;
function validateAddInIssuanceArgs(args) {
  const assetAmount = args.assetAmount || 0;
  const tokenAmount = args.tokenAmount || 0;
  if (assetAmount <= 0 && tokenAmount <= 0) {
    throw new Error('Either asset or token amounts must be a positive number');
  }
  if (assetAmount > 0) {
    if (!args.assetAddress || args.assetAddress.length === 0) {
      throw new Error(
        'Asset address must be defined if asset amount is non-zero',
      );
    }
  }
  if (tokenAmount > 0) {
    if (!args.tokenAddress || args.tokenAddress.length === 0) {
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
function validateAddInReissuanceArgs(args) {
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
  if (!(0, address_1.isConfidential)(args.assetAddress)) {
    throw new Error('Asset and token addresses must be both confidential');
  }
}
function matchAddressesType(addrA, addrB) {
  if (!addrA || addrA.length === 0 || !addrB || addrB.length === 0) {
    return true;
  }
  const netA = (0, address_1.getNetwork)(addrA);
  const netB = (0, address_1.getNetwork)(addrB);
  if (netA.name !== netB.name) {
    return false;
  }
  const isConfidentialA = (0, address_1.isConfidential)(addrA);
  const isConfidentialB = (0, address_1.isConfidential)(addrB);
  if (isConfidentialA !== isConfidentialB) {
    return false;
  }
  return true;
}
function validatePartialSignature(psig) {
  if (psig.pubkey.length !== 33) {
    throw new Error('Invalid pubkey length');
  }
  bscript.signature.decode(psig.signature);
}
