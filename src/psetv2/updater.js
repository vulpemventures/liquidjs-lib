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
function processOutputDestination(dest) {
  if (typeof dest === 'string') {
    const script = (0, address_1.toOutputScript)(dest);
    if ((0, address_1.isConfidential)(dest))
      return {
        script,
        blindingPublicKey: (0, address_1.fromConfidential)(dest).blindingKey,
      };
    return { script };
  }
  return dest;
}
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
      if (input.witnessScript)
        this.addInWitnessScript(inputIndex, input.witnessScript);
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
  addInWitnessUtxo(inIndex, witnessUtxo) {
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
  addInRedeemScript(inIndex, redeemScript) {
    this.validateInputIndex(inIndex);
    const pset = this.pset.copy();
    pset.inputs[inIndex].redeemScript = redeemScript;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInWitnessScript(inIndex, witnessScript) {
    this.validateInputIndex(inIndex);
    const pset = this.pset.copy();
    pset.inputs[inIndex].witnessScript = witnessScript;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInBIP32Derivation(inIndex, d) {
    this.validateInputIndex(inIndex);
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
  addInUtxoRangeProof(inIndex, proof) {
    this.validateInputIndex(inIndex);
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
    pset.inputs[inIndex].blindedIssuance =
      args.blindedIssuance !== undefined ? args.blindedIssuance : true;
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
      const { blindingPublicKey, script } = processOutputDestination(
        args.assetAddress,
      );
      const output = new creator_1.CreatorOutput(
        issuedAsset,
        assetAmount,
        script,
        blindingPublicKey,
        blindingPublicKey ? inIndex : undefined,
      );
      pset.addOutput(output.toPartialOutput());
    }
    if (tokenAmount > 0) {
      const reissuanceToken = asset_1.AssetHash.fromBytes(
        (0, issuance_1.calculateReissuanceToken)(
          entropy,
          args.blindedIssuance ?? true,
        ),
      ).hex;
      const { blindingPublicKey, script } = processOutputDestination(
        args.tokenAddress,
      );
      const output = new creator_1.CreatorOutput(
        reissuanceToken,
        tokenAmount,
        script,
        blindingPublicKey,
        blindingPublicKey ? inIndex : undefined,
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
      (0, issuance_1.calculateReissuanceToken)(
        entropy,
        args.initialIssuanceBlinded ?? true,
      ),
    ).hex;
    pset.inputs[inIndex].issuanceAssetEntropy = entropy;
    pset.inputs[inIndex].issuanceBlindingNonce = blindingNonce;
    pset.inputs[inIndex].issuanceValue = args.assetAmount;
    pset.inputs[inIndex].issuanceInflationKeys = 0;
    if (args.blindedIssuance !== undefined) {
      pset.inputs[inIndex].blindedIssuance = args.blindedIssuance;
    }
    if (args.assetAddress) {
      const { blindingPublicKey, script } = processOutputDestination(
        args.assetAddress,
      );
      const assetOutput = new creator_1.CreatorOutput(
        asset,
        args.assetAmount,
        script,
        blindingPublicKey,
        blindingPublicKey ? inIndex : undefined,
      );
      pset.addOutput(assetOutput.toPartialOutput());
    }
    if (args.tokenAddress) {
      const { blindingPublicKey, script } = processOutputDestination(
        args.tokenAddress,
      );
      const tokenOutput = new creator_1.CreatorOutput(
        reissuanceToken,
        args.tokenAmount,
        script,
        blindingPublicKey,
        blindingPublicKey ? inIndex : undefined,
      );
      pset.addOutput(tokenOutput.toPartialOutput());
    }
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInPartialSignature(inIndex, ps, validator) {
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
    pset.inputs[inIndex].partialSigs.push(ps);
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addInTimeLocktime(inIndex, locktime) {
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
  addInHeightLocktime(inIndex, locktime) {
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
  addInTapKeySig(inIndex, sig, genesisBlockHash, validator) {
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
    this.validateInputIndex(inIndex);
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
    this.validateInputIndex(inIndex);
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
    this.validateInputIndex(inIndex);
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
    this.validateInputIndex(inIndex);
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
  addInExplicitValue(inIndex, explicitValue, explicitValueProof) {
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
  addInExplicitAsset(inIndex, explicitAsset, explicitAssetProof) {
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
  addOutBIP32Derivation(outIndex, d) {
    this.validateOutputIndex(outIndex);
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
    this.validateOutputIndex(outIndex);
    const pset = this.pset.copy();
    pset.outputs[outIndex].redeemScript = redeemScript;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addOutWitnessScript(outIndex, witnessScript) {
    this.validateOutputIndex(outIndex);
    const pset = this.pset.copy();
    pset.outputs[outIndex].witnessScript = witnessScript;
    pset.sanityCheck();
    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
    return this;
  }
  addOutTapInternalKey(outIndex, tapInternalKey) {
    this.validateOutputIndex(outIndex);
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
  addOutTapBIP32Derivation(outIndex, d) {
    this.validateOutputIndex(outIndex);
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
    this.validateInputIndex(inIndex);
    const input = this.pset.inputs[inIndex];
    if (input.issuanceAssetEntropy && input.issuanceAssetEntropy.length > 0) {
      throw new Error('Input ' + inIndex + ' already has an issuance');
    }
  }
  validateReissuanceInput(inIndex) {
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
  validateOutputIndex(outIndex) {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('Output index out of range');
    }
  }
  validateInputIndex(inIndex) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
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
    if (!args.assetAddress) {
      throw new Error(
        'Asset address must be defined if asset amount is non-zero',
      );
    }
  }
  if (tokenAmount > 0) {
    if (!args.tokenAddress) {
      throw new Error(
        'Token address must be defined if token amount is non-zero',
      );
    }
  }
  if (!matchAddressesNetworkType(args.assetAddress, args.tokenAddress)) {
    throw new Error('Asset and token addresses must be of same network');
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
  if (!args.assetAddress) {
    throw new Error('Missing asset address');
  }
  if (!args.assetAddress) {
    throw new Error('Missing token address');
  }
  if (!matchAddressesNetworkType(args.assetAddress, args.tokenAddress)) {
    throw new Error(
      'Asset and token addresses must be both of same network and both confidential',
    );
  }
}
function matchAddressesNetworkType(addrA, addrB) {
  if (!addrA || !addrB) {
    return true;
  }
  if (typeof addrA === 'string' && typeof addrB === 'string') {
    const netA = (0, address_1.getNetwork)(addrA);
    const netB = (0, address_1.getNetwork)(addrB);
    return netA.name === netB.name;
  }
  return true;
}
function validatePartialSignature(psig) {
  if (psig.pubkey.length !== 33) {
    throw new Error('Invalid pubkey length');
  }
  bscript.signature.decode(psig.signature);
}
