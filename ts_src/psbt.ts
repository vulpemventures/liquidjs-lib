import * as confidential from './confidential';
import * as varuint from 'bip174-liquid/src/lib/converter/varint';

import {
  Transaction as ITransaction,
  KeyValue,
  PartialSig,
  PsbtGlobalUpdate,
  PsbtInput,
  PsbtInputUpdate,
  PsbtOutput,
  PsbtOutputUpdate,
  TransactionFromBuffer,
  TransactionInput,
  WitnessUtxo,
} from 'bip174-liquid/src/lib/interfaces';
import { toOutputScript } from './address';
import { reverseBuffer } from './bufferutils';
import { hash160 } from './crypto';
import { Network, liquid as btcNetwork } from './networks';
import { Output, Transaction, ZERO } from './transaction';
import {
  Signer,
  SignerAsync,
  fromPrivateKey as ecPairFromPrivateKey,
  fromPublicKey as ecPairFromPublicKey,
} from './ecpair';
import {
  AddIssuanceArgs,
  calculateAsset,
  calculateReissuanceToken,
  generateEntropy,
  hasTokenAmount,
  Issuance,
  newIssuance,
  validateAddIssuanceArgs,
} from './issuance';
import * as payments from './payments';
import * as bscript from './script';
import { IssuanceBlindingKeys } from './types';

import { Psbt as PsbtBase } from 'bip174-liquid';
import { checkForInput } from 'bip174-liquid/src/lib/utils';

const _randomBytes = require('randombytes');

/**
 * These are the default arguments for a Psbt instance.
 */
const DEFAULT_OPTS: PsbtOpts = {
  /**
   * A bitcoinjs Network object. This is only used if you pass an `address`
   * parameter to addOutput. Otherwise it is not needed and can be left default.
   */
  network: btcNetwork,
  /**
   * When extractTransaction is called, the fee rate is checked.
   * THIS IS NOT TO BE RELIED ON.
   * It is only here as a last ditch effort to prevent sending a 500 BTC fee etc.
   */
  maximumFeeRate: 5000, // satoshi per byte
};

/**
 * Psbt class can parse and generate a PSBT binary based off of the BIP174.
 * There are 6 roles that this class fulfills. (Explained in BIP174)
 *
 * Creator: This can be done with `new Psbt()`
 * Updater: This can be done with `psbt.addInput(input)`, `psbt.addInputs(inputs)`,
 *   `psbt.addOutput(output)`, `psbt.addOutputs(outputs)` when you are looking to
 *   add new inputs and outputs to the PSBT, and `psbt.updateGlobal(itemObject)`,
 *   `psbt.updateInput(itemObject)`, `psbt.updateOutput(itemObject)`
 *   addInput requires hash: Buffer | string; and index: number; as attributes
 *   and can also include any attributes that are used in updateInput method.
 *   addOutput requires script: Buffer; and value: number; and likewise can include
 *   data for updateOutput.
 *   For a list of what attributes should be what types. Check the bip174 library.
 *   Also, check the integration tests for some examples of usage.
 * Signer: There are a few methods. signAllInputs and signAllInputsAsync, which will search all input
 *   information for your pubkey or pubkeyhash, and only sign inputs where it finds
 *   your info. Or you can explicitly sign a specific input with signInput and
 *   signInputAsync. For the async methods you can create a SignerAsync object
 *   and use something like a hardware wallet to sign with. (You must implement this)
 * Combiner: psbts can be combined easily with `psbt.combine(psbt2, psbt3, psbt4 ...)`
 *   the psbt calling combine will always have precedence when a conflict occurs.
 *   Combine checks if the internal bitcoin transaction is the same, so be sure that
 *   all sequences, version, locktime, etc. are the same before combining.
 * Input Finalizer: This role is fairly important. Not only does it need to construct
 *   the input scriptSigs and witnesses, but it SHOULD verify the signatures etc.
 *   Before running `psbt.finalizeAllInputs()` please run `psbt.validateSignaturesOfAllInputs()`
 *   Running any finalize method will delete any data in the input(s) that are no longer
 *   needed due to the finalized scripts containing the information.
 * Transaction Extractor: This role will perform some checks before returning a
 *   Transaction object. Such as fee rate not being larger than maximumFeeRate etc.
 */
export class Psbt {
  static fromBase64(data: string, opts: PsbtOptsOptional = {}): Psbt {
    const buffer = Buffer.from(data, 'base64');
    return this.fromBuffer(buffer, opts);
  }

  static fromHex(data: string, opts: PsbtOptsOptional = {}): Psbt {
    const buffer = Buffer.from(data, 'hex');
    return this.fromBuffer(buffer, opts);
  }

  static fromBuffer(buffer: Buffer, opts: PsbtOptsOptional = {}): Psbt {
    const psbtBase = PsbtBase.fromBuffer(buffer, transactionFromBuffer);
    const psbt = new Psbt(opts, psbtBase);
    checkTxForDupeIns(psbt.__CACHE.__TX, psbt.__CACHE);
    return psbt;
  }

  private __CACHE: PsbtCache;
  private opts: PsbtOpts;

  constructor(
    opts: PsbtOptsOptional = {},
    readonly data: PsbtBase = new PsbtBase(new PsbtTransaction()),
  ) {
    // set defaults
    this.opts = Object.assign({}, DEFAULT_OPTS, opts);
    this.__CACHE = {
      __NON_WITNESS_UTXO_TX_CACHE: [],
      __NON_WITNESS_UTXO_BUF_CACHE: [],
      __TX_IN_CACHE: {},
      __TX: (this.data.globalMap.unsignedTx as PsbtTransaction).tx,
    };
    if (this.data.inputs.length === 0) this.setVersion(2);

    // Make data hidden when enumerating
    const dpew = (
      obj: any,
      attr: string,
      enumerable: boolean,
      writable: boolean,
    ): any =>
      Object.defineProperty(obj, attr, {
        enumerable,
        writable,
      });
    dpew(this, '__CACHE', false, true);
    dpew(this, 'opts', false, true);
  }

  get inputCount(): number {
    return this.data.inputs.length;
  }

  combine(...those: Psbt[]): this {
    this.data.combine(...those.map(o => o.data));
    return this;
  }

  clone(): Psbt {
    // TODO: more efficient cloning
    const res = Psbt.fromBuffer(this.data.toBuffer());
    res.opts = JSON.parse(JSON.stringify(this.opts));
    return res;
  }

  setMaximumFeeRate(satoshiPerByte: number): void {
    check32Bit(satoshiPerByte); // 42.9 BTC per byte IS excessive... so throw
    this.opts.maximumFeeRate = satoshiPerByte;
  }

  setVersion(version: number): this {
    check32Bit(version);
    checkInputsForPartialSig(this.data.inputs, 'setVersion');
    const c = this.__CACHE;
    c.__TX.version = version;
    c.__EXTRACTED_TX = undefined;
    return this;
  }

  setLocktime(locktime: number): this {
    check32Bit(locktime);
    checkInputsForPartialSig(this.data.inputs, 'setLocktime');
    const c = this.__CACHE;
    c.__TX.locktime = locktime;
    c.__EXTRACTED_TX = undefined;
    return this;
  }

  setInputSequence(inputIndex: number, sequence: number): this {
    check32Bit(sequence);
    checkInputsForPartialSig(this.data.inputs, 'setInputSequence');
    const c = this.__CACHE;
    if (c.__TX.ins.length <= inputIndex) {
      throw new Error('Input index too high');
    }
    c.__TX.ins[inputIndex].sequence = sequence;
    c.__EXTRACTED_TX = undefined;
    return this;
  }

  addInputs(inputDatas: PsbtInputExtended[]): this {
    inputDatas.forEach(inputData => this.addInput(inputData));
    return this;
  }

  addInput(inputData: PsbtInputExtended): this {
    if (
      arguments.length > 1 ||
      !inputData ||
      inputData.hash === undefined ||
      inputData.index === undefined
    ) {
      throw new Error(
        `Invalid arguments for Psbt.addInput. ` +
        `Requires single object with at least [hash] and [index]`,
      );
    }
    checkInputsForPartialSig(this.data.inputs, 'addInput');
    const c = this.__CACHE;
    this.data.addInput(inputData);
    const txIn = c.__TX.ins[c.__TX.ins.length - 1];
    checkTxInputCache(c, txIn);

    const inputIndex = this.data.inputs.length - 1;
    const input = this.data.inputs[inputIndex];
    if (input.nonWitnessUtxo) {
      addNonWitnessTxCache(this.__CACHE, input, inputIndex);
    }
    c.__FEE = undefined;
    c.__FEE_RATE = undefined;
    c.__EXTRACTED_TX = undefined;
    return this;
  }

  addIssuance(args: AddIssuanceArgs, inputIndex?: number): this {
    validateAddIssuanceArgs(args); // throw an error if args are invalid

    if (inputIndex && !this.data.inputs[inputIndex]) {
      throw new Error(`The input ${inputIndex} does not exist.`);
      // check if the input is available for issuance.
    } else {
      // verify if there is at least one input available.
      if (this.__CACHE.__TX.ins.filter(i => !i.issuance).length === 0)
        throw new Error(
          'transaction needs at least one input without issuance data.',
        );
      // search and extract the input index.
      inputIndex = this.__CACHE.__TX.ins.findIndex(i => !i.issuance);
    }

    if (this.__CACHE.__TX.ins[inputIndex].issuance)
      throw new Error(`The input ${inputIndex} already has issuance data.`);

    const { hash, index } = this.__CACHE.__TX.ins[inputIndex];

    // create an issuance object using the vout and the args
    const issuance: Issuance = newIssuance(
      args.assetAmount,
      args.tokenAmount,
      args.precision,
      args.contract,
    );

    // generate the entropy
    const entropy: Buffer = generateEntropy(
      { txHash: hash, vout: index },
      issuance.assetEntropy,
    );

    // add the issuance to the input.
    this.__CACHE.__TX.ins[inputIndex].issuance = issuance;

    const asset = Buffer.concat([Buffer.of(args.confidential ? 0x0a : 0x01), calculateAsset(entropy)]);
    const assetScript = toOutputScript(args.assetAddress, args.net);

    // send the asset amount to the asset address.
    this.addOutput({
      value: issuance.assetAmount,
      script: assetScript,
      asset,
      nonce: Buffer.from('00', 'hex'),
    });

    // check if the token amount is not 0
    if (args.tokenAmount !== 0) {
      if (!args.tokenAddress)
        throw new Error("tokenAddress can't be undefined if tokenAmount > 0");

      const token = calculateReissuanceToken(
        entropy,
        args.confidential,
      );
      const tokenScript = toOutputScript(args.tokenAddress, args.net);

      // send the token amount to the token address.
      this.addOutput({
        script: tokenScript,
        value: issuance.tokenAmount,
        asset: Buffer.concat([Buffer.of(0x01), token]),
        nonce: Buffer.from('00', 'hex'),
      });
    }

    return this;
  }

  addOutputs(outputDatas: PsbtOutputExtended[]): this {
    outputDatas.forEach(outputData => this.addOutput(outputData));
    return this;
  }

  addOutput(outputData: PsbtOutputExtended): this {
    if (
      arguments.length > 1 ||
      !outputData ||
      outputData.value === undefined ||
      ((outputData as any).address === undefined &&
        (outputData as any).script === undefined)
    ) {
      throw new Error(
        `Invalid arguments for Psbt.addOutput. ` +
        `Requires single object with at least [script or address] and [value]`,
      );
    }
    checkInputsForPartialSig(this.data.inputs, 'addOutput');
    const { address } = outputData as any;
    if (typeof address === 'string') {
      const { network } = this.opts;
      const script = toOutputScript(address, network);
      outputData = Object.assign(outputData, { script });
    }
    const c = this.__CACHE;
    this.data.addOutput(outputData);
    c.__FEE = undefined;
    c.__FEE_RATE = undefined;
    c.__EXTRACTED_TX = undefined;
    return this;
  }

  extractTransaction(disableFeeCheck?: boolean): Transaction {
    if (!this.data.inputs.every(isFinalized)) throw new Error('Not finalized');
    const c = this.__CACHE;
    if (!disableFeeCheck) {
      checkFees(this, c, this.opts);
    }
    if (c.__EXTRACTED_TX) return c.__EXTRACTED_TX;
    const tx = c.__TX.clone();
    inputFinalizeGetAmts(this.data.inputs, tx, c, true);
    return tx;
  }

  getFeeRate(): number {
    return getTxCacheValue(
      '__FEE_RATE',
      'fee rate',
      this.data.inputs,
      this.__CACHE,
    )!;
  }

  getFee(): number {
    return getTxCacheValue('__FEE', 'fee', this.data.inputs, this.__CACHE)!;
  }

  finalizeAllInputs(): this {
    checkForInput(this.data.inputs, 0); // making sure we have at least one
    range(this.data.inputs.length).forEach(idx => this.finalizeInput(idx));
    return this;
  }

  finalizeInput(inputIndex: number): this {
    const input = checkForInput(this.data.inputs, inputIndex);
    const { script, isP2SH, isP2WSH, isSegwit } = getScriptFromInput(
      inputIndex,
      input,
      this.__CACHE,
    );
    if (!script) throw new Error(`No script found for input #${inputIndex}`);

    const scriptType = classifyScript(script);
    if (!canFinalize(input, script, scriptType))
      throw new Error(`Can not finalize input #${inputIndex}`);

    checkPartialSigSighashes(input);

    const { finalScriptSig, finalScriptWitness } = getFinalScripts(
      script,
      scriptType,
      input.partialSig!,
      isSegwit,
      isP2SH,
      isP2WSH,
    );

    if (finalScriptSig) this.data.updateInput(inputIndex, { finalScriptSig });
    if (finalScriptWitness)
      this.data.updateInput(inputIndex, { finalScriptWitness });
    if (!finalScriptSig && !finalScriptWitness)
      throw new Error(`Unknown error finalizing input #${inputIndex}`);

    this.data.clearFinalizedInput(inputIndex);
    return this;
  }

  validateSignaturesOfAllInputs(): boolean {
    checkForInput(this.data.inputs, 0); // making sure we have at least one
    const results = range(this.data.inputs.length).map(idx =>
      this.validateSignaturesOfInput(idx),
    );
    return results.reduce((final, res) => res === true && final, true);
  }

  validateSignaturesOfInput(inputIndex: number, pubkey?: Buffer): boolean {
    const input = this.data.inputs[inputIndex];
    const partialSig = (input || {}).partialSig;
    if (!input || !partialSig || partialSig.length < 1)
      throw new Error('No signatures to validate');
    const mySigs = pubkey
      ? partialSig.filter(sig => sig.pubkey.equals(pubkey))
      : partialSig;
    if (mySigs.length < 1) throw new Error('No signatures for this pubkey');
    const results: boolean[] = [];
    let hashCache: Buffer;
    let scriptCache: Buffer;
    let sighashCache: number;
    for (const pSig of mySigs) {
      const sig = bscript.signature.decode(pSig.signature);
      const { hash, script } =
        sighashCache! !== sig.hashType
          ? getHashForSig(
            inputIndex,
            Object.assign({}, input, { sighashType: sig.hashType }),
            this.__CACHE,
          )
          : { hash: hashCache!, script: scriptCache! };
      sighashCache = sig.hashType;
      hashCache = hash;
      scriptCache = script;
      checkScriptForPubkey(pSig.pubkey, script, 'verify');
      const keypair = ecPairFromPublicKey(pSig.pubkey);
      results.push(keypair.verify(hash, sig.signature));
    }
    return results.every(res => res === true);
  }

  signAllInputsHD(
    hdKeyPair: HDSigner,
    sighashTypes: number[] = [Transaction.SIGHASH_ALL],
  ): this {
    if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
      throw new Error('Need HDSigner to sign input');
    }

    const results: boolean[] = [];
    for (const i of range(this.data.inputs.length)) {
      try {
        this.signInputHD(i, hdKeyPair, sighashTypes);
        results.push(true);
      } catch (err) {
        results.push(false);
      }
    }
    if (results.every(v => v === false)) {
      throw new Error('No inputs were signed');
    }
    return this;
  }

  signAllInputsHDAsync(
    hdKeyPair: HDSigner | HDSignerAsync,
    sighashTypes: number[] = [Transaction.SIGHASH_ALL],
  ): Promise<void> {
    return new Promise(
      (resolve, reject): any => {
        if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
          return reject(new Error('Need HDSigner to sign input'));
        }

        const results: boolean[] = [];
        const promises: Array<Promise<void>> = [];
        for (const i of range(this.data.inputs.length)) {
          promises.push(
            this.signInputHDAsync(i, hdKeyPair, sighashTypes).then(
              () => {
                results.push(true);
              },
              () => {
                results.push(false);
              },
            ),
          );
        }
        return Promise.all(promises).then(() => {
          if (results.every(v => v === false)) {
            return reject(new Error('No inputs were signed'));
          }
          resolve();
        });
      },
    );
  }

  signInputHD(
    inputIndex: number,
    hdKeyPair: HDSigner,
    sighashTypes: number[] = [Transaction.SIGHASH_ALL],
  ): this {
    if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
      throw new Error('Need HDSigner to sign input');
    }
    const signers = getSignersFromHD(
      inputIndex,
      this.data.inputs,
      hdKeyPair,
    ) as Signer[];
    signers.forEach(signer => this.signInput(inputIndex, signer, sighashTypes));
    return this;
  }

  signInputHDAsync(
    inputIndex: number,
    hdKeyPair: HDSigner | HDSignerAsync,
    sighashTypes: number[] = [Transaction.SIGHASH_ALL],
  ): Promise<void> {
    return new Promise(
      (resolve, reject): any => {
        if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
          return reject(new Error('Need HDSigner to sign input'));
        }
        const signers = getSignersFromHD(
          inputIndex,
          this.data.inputs,
          hdKeyPair,
        );
        const promises = signers.map(signer =>
          this.signInputAsync(inputIndex, signer, sighashTypes),
        );
        return Promise.all(promises)
          .then(() => {
            resolve();
          })
          .catch(reject);
      },
    );
  }

  signAllInputs(
    keyPair: Signer,
    sighashTypes: number[] = [Transaction.SIGHASH_ALL],
  ): this {
    if (!keyPair || !keyPair.publicKey)
      throw new Error('Need Signer to sign input');

    // TODO: Add a pubkey/pubkeyhash cache to each input
    // as input information is added, then eventually
    // optimize this method.
    const results: boolean[] = [];
    for (const i of range(this.data.inputs.length)) {
      try {
        this.signInput(i, keyPair, sighashTypes);
        results.push(true);
      } catch (err) {
        results.push(false);
      }
    }
    if (results.every(v => v === false)) {
      throw new Error('No inputs were signed');
    }
    return this;
  }

  signAllInputsAsync(
    keyPair: Signer | SignerAsync,
    sighashTypes: number[] = [Transaction.SIGHASH_ALL],
  ): Promise<void> {
    return new Promise(
      (resolve, reject): any => {
        if (!keyPair || !keyPair.publicKey)
          return reject(new Error('Need Signer to sign input'));

        // TODO: Add a pubkey/pubkeyhash cache to each input
        // as input information is added, then eventually
        // optimize this method.
        const results: boolean[] = [];
        const promises: Array<Promise<void>> = [];
        for (const [i] of this.data.inputs.entries()) {
          promises.push(
            this.signInputAsync(i, keyPair, sighashTypes).then(
              () => {
                results.push(true);
              },
              () => {
                results.push(false);
              },
            ),
          );
        }
        return Promise.all(promises).then(() => {
          if (results.every(v => v === false)) {
            return reject(new Error('No inputs were signed'));
          }
          resolve();
        });
      },
    );
  }

  signInput(
    inputIndex: number,
    keyPair: Signer,
    sighashTypes: number[] = [Transaction.SIGHASH_ALL],
  ): this {
    if (!keyPair || !keyPair.publicKey)
      throw new Error('Need Signer to sign input');
    const { hash, sighashType } = getHashAndSighashType(
      this.data.inputs,
      inputIndex,
      keyPair.publicKey,
      this.__CACHE,
      sighashTypes,
    );

    const partialSig = [
      {
        pubkey: keyPair.publicKey,
        signature: bscript.signature.encode(keyPair.sign(hash), sighashType),
      },
    ];

    this.data.updateInput(inputIndex, { partialSig });
    return this;
  }

  signInputAsync(
    inputIndex: number,
    keyPair: Signer | SignerAsync,
    sighashTypes: number[] = [Transaction.SIGHASH_ALL],
  ): Promise<void> {
    return new Promise(
      (resolve, reject): void => {
        if (!keyPair || !keyPair.publicKey)
          return reject(new Error('Need Signer to sign input'));
        const { hash, sighashType } = getHashAndSighashType(
          this.data.inputs,
          inputIndex,
          keyPair.publicKey,
          this.__CACHE,
          sighashTypes,
        );

        Promise.resolve(keyPair.sign(hash)).then(signature => {
          const partialSig = [
            {
              pubkey: keyPair.publicKey,
              signature: bscript.signature.encode(signature, sighashType),
            },
          ];

          this.data.updateInput(inputIndex, { partialSig });
          resolve();
        });
      },
    );
  }

  toBuffer(): Buffer {
    return this.data.toBuffer();
  }

  toHex(): string {
    return this.data.toHex();
  }

  toBase64(): string {
    return this.data.toBase64();
  }

  updateGlobal(updateData: PsbtGlobalUpdate): this {
    this.data.updateGlobal(updateData);
    return this;
  }

  updateInput(inputIndex: number, updateData: PsbtInputUpdate): this {
    if (updateData.witnessUtxo) {
      const { witnessUtxo } = updateData;
      const script = Buffer.isBuffer(witnessUtxo.script)
        ? witnessUtxo.script
        : Buffer.from(witnessUtxo.script, 'hex');
      const value = Buffer.isBuffer(witnessUtxo.value)
        ? witnessUtxo.value
        : typeof witnessUtxo.value === 'string'
          ? Buffer.from(witnessUtxo.value, 'hex')
          : confidential.satoshiToConfidentialValue(witnessUtxo.value);
      // if the asset is a string, by checking the first byte we can determine if
      // it's an asset commitment, in this case we decode the hex string as buffer,
      // or if it's an asset hash, in this case we put the unconf prefix in front of the reversed the buffer
      const asset = Buffer.isBuffer(witnessUtxo.asset)
        ? witnessUtxo.asset
        : (witnessUtxo.asset as string).startsWith('0a') ||
          (witnessUtxo.asset as string).startsWith('0b')
          ? Buffer.from(witnessUtxo.asset, 'hex')
          : Buffer.concat([
            Buffer.alloc(1, 1),
            reverseBuffer(Buffer.from(witnessUtxo.asset, 'hex')),
          ]);
      const nonce = witnessUtxo.nonce
        ? Buffer.isBuffer(witnessUtxo.nonce)
          ? witnessUtxo.nonce
          : Buffer.from(witnessUtxo.nonce, 'hex')
        : Buffer.alloc(1, 0);
      const rangeProof = witnessUtxo.rangeProof
        ? Buffer.isBuffer(witnessUtxo.rangeProof)
          ? witnessUtxo.rangeProof
          : Buffer.from(witnessUtxo.rangeProof, 'hex')
        : undefined;
      const surjectionProof = witnessUtxo.surjectionProof
        ? Buffer.isBuffer(witnessUtxo.surjectionProof)
          ? witnessUtxo.surjectionProof
          : Buffer.from(witnessUtxo.surjectionProof, 'hex')
        : undefined;

      updateData = Object.assign(updateData, {
        witnessUtxo: {
          script,
          value,
          asset,
          nonce,
          rangeProof,
          surjectionProof,
        },
      });
    }

    this.data.updateInput(inputIndex, updateData);
    if (updateData.nonWitnessUtxo) {
      addNonWitnessTxCache(
        this.__CACHE,
        this.data.inputs[inputIndex],
        inputIndex,
      );
    }
    return this;
  }

  updateOutput(outputIndex: number, updateData: PsbtOutputUpdate): this {
    this.data.updateOutput(outputIndex, updateData);
    return this;
  }

  blindOutputs(
    blindingDataLike: BlindingDataLike[],
    blindingPubkeys: Buffer[],
    opts?: RngOpts,
  ): Promise<this> {
    return this.rawBlindOutputs(
      blindingDataLike,
      blindingPubkeys,
      undefined,
      undefined,
      opts,
    );
  }

  blindOutputsByIndex(
    inputsBlindingData: Map<number, BlindingDataLike>,
    outputsBlindingPubKeys: Map<number, Buffer>,
    issuancesBlindingKeys?: Map<number, IssuanceBlindingKeys>,
    opts?: RngOpts,
  ): Promise<this> {
    const blindingPrivKeysArgs = range(this.__CACHE.__TX.ins.length).map(
      (inputIndex: number) => inputsBlindingData.get(inputIndex),
    );
    const blindingPrivKeysIssuancesArgs = issuancesBlindingKeys
      ? range(this.__CACHE.__TX.ins.length).map((inputIndex: number) =>
        issuancesBlindingKeys.get(inputIndex),
      )
      : [];
    const outputIndexes: number[] = [];
    const blindingPublicKey: Buffer[] = [];

    for (const [outputIndex, pubBlindingKey] of outputsBlindingPubKeys) {
      outputIndexes.push(outputIndex);
      blindingPublicKey.push(pubBlindingKey);
    }

    return this.rawBlindOutputs(
      blindingPrivKeysArgs,
      blindingPublicKey,
      blindingPrivKeysIssuancesArgs,
      outputIndexes,
      opts,
    );
  }

  addUnknownKeyValToGlobal(keyVal: KeyValue): this {
    this.data.addUnknownKeyValToGlobal(keyVal);
    return this;
  }

  addUnknownKeyValToInput(inputIndex: number, keyVal: KeyValue): this {
    this.data.addUnknownKeyValToInput(inputIndex, keyVal);
    return this;
  }

  addUnknownKeyValToOutput(outputIndex: number, keyVal: KeyValue): this {
    this.data.addUnknownKeyValToOutput(outputIndex, keyVal);
    return this;
  }

  clearFinalizedInput(inputIndex: number): this {
    this.data.clearFinalizedInput(inputIndex);
    return this;
  }

  private unblindInputsToIssuanceBlindingData(
    issuanceBlindingPrivKeys: Array<IssuanceBlindingKeys | undefined> = [],
  ): confidential.UnblindOutputResult[] {
    const pseudoBlindingDataFromIssuances: confidential.UnblindOutputResult[] = [];

    let inputIndex = 0;
    for (const input of this.__CACHE.__TX.ins) {
      if (input.issuance) {
        const isConfidentialIssuance =
          issuanceBlindingPrivKeys && issuanceBlindingPrivKeys[inputIndex]
            ? true
            : false;
        const entropy = generateEntropy(
          { txHash: input.hash, vout: input.index },
          input.issuance.assetEntropy,
        );
        const asset = calculateAsset(entropy);
        const value = confidential
          .confidentialValueToSatoshi(input.issuance.assetAmount)
          .toString(10);

        const assetBlindingData = {
          value,
          asset,
          assetBlindingFactor: ZERO,
          valueBlindingFactor: isConfidentialIssuance ? randomBytes() : ZERO,
        };

        pseudoBlindingDataFromIssuances.push(assetBlindingData);

        if (hasTokenAmount(input.issuance)) {
          const token = calculateReissuanceToken(
            entropy,
            isConfidentialIssuance,
          );
          const tokenValue = confidential
            .confidentialValueToSatoshi(input.issuance.tokenAmount)
            .toString(10);

          const tokenBlindingData = {
            value: tokenValue,
            asset: token,
            assetBlindingFactor: ZERO,
            valueBlindingFactor: isConfidentialIssuance ? randomBytes() : ZERO,
          };

          pseudoBlindingDataFromIssuances.push(tokenBlindingData);
        }
      }

      inputIndex++;
    }

    return pseudoBlindingDataFromIssuances;
  }

  private async blindInputs(
    blindingData: confidential.UnblindOutputResult[],
    issuanceBlindingPrivKeys: Array<IssuanceBlindingKeys | undefined> = [],
  ): Promise<this> {
    if (!issuanceBlindingPrivKeys || issuanceBlindingPrivKeys.length === 0)
      return this; // skip if no issuance blind keys

    function getBlindingFactors(
      asset: Buffer,
    ): confidential.UnblindOutputResult {
      for (const blindData of blindingData) {
        if (asset.equals(blindData.asset)) {
          return blindData;
        }
      }
      throw new Error(
        'no blinding factors generated for pseudo issuance inputs',
      );
    }

    // loop over inputs and create blindingData object in case of issuance
    let inputIndex = 0;
    for (const input of this.__CACHE.__TX.ins) {
      if (input.issuance) {
        if (!issuanceBlindingPrivKeys[inputIndex]) {
          // check if the user has provided blinding key
          inputIndex++;
          continue;
        }

        const entropy = generateEntropy(
          { txHash: input.hash, vout: input.index },
          input.issuance.assetEntropy,
        );
        const issuedAsset = calculateAsset(entropy);
        const blindingFactorsAsset = getBlindingFactors(issuedAsset);

        const assetCommitment = await confidential.assetCommitment(
          blindingFactorsAsset.asset,
          blindingFactorsAsset.assetBlindingFactor,
        );

        const valueCommitment = await confidential.valueCommitment(
          blindingFactorsAsset.value,
          assetCommitment,
          blindingFactorsAsset.valueBlindingFactor,
        );

        const assetBlindingPrivateKey = issuanceBlindingPrivKeys[inputIndex]
          ? issuanceBlindingPrivKeys[inputIndex]!.assetKey
          : undefined;

        if (!assetBlindingPrivateKey) {
          throw new Error(
            `missing asset blinding private key for issuance #${inputIndex}`,
          );
        }

        const issuanceRangeProof = await confidential.rangeProofWithoutNonceHash(
          blindingFactorsAsset.value,
          assetBlindingPrivateKey,
          blindingFactorsAsset.asset,
          blindingFactorsAsset.assetBlindingFactor,
          blindingFactorsAsset.valueBlindingFactor,
          valueCommitment,
          Buffer.alloc(0),
          '1',
          0,
          52,
        );

        this.__CACHE.__TX.ins[
          inputIndex
        ].issuanceRangeProof = issuanceRangeProof;
        this.__CACHE.__TX.ins[
          inputIndex
        ].issuance!.assetAmount = valueCommitment;

        if (hasTokenAmount(input.issuance)) {
          const token = calculateReissuanceToken(entropy, true);
          const blindingFactorsToken = getBlindingFactors(issuedAsset);

          const issuedTokenCommitment = await confidential.assetCommitment(
            token,
            blindingFactorsToken.assetBlindingFactor,
          );
          const valueCommitment = await confidential.valueCommitment(
            blindingFactorsToken.value,
            issuedTokenCommitment,
            blindingFactorsToken.valueBlindingFactor,
          );

          const inflationRangeProof = await confidential.rangeProofWithoutNonceHash(
            blindingFactorsToken.value,
            issuanceBlindingPrivKeys[inputIndex]!.tokenKey,
            token,
            blindingFactorsToken.assetBlindingFactor,
            blindingFactorsToken.valueBlindingFactor,
            valueCommitment,
            Buffer.alloc(0),
            '1',
            0,
            52,
          );

          this.__CACHE.__TX.ins[
            inputIndex
          ].inflationRangeProof = inflationRangeProof;
          this.__CACHE.__TX.ins[
            inputIndex
          ].issuance!.tokenAmount = valueCommitment;
        }
      }

      inputIndex++;
    }

    return this;
  }

  private async blindOutputsRaw(
    blindingData: confidential.UnblindOutputResult[],
    blindingPubkeys: Buffer[],
    outputIndexes: number[],
    opts?: RngOpts,
  ): Promise<this> {
    // get data (satoshis & asset) outputs to blind
    const outputsData = outputIndexes.map((index: number) => {
      const output = this.__CACHE.__TX.outs[index];

      // prevent blinding the fee output
      if (output.script.length === 0)
        throw new Error("cant't blind the fee output");

      const value = confidential
        .confidentialValueToSatoshi(output.value)
        .toString(10);
      return [value, output.asset.slice(1)] as [string, Buffer];
    });

    // compute the outputs blinders
    const outputsBlindingData = await computeOutputsBlindingData(
      blindingData,
      outputsData,
    );

    // use blinders to compute proofs & commitments
    let indexInArray = 0;
    for (const outputIndex of outputIndexes) {
      const randomSeed = randomBytes(opts);
      const ephemeralPrivKey = randomBytes(opts);
      const outputNonce = ecPairFromPrivateKey(ephemeralPrivKey).publicKey;
      const outputBlindingData = outputsBlindingData[indexInArray];

      // commitments
      const assetCommitment = await confidential.assetCommitment(
        outputBlindingData.asset,
        outputBlindingData.assetBlindingFactor,
      );

      const valueCommitment = await confidential.valueCommitment(
        outputBlindingData.value,
        assetCommitment,
        outputBlindingData.valueBlindingFactor,
      );

      // proofs
      const rangeProof = await confidential.rangeProof(
        outputBlindingData.value,
        blindingPubkeys[indexInArray],
        ephemeralPrivKey,
        outputBlindingData.asset,
        outputBlindingData.assetBlindingFactor,
        outputBlindingData.valueBlindingFactor,
        valueCommitment,
        this.__CACHE.__TX.outs[outputIndex].script,
      );

      const surjectionProof = await confidential.surjectionProof(
        outputBlindingData.asset,
        outputBlindingData.assetBlindingFactor,
        blindingData.map(({ asset }) => asset),
        blindingData.map(({ assetBlindingFactor }) => assetBlindingFactor),
        randomSeed,
      );

      // set commitments & proofs & nonce
      this.__CACHE.__TX.outs[outputIndex].asset = assetCommitment;
      this.__CACHE.__TX.outs[outputIndex].value = valueCommitment;
      this.__CACHE.__TX.setOutputNonce(outputIndex, outputNonce);
      this.__CACHE.__TX.setOutputRangeProof(outputIndex, rangeProof);
      this.__CACHE.__TX.setOutputSurjectionProof(outputIndex, surjectionProof);
      indexInArray++;
    }

    return this;
  }

  private async rawBlindOutputs(
    blindingDataLike: BlindingDataLike[],
    blindingPubkeys: Buffer[],
    issuanceBlindingPrivKeys: Array<IssuanceBlindingKeys | undefined> = [],
    outputIndexes?: number[],
    opts?: RngOpts,
  ): Promise<this> {
    if (
      this.data.inputs.some(
        (v: PsbtInput) => !v.nonWitnessUtxo && !v.witnessUtxo,
      )
    )
      throw new Error(
        'All inputs must contain a non witness utxo or a witness utxo',
      );

    if (this.__CACHE.__TX.ins.length !== blindingDataLike.length) {
      throw new Error(
        'blindingDataLike length does not match the number of inputs (undefined for unconfidential utxo)',
      );
    }

    if (!outputIndexes) {
      outputIndexes = [];
      // fill the outputIndexes array with all the output index (except the fee output)
      this.__CACHE.__TX.outs.forEach((out: Output, index: number) => {
        if (out.script.length > 0) outputIndexes!.push(index);
      });
    }

    if (outputIndexes.length !== blindingPubkeys.length)
      throw new Error(
        'not enough blinding public keys to blind the requested outputs',
      );

    const witnesses = this.data.inputs.map(
      (input: PsbtInput, index: number) => {
        if (input.nonWitnessUtxo) {
          const prevTx = nonWitnessUtxoTxFromCache(this.__CACHE, input, index);
          const prevoutIndex = this.__CACHE.__TX.ins[index].index;
          return prevTx.outs[prevoutIndex] as WitnessUtxo;
        }

        if (input.witnessUtxo) {
          return input.witnessUtxo;
        }

        throw new Error('input data needs witness utxo or nonwitness utxo');
      },
    );

    const inputsBlindingData = await Promise.all(
      blindingDataLike.map((data, i) => toBlindingData(data, witnesses[i])),
    );

    const pseudoInputsBlindingData = this.unblindInputsToIssuanceBlindingData(
      issuanceBlindingPrivKeys,
    );

    const totalBlindingData = inputsBlindingData.concat(pseudoInputsBlindingData)

    await this.blindOutputsRaw(
      totalBlindingData,
      blindingPubkeys,
      outputIndexes,
      opts,
    );
    await this.blindInputs(totalBlindingData, issuanceBlindingPrivKeys);

    this.__CACHE.__FEE = undefined;
    this.__CACHE.__FEE_RATE = undefined;
    this.__CACHE.__EXTRACTED_TX = undefined;

    return this;
  }
}

interface PsbtCache {
  __NON_WITNESS_UTXO_TX_CACHE: Transaction[];
  __NON_WITNESS_UTXO_BUF_CACHE: Buffer[];
  __TX_IN_CACHE: { [index: string]: number };
  __TX: Transaction;
  __FEE_RATE?: number;
  __FEE?: number;
  __EXTRACTED_TX?: Transaction;
}

interface PsbtOptsOptional {
  network?: Network;
  maximumFeeRate?: number;
}

interface PsbtOpts {
  network: Network;
  maximumFeeRate: number;
}

interface PsbtInputExtended extends PsbtInput, TransactionInput { }

type PsbtOutputExtended = PsbtOutputExtendedScript | PsbtOutputExtendedAddress;

interface PsbtOutputExtendedScript extends PsbtOutput {
  script: string | Buffer;
  asset: string | Buffer;
  value: number | Buffer;
  nonce?: string | Buffer;
}

interface PsbtOutputExtendedAddress extends PsbtOutput {
  address: string;
  asset: string | Buffer;
  value: number | Buffer;
  nonce?: string | Buffer;
}

interface HDSignerBase {
  /**
   * DER format compressed publicKey buffer
   */
  publicKey: Buffer;
  /**
   * The first 4 bytes of the sha256-ripemd160 of the publicKey
   */
  fingerprint: Buffer;
}

interface HDSigner extends HDSignerBase {
  /**
   * The path string must match /^m(\/\d+'?)+$/
   * ex. m/44'/0'/0'/1/23 levels with ' must be hard derivations
   */
  derivePath(path: string): HDSigner;
  /**
   * Input hash (the "message digest") for the signature algorithm
   * Return a 64 byte signature (32 byte r and 32 byte s in that order)
   */
  sign(hash: Buffer): Buffer;
}

/**
 * Same as above but with async sign method
 */
interface HDSignerAsync extends HDSignerBase {
  derivePath(path: string): HDSignerAsync;
  sign(hash: Buffer): Promise<Buffer>;
}

/**
 * This function is needed to pass to the bip174 base class's fromBuffer.
 * It takes the "transaction buffer" portion of the psbt buffer and returns a
 * Transaction (From the bip174 library) interface.
 */
const transactionFromBuffer: TransactionFromBuffer = (
  buffer: Buffer,
): ITransaction => new PsbtTransaction(buffer);

/**
 * This class implements the Transaction interface from bip174 library.
 * It contains a liquidjs-lib Transaction object.
 */
class PsbtTransaction implements ITransaction {
  tx: Transaction;
  constructor(buffer: Buffer = Buffer.from([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])) {
    this.tx = Transaction.fromBuffer(buffer);
    checkTxEmpty(this.tx);
    Object.defineProperty(this, 'tx', {
      enumerable: false,
      writable: true,
    });
  }

  getInputOutputCounts(): {
    inputCount: number;
    outputCount: number;
  } {
    return {
      inputCount: this.tx.ins.length,
      outputCount: this.tx.outs.length,
    };
  }

  addInput(input: any): void {
    if (
      (input as any).hash === undefined ||
      (input as any).index === undefined ||
      (!Buffer.isBuffer((input as any).hash) &&
        typeof (input as any).hash !== 'string') ||
      typeof (input as any).index !== 'number'
    ) {
      throw new Error('Error adding input.');
    }
    const hash =
      typeof input.hash === 'string'
        ? reverseBuffer(Buffer.from(input.hash, 'hex'))
        : input.hash;
    this.tx.addInput(hash, input.index, input.sequence);
  }

  addOutput(output: any): void {
    if (
      (output as any).script === undefined ||
      (!Buffer.isBuffer((output as any).script) &&
        typeof output.script !== 'string') ||
      (output as any).value === undefined ||
      (!Buffer.isBuffer((output as any).value) &&
        typeof (output as any).value !== 'number') ||
      (output as any).asset === undefined ||
      (!Buffer.isBuffer((output as any).asset) &&
        typeof output.asset !== 'string')
    ) {
      throw new Error('Error adding output.');
    }
    const nonce = Buffer.alloc(1, 0);
    const script = Buffer.isBuffer(output.script)
      ? output.script
      : Buffer.from(output.script, 'hex');
    const value = Buffer.isBuffer(output.value)
      ? output.value
      : confidential.satoshiToConfidentialValue(output.value);
    const asset = Buffer.isBuffer(output.asset)
      ? output.asset
      : Buffer.concat([
        Buffer.alloc(1, 1),
        reverseBuffer(Buffer.from(output.asset, 'hex')),
      ]);
    this.tx.addOutput(script, value, asset, nonce);
  }

  toBuffer(): Buffer {
    return this.tx.toBuffer();
  }
}

function canFinalize(
  input: PsbtInput,
  script: Buffer,
  scriptType: string,
): boolean {
  switch (scriptType) {
    case 'pubkey':
    case 'pubkeyhash':
    case 'witnesspubkeyhash':
      return hasSigs(1, input.partialSig);
    case 'multisig':
      const p2ms = payments.p2ms({ output: script });
      return hasSigs(p2ms.m!, input.partialSig, p2ms.pubkeys);
    default:
      return false;
  }
}

function hasSigs(
  neededSigs: number,
  partialSig?: any[],
  pubkeys?: Buffer[],
): boolean {
  if (!partialSig) return false;
  let sigs: any;
  if (pubkeys) {
    sigs = pubkeys
      .map(pkey => {
        const pubkey = ecPairFromPublicKey(pkey, { compressed: true })
          .publicKey;
        return partialSig.find(pSig => pSig.pubkey.equals(pubkey));
      })
      .filter(v => !!v);
  } else {
    sigs = partialSig;
  }
  if (sigs.length > neededSigs) throw new Error('Too many signatures');
  return sigs.length === neededSigs;
}

function isFinalized(input: PsbtInput): boolean {
  return !!input.finalScriptSig || !!input.finalScriptWitness;
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
const isP2MS = isPaymentFactory(payments.p2ms);
const isP2PK = isPaymentFactory(payments.p2pk);
const isP2PKH = isPaymentFactory(payments.p2pkh);
const isP2WPKH = isPaymentFactory(payments.p2wpkh);
const isP2WSHScript = isPaymentFactory(payments.p2wsh);

function check32Bit(num: number): void {
  if (
    typeof num !== 'number' ||
    num !== Math.floor(num) ||
    num > 0xffffffff ||
    num < 0
  ) {
    throw new Error('Invalid 32 bit integer');
  }
}

function checkFees(psbt: Psbt, cache: PsbtCache, opts: PsbtOpts): void {
  const feeRate = cache.__FEE_RATE || psbt.getFeeRate();
  const vsize = cache.__EXTRACTED_TX!.virtualSize();
  const satoshis = feeRate * vsize;
  if (feeRate >= opts.maximumFeeRate) {
    throw new Error(
      `Warning: You are paying around ${(satoshis / 1e8).toFixed(8)} in ` +
      `fees, which is ${feeRate} satoshi per byte for a transaction ` +
      `with a VSize of ${vsize} bytes (segwit counted as 0.25 byte per ` +
      `byte). Use setMaximumFeeRate method to raise your threshold, or ` +
      `pass true to the first arg of extractTransaction.`,
    );
  }
}

function checkInputsForPartialSig(inputs: PsbtInput[], action: string): void {
  inputs.forEach(input => {
    let throws = false;
    let pSigs: PartialSig[] = [];
    if ((input.partialSig || []).length === 0) {
      if (!input.finalScriptSig && !input.finalScriptWitness) return;
      pSigs = getPsigsFromInputFinalScripts(input);
    } else {
      pSigs = input.partialSig!;
    }
    pSigs.forEach(pSig => {
      const { hashType } = bscript.signature.decode(pSig.signature);
      const whitelist: string[] = [];
      const isAnyoneCanPay = hashType & Transaction.SIGHASH_ANYONECANPAY;
      if (isAnyoneCanPay) whitelist.push('addInput');
      const hashMod = hashType & 0x1f;
      switch (hashMod) {
        case Transaction.SIGHASH_ALL:
          break;
        case Transaction.SIGHASH_SINGLE:
        case Transaction.SIGHASH_NONE:
          whitelist.push('addOutput');
          whitelist.push('setInputSequence');
          break;
      }
      if (whitelist.indexOf(action) === -1) {
        throws = true;
      }
    });
    if (throws) {
      throw new Error('Can not modify transaction, signatures exist.');
    }
  });
}

function checkPartialSigSighashes(input: PsbtInput): void {
  if (!input.sighashType || !input.partialSig) return;
  const { partialSig, sighashType } = input;
  partialSig.forEach(pSig => {
    const { hashType } = bscript.signature.decode(pSig.signature);
    if (sighashType !== hashType) {
      throw new Error('Signature sighash does not match input sighash type');
    }
  });
}

function checkScriptForPubkey(
  pubkey: Buffer,
  script: Buffer,
  action: string,
): void {
  const pubkeyHash = hash160(pubkey);

  const decompiled = bscript.decompile(script);
  if (decompiled === null) throw new Error('Unknown script error');

  const hasKey = decompiled.some(element => {
    if (typeof element === 'number') return false;
    return element.equals(pubkey) || element.equals(pubkeyHash);
  });

  if (!hasKey) {
    throw new Error(
      `Can not ${action} for this input with the key ${pubkey.toString('hex')}`,
    );
  }
}

function checkTxEmpty(tx: Transaction): void {
  const isEmpty = tx.ins.every(
    input => input.script && input.script.length === 0,
  );
  if (!isEmpty) {
    throw new Error('Format Error: Transaction ScriptSigs are not empty');
  }
  // if (tx.flag === 1 && tx.witnessIn.length > 0) {
  //   throw new Error('Format Error: Transaction WitnessScriptSigs are not empty');
  // }
}

function checkTxForDupeIns(tx: Transaction, cache: PsbtCache): void {
  tx.ins.forEach(input => {
    checkTxInputCache(cache, input);
  });
}

function checkTxInputCache(
  cache: PsbtCache,
  input: { hash: Buffer; index: number },
): void {
  const key =
    reverseBuffer(Buffer.from(input.hash)).toString('hex') + ':' + input.index;
  if (cache.__TX_IN_CACHE[key]) throw new Error('Duplicate input detected.');
  cache.__TX_IN_CACHE[key] = 1;
}

function scriptCheckerFactory(
  payment: any,
  paymentScriptName: string,
): (idx: number, spk: Buffer, rs: Buffer) => void {
  return (
    inputIndex: number,
    scriptPubKey: Buffer,
    redeemScript: Buffer,
  ): void => {
    const redeemScriptOutput = payment({
      redeem: { output: redeemScript },
    }).output as Buffer;

    if (!scriptPubKey.equals(redeemScriptOutput)) {
      throw new Error(
        `${paymentScriptName} for input #${inputIndex} doesn't match the scriptPubKey in the prevout`,
      );
    }
  };
}
const checkRedeemScript = scriptCheckerFactory(payments.p2sh, 'Redeem script');
const checkWitnessScript = scriptCheckerFactory(
  payments.p2wsh,
  'Witness script',
);

type TxCacheNumberKey = '__FEE_RATE' | '__FEE';
function getTxCacheValue(
  key: TxCacheNumberKey,
  name: string,
  inputs: PsbtInput[],
  c: PsbtCache,
): number | undefined {
  if (!inputs.every(isFinalized))
    throw new Error(`PSBT must be finalized to calculate ${name}`);
  if (key === '__FEE_RATE' && c.__FEE_RATE) return c.__FEE_RATE;
  if (key === '__FEE' && c.__FEE) return c.__FEE;
  let tx: Transaction;
  let mustFinalize = true;
  if (c.__EXTRACTED_TX) {
    tx = c.__EXTRACTED_TX;
    mustFinalize = false;
  } else {
    tx = c.__TX.clone();
  }
  inputFinalizeGetAmts(inputs, tx, c, mustFinalize);
  if (key === '__FEE_RATE') return c.__FEE_RATE!;
  else if (key === '__FEE') return c.__FEE!;
}

function getFinalScripts(
  script: Buffer,
  scriptType: string,
  partialSig: PartialSig[],
  isSegwit: boolean,
  isP2SH: boolean,
  isP2WSH: boolean,
): {
  finalScriptSig: Buffer | undefined;
  finalScriptWitness: Buffer | undefined;
} {
  let finalScriptSig: Buffer | undefined;
  let finalScriptWitness: Buffer | undefined;

  // Wow, the payments API is very handy
  const payment: payments.Payment = getPayment(script, scriptType, partialSig);
  const p2wsh = !isP2WSH ? null : payments.p2wsh({ redeem: payment });
  const p2sh = !isP2SH ? null : payments.p2sh({ redeem: p2wsh || payment });

  if (isSegwit) {
    if (p2wsh) {
      finalScriptWitness = witnessStackToScriptWitness(p2wsh.witness!);
    } else {
      finalScriptWitness = witnessStackToScriptWitness(payment.witness!);
    }
    if (p2sh) {
      finalScriptSig = p2sh.input;
    }
  } else {
    if (p2sh) {
      finalScriptSig = p2sh.input;
    } else {
      finalScriptSig = payment.input;
    }
  }
  return {
    finalScriptSig,
    finalScriptWitness,
  };
}

function getHashAndSighashType(
  inputs: PsbtInput[],
  inputIndex: number,
  pubkey: Buffer,
  cache: PsbtCache,
  sighashTypes: number[],
): {
  hash: Buffer;
  sighashType: number;
} {
  const input = checkForInput(inputs, inputIndex);
  const { hash, sighashType, script } = getHashForSig(
    inputIndex,
    input,
    cache,
    sighashTypes,
  );
  checkScriptForPubkey(pubkey, script, 'sign');
  return {
    hash,
    sighashType,
  };
}

function getHashForSig(
  inputIndex: number,
  input: PsbtInput,
  cache: PsbtCache,
  sighashTypes?: number[],
): {
  script: Buffer;
  hash: Buffer;
  sighashType: number;
} {
  const unsignedTx = cache.__TX;
  const sighashType = input.sighashType || Transaction.SIGHASH_ALL;
  if (sighashTypes && sighashTypes.indexOf(sighashType) < 0) {
    const str = sighashTypeToString(sighashType);
    throw new Error(
      `Sighash type is not allowed. Retry the sign method passing the ` +
      `sighashTypes array of whitelisted types. Sighash type: ${str}`,
    );
  }
  let hash: Buffer;
  let script: Buffer;

  if (input.nonWitnessUtxo) {
    const nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(
      cache,
      input,
      inputIndex,
    );

    const prevoutHash = unsignedTx.ins[inputIndex].hash;
    const utxoHash = nonWitnessUtxoTx.getHash();

    // If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
    if (!prevoutHash.equals(utxoHash)) {
      throw new Error(
        `Non-witness UTXO hash for input #${inputIndex} doesn't match the hash specified in the prevout`,
      );
    }

    const prevoutIndex = unsignedTx.ins[inputIndex].index;
    const prevout = nonWitnessUtxoTx.outs[prevoutIndex] as Output;

    if (input.redeemScript) {
      // If a redeemScript is provided, the scriptPubKey must be for that redeemScript
      checkRedeemScript(inputIndex, prevout.script, input.redeemScript);
      script = input.redeemScript;
    } else {
      script = prevout.script;
    }

    if (isP2WSHScript(script)) {
      if (!input.witnessScript)
        throw new Error('Segwit input needs witnessScript if not P2WPKH');
      checkWitnessScript(inputIndex, script, input.witnessScript);
      hash = unsignedTx.hashForWitnessV0(
        inputIndex,
        input.witnessScript,
        prevout.value,
        sighashType,
      );
      script = input.witnessScript;
    } else if (isP2WPKH(script)) {
      // P2WPKH uses the P2PKH template for prevoutScript when signing
      const signingScript = payments.p2pkh({ hash: script.slice(2) }).output!;
      hash = unsignedTx.hashForWitnessV0(
        inputIndex,
        signingScript,
        prevout.value,
        sighashType,
      );
    } else {
      hash = unsignedTx.hashForSignature(inputIndex, script, sighashType);
    }
  } else if (input.witnessUtxo) {
    let _script: Buffer; // so we don't shadow the `let script` above
    if (input.redeemScript) {
      // If a redeemScript is provided, the scriptPubKey must be for that redeemScript
      checkRedeemScript(
        inputIndex,
        input.witnessUtxo.script,
        input.redeemScript,
      );
      _script = input.redeemScript;
    } else {
      _script = input.witnessUtxo.script;
    }
    if (isP2WPKH(_script)) {
      // P2WPKH uses the P2PKH template for prevoutScript when signing
      const signingScript = payments.p2pkh({ hash: _script.slice(2) }).output!;
      hash = unsignedTx.hashForWitnessV0(
        inputIndex,
        signingScript,
        input.witnessUtxo.value,
        sighashType,
      );
      script = _script;
    } else if (isP2WSHScript(_script)) {
      if (!input.witnessScript)
        throw new Error('Segwit input needs witnessScript if not P2WPKH');
      checkWitnessScript(inputIndex, _script, input.witnessScript);
      hash = unsignedTx.hashForWitnessV0(
        inputIndex,
        input.witnessScript,
        input.witnessUtxo.value,
        sighashType,
      );
      // want to make sure the script we return is the actual meaningful script
      script = input.witnessScript;
    } else {
      throw new Error(
        `Input #${inputIndex} has witnessUtxo but non-segwit script: ` +
        `${_script.toString('hex')}`,
      );
    }
  } else {
    throw new Error('Need a Utxo input item for signing');
  }
  return {
    script,
    sighashType,
    hash,
  };
}

function getPayment(
  script: Buffer,
  scriptType: string,
  partialSig: PartialSig[],
): payments.Payment {
  let payment: payments.Payment;
  switch (scriptType) {
    case 'multisig':
      const sigs = getSortedSigs(script, partialSig);
      payment = payments.p2ms({
        output: script,
        signatures: sigs,
      });
      break;
    case 'pubkey':
      payment = payments.p2pk({
        output: script,
        signature: partialSig[0].signature,
      });
      break;
    case 'pubkeyhash':
      payment = payments.p2pkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
      break;
    case 'witnesspubkeyhash':
      payment = payments.p2wpkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
      break;
  }
  return payment!;
}

function getPsigsFromInputFinalScripts(input: PsbtInput): PartialSig[] {
  const scriptItems = !input.finalScriptSig
    ? []
    : bscript.decompile(input.finalScriptSig) || [];
  const witnessItems = !input.finalScriptWitness
    ? []
    : bscript.decompile(input.finalScriptWitness) || [];
  return scriptItems
    .concat(witnessItems)
    .filter(item => {
      return Buffer.isBuffer(item) && bscript.isCanonicalScriptSignature(item);
    })
    .map(sig => ({ signature: sig })) as PartialSig[];
}

interface GetScriptReturn {
  script: Buffer | null;
  isSegwit: boolean;
  isP2SH: boolean;
  isP2WSH: boolean;
}

function getScriptFromInput(
  inputIndex: number,
  input: PsbtInput,
  cache: PsbtCache,
): GetScriptReturn {
  const unsignedTx = cache.__TX;
  const res: GetScriptReturn = {
    script: null,
    isSegwit: false,
    isP2SH: false,
    isP2WSH: false,
  };
  res.isP2SH = !!input.redeemScript;
  res.isP2WSH = !!input.witnessScript;
  if (input.witnessScript) {
    res.script = input.witnessScript;
  } else if (input.redeemScript) {
    res.script = input.redeemScript;
  } else {
    if (input.nonWitnessUtxo) {
      const nonWitnessUtxoTx = nonWitnessUtxoTxFromCache(
        cache,
        input,
        inputIndex,
      );
      const prevoutIndex = unsignedTx.ins[inputIndex].index;
      res.script = nonWitnessUtxoTx.outs[prevoutIndex].script;
    } else if (input.witnessUtxo) {
      res.script = input.witnessUtxo.script;
    }
  }
  if (input.witnessScript || isP2WPKH(res.script!)) {
    res.isSegwit = true;
  }
  return res;
}

function getSignersFromHD(
  inputIndex: number,
  inputs: PsbtInput[],
  hdKeyPair: HDSigner | HDSignerAsync,
): Array<Signer | SignerAsync> {
  const input = checkForInput(inputs, inputIndex);
  if (!input.bip32Derivation || input.bip32Derivation.length === 0) {
    throw new Error('Need bip32Derivation to sign with HD');
  }
  const myDerivations = input.bip32Derivation
    .map(bipDv => {
      if (bipDv.masterFingerprint.equals(hdKeyPair.fingerprint)) {
        return bipDv;
      } else {
        return;
      }
    })
    .filter(v => !!v);
  if (myDerivations.length === 0) {
    throw new Error(
      'Need one bip32Derivation masterFingerprint to match the HDSigner fingerprint',
    );
  }
  const signers: Array<Signer | SignerAsync> = myDerivations.map(bipDv => {
    const node = hdKeyPair.derivePath(bipDv!.path);
    if (!bipDv!.pubkey.equals(node.publicKey)) {
      throw new Error('pubkey did not match bip32Derivation');
    }
    return node;
  });
  return signers;
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

function scriptWitnessToWitnessStack(buffer: Buffer): Buffer[] {
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

function sighashTypeToString(sighashType: number): string {
  let text =
    sighashType & Transaction.SIGHASH_ANYONECANPAY
      ? 'SIGHASH_ANYONECANPAY | '
      : '';
  const sigMod = sighashType & 0x1f;
  switch (sigMod) {
    case Transaction.SIGHASH_ALL:
      text += 'SIGHASH_ALL';
      break;
    case Transaction.SIGHASH_SINGLE:
      text += 'SIGHASH_SINGLE';
      break;
    case Transaction.SIGHASH_NONE:
      text += 'SIGHASH_NONE';
      break;
  }
  return text;
}

function witnessStackToScriptWitness(witness: Buffer[]): Buffer {
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

function addNonWitnessTxCache(
  cache: PsbtCache,
  input: PsbtInput,
  inputIndex: number,
): void {
  cache.__NON_WITNESS_UTXO_BUF_CACHE[inputIndex] = input.nonWitnessUtxo!;

  const tx = Transaction.fromBuffer(input.nonWitnessUtxo!);
  cache.__NON_WITNESS_UTXO_TX_CACHE[inputIndex] = tx;

  const self = cache;
  const selfIndex = inputIndex;
  delete input.nonWitnessUtxo;
  Object.defineProperty(input, 'nonWitnessUtxo', {
    enumerable: true,
    get(): Buffer {
      const buf = self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex];
      const txCache = self.__NON_WITNESS_UTXO_TX_CACHE[selfIndex];
      if (buf !== undefined) {
        return buf;
      } else {
        const newBuf = txCache.toBuffer();
        self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = newBuf;
        return newBuf;
      }
    },
    set(data: Buffer): void {
      self.__NON_WITNESS_UTXO_BUF_CACHE[selfIndex] = data;
    },
  });
}

function inputFinalizeGetAmts(
  inputs: PsbtInput[],
  tx: Transaction,
  cache: PsbtCache,
  mustFinalize: boolean,
): void {
  inputs.forEach((input, idx) => {
    if (mustFinalize && input.finalScriptSig)
      tx.ins[idx].script = input.finalScriptSig;
    if (mustFinalize && input.finalScriptWitness) {
      tx.ins[idx].witness = scriptWitnessToWitnessStack(
        input.finalScriptWitness,
      );
    }
  });
  if (tx.ins.some(x => x.witness.length !== 0)) {
    tx.flag = 1;
  }
  const bytes = tx.virtualSize();
  const fee = 2 * bytes;
  cache.__FEE = fee;
  cache.__EXTRACTED_TX = tx;
  cache.__FEE_RATE = Math.floor(fee / bytes);
}

function nonWitnessUtxoTxFromCache(
  cache: PsbtCache,
  input: PsbtInput,
  inputIndex: number,
): Transaction {
  const c = cache.__NON_WITNESS_UTXO_TX_CACHE;
  if (!c[inputIndex]) {
    addNonWitnessTxCache(cache, input, inputIndex);
  }
  return c[inputIndex];
}

function classifyScript(script: Buffer): string {
  if (isP2WPKH(script)) return 'witnesspubkeyhash';
  if (isP2PKH(script)) return 'pubkeyhash';
  if (isP2MS(script)) return 'multisig';
  if (isP2PK(script)) return 'pubkey';
  return 'nonstandard';
}

function range(n: number): number[] {
  return [...Array(n).keys()];
}

interface RngOpts {
  rng?(arg0: number): Buffer;
}

function randomBytes(options?: RngOpts): Buffer {
  if (options === undefined) options = {};
  const rng = options.rng || _randomBytes;
  return rng(32);
}

// Buffer = privateBlindingKey for conf inputs
// BlindingData = blinders for already unblinded conf inputs
// undefined = unconfidential inputs
export type BlindingDataLike =
  | Buffer
  | confidential.UnblindOutputResult
  | undefined;

/**
 * Compute outputs blinders
 * @param inputsBlindingData the transaction inputs blinding data
 * @param outputsData data = [satoshis, asset] of output to blind ([string Buffer])
 * @returns an array of BlindingData[] corresponding of blinders to blind outputs specified in outputsData
 */
export async function computeOutputsBlindingData(
  inputsBlindingData: confidential.UnblindOutputResult[],
  outputsData: Array<[string, Buffer]>,
): Promise<confidential.UnblindOutputResult[]> {
  const outputsBlindingData: confidential.UnblindOutputResult[] = [];
  outputsData.slice(0, outputsData.length - 1).forEach(([satoshis, asset]) => {
    const blindingData: confidential.UnblindOutputResult = {
      value: satoshis,
      asset,
      valueBlindingFactor: randomBytes(),
      assetBlindingFactor: randomBytes(),
    };
    outputsBlindingData.push(blindingData);
  });

  const [lastOutputValue, lastOutputAsset] = outputsData[
    outputsData.length - 1
  ];
  const finalBlindingData: confidential.UnblindOutputResult = {
    value: lastOutputValue,
    asset: lastOutputAsset,
    assetBlindingFactor: randomBytes(),
    valueBlindingFactor: Buffer.from([]), // invalid at this step
  };

  // values
  const inputsValues = inputsBlindingData.map(({ value }) => value);
  const outputsValues = outputsData
    .map(([amount]) => amount)
    .concat(lastOutputValue);
  // asset blinders
  const inputsAssetBlinders = inputsBlindingData.map(
    ({ assetBlindingFactor }) => assetBlindingFactor,
  );
  const outputsAssetBlinders = outputsBlindingData
    .map(({ assetBlindingFactor }) => assetBlindingFactor)
    .concat(finalBlindingData.assetBlindingFactor);
  // value blinders
  const inputsAmountBlinders = inputsBlindingData.map(
    ({ valueBlindingFactor }) => valueBlindingFactor,
  );
  const outputsAmountBlinders = outputsBlindingData.map(
    ({ valueBlindingFactor }) => valueBlindingFactor,
  );

  // compute output final amount blinder
  const finalAmountBlinder = await confidential.valueBlindingFactor(
    inputsValues,
    outputsValues,
    inputsAssetBlinders,
    outputsAssetBlinders,
    inputsAmountBlinders,
    outputsAmountBlinders,
  );

  finalBlindingData.valueBlindingFactor = finalAmountBlinder;
  outputsBlindingData.push(finalBlindingData);

  return outputsBlindingData;
}

/**
 * toBlindingData convert a BlindingDataLike to UnblindOutputResult
 * @param blindDataLike blinding data "like" associated to a specific input I
 * @param witnessUtxo the prevout of the input I
 */
export async function toBlindingData(
  blindDataLike: BlindingDataLike,
  witnessUtxo?: WitnessUtxo,
): Promise<confidential.UnblindOutputResult> {
  if (!blindDataLike) {
    if (!witnessUtxo) throw new Error('need witnessUtxo');
    return getUnconfidentialWitnessUtxoBlindingData(witnessUtxo);
  }

  if (Buffer.isBuffer(blindDataLike)) {
    if (!witnessUtxo) throw new Error('need witnessUtxo');
    return confidential.unblindOutputWithKey(witnessUtxo, blindDataLike);
  }

  return blindDataLike;
}

function getUnconfidentialWitnessUtxoBlindingData(
  prevout: WitnessUtxo,
): confidential.UnblindOutputResult {
  const unblindedInputBlindingData: confidential.UnblindOutputResult = {
    value: confidential.confidentialValueToSatoshi(prevout.value).toString(10),
    valueBlindingFactor: ZERO,
    asset: prevout.asset.slice(1),
    assetBlindingFactor: ZERO,
  };

  return unblindedInputBlindingData;
}
