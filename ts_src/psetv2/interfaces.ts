export interface Xpub {
  extendedKey: Buffer;
  masterFingerprint: Buffer;
  derivationPath: string;
}

export interface PartialSig {
  pubkey: Buffer;
  signature: Buffer;
}

export interface Bip32Derivation {
  masterFingerprint: Buffer;
  pubkey: Buffer;
  path: string;
}

export interface WitnessUtxo {
  script: Buffer;
  value: number;
  nonce: Buffer;
  asset: Buffer;
  rangeProof?: Buffer;
  surjectionProof?: Buffer;
}
