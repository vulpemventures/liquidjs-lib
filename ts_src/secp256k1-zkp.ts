type Ecdh = (pubkey: Uint8Array, scalar: Uint8Array) => Uint8Array;

// TODO: make this an extension of ecpair's TinySecpInterface + privateMul.
interface Ec {
  prvkeyNegate: (key: Uint8Array) => Uint8Array;
  prvkeyTweakAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  prvkeyTweakMul: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
}

interface Generator {
  generate: (seed: Uint8Array) => Uint8Array;
  generateBlinded(key: Uint8Array, blind: Uint8Array): Uint8Array;
}

interface Pedersen {
  commitment(
    value: string,
    generator: Uint8Array,
    blinder: Uint8Array,
  ): Uint8Array;
  blindGeneratorBlindSum(
    values: Array<string>,
    valueBlinders: Array<Uint8Array>,
    assetBlinders: Array<Uint8Array>,
    nInputs: number,
  ): Uint8Array;
}

interface RangeProof {
  info(proof: Uint8Array): {
    exp: string;
    mantissa: string;
    minValue: string;
    maxValue: string;
  };
  verify(
    proof: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    script?: Uint8Array,
  ): boolean;
  sign(
    value: string,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    valueBlinder: Uint8Array,
    nonce: Uint8Array,
    minValue?: string,
    base10Exp?: string,
    minBits?: string,
    message?: Uint8Array,
    script?: Uint8Array,
  ): Uint8Array;
  rewind(
    proof: Uint8Array,
    valueCommitment: Uint8Array,
    assetCommitment: Uint8Array,
    nonce: Uint8Array,
    script?: Uint8Array,
  ): {
    value: string;
    minValue: string;
    maxValue: string;
    blinder: Uint8Array;
    message: Uint8Array;
  };
}

interface SurjectionProof {
  initialize: (
    inputTags: Array<Uint8Array>,
    outputTag: Uint8Array,
    maxIterations: number,
    seed: Uint8Array,
  ) => {
    proof: Uint8Array;
    inputIndex: number;
  };
  generate: (
    proof: Uint8Array,
    inputTags: Array<Uint8Array>,
    outputTag: Uint8Array,
    inputIndex: number,
    inputBlindingKey: Uint8Array,
    outputBlindingKey: Uint8Array,
  ) => Uint8Array;
  verify: (
    proof: Uint8Array,
    inputTags: Array<Uint8Array>,
    outputTag: Uint8Array,
  ) => boolean;
}

export interface ZKPInterface {
  ecdh: Ecdh;
  ec: Ec;
  surjectionproof: SurjectionProof;
  rangeproof: RangeProof;
  pedersen: Pedersen;
  generator: Generator;
}
