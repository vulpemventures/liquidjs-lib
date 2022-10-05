export const hardenedKeyStart = 0x80000000;

export function decodeBip32Derivation(buf: Buffer): {
  masterFingerprint: Buffer;
  path: string;
} {
  if (buf.length % 4 !== 0 || buf.length / 4 - 1 < 1) {
    throw new Error('invalid BIP32 derivation format');
  }

  const masterFingerprint = buf.slice(0, 4);
  const steps: number[] = [];

  for (let i = 4; i < buf.length; i += 4) {
    steps.push(buf.slice(i, i + 4).readUInt32LE());
  }

  const path = stepsToString(steps);
  return { masterFingerprint, path };
}

export function encodeBIP32Derivation(
  masterFingerprint: Buffer,
  path: string,
): Buffer {
  const steps = path.split('/');
  const buf = Buffer.allocUnsafe(4 + 4 * steps.length);
  masterFingerprint.copy(buf, 0);

  let offset = 4;
  steps.forEach((step) => {
    const isHardened = step.slice(-1) === "'";
    let num = 0x7fffffff & parseInt(isHardened ? step.slice(0, -1) : step, 10);
    if (isHardened) num += hardenedKeyStart;
    buf.writeUInt32LE(num, offset);
    offset += 4;
  });

  return buf;
}

function stepsToString(steps: number[]): string {
  const stepsStr = steps.map((step) => stepToString(step));
  return stepsStr.join('/');
}

function stepToString(step: number): string {
  if (step < hardenedKeyStart) {
    return step.toString();
  }
  step -= hardenedKeyStart;
  return step.toString() + "'";
}
