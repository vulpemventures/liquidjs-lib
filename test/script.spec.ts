import * as assert from 'assert';
import { describe, it } from 'mocha';
import { script } from '../ts_src';

describe.only('script', () => {
  describe('toASM', () => {
    it('converts OP_CHECKLOCKTIMEVERIFY correctly', () => {
      const asm = 'OP_CHECKLOCKTIMEVERIFY';
      const scrpt = script.fromASM(asm);
      assert.strictEqual(script.toASM(scrpt), asm);
    });
    it('converts OP_CHECKSEQUENCEVERIFY correctly', () => {
      const asm = 'OP_CHECKSEQUENCEVERIFY';
      const scrpt = script.fromASM(asm);
      assert.strictEqual(script.toASM(scrpt), asm);
    });
  });
});
