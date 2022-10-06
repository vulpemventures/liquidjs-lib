import * as assert from 'assert';
import { describe, it } from 'mocha';
import { ElementsValue } from '../src';
import * as fixtures from './fixtures/value.json';

describe('value', () => {
  describe('fromNumber', () => {
    const fromNumber = fixtures.fromNumber;
    it('valid', () => {
      fromNumber.valid.forEach((f) => {
        const v = ElementsValue.fromNumber(f.value);
        assert.deepStrictEqual(v.hex, f.expected);
      });
    });
    it('invalid', () => {
      fromNumber.invalid.forEach((f) => {
        assert.throws(() => {
          ElementsValue.fromNumber(f.value);
        }, new Error(f.expectedError));
      });
    });
  });

  describe('fromHex', () => {
    const fromHex = fixtures.fromHex;
    it('valid', () => {
      fromHex.valid.forEach((f) => {
        const v = ElementsValue.fromHex(f.hex);
        if (f.isCommitment) {
          assert.deepStrictEqual(v.hex, f.expected);
        } else {
          assert.deepStrictEqual(v.number, f.expected);
        }
      });
    });
    it('invalid', () => {
      fromHex.invalid.forEach((f) => {
        assert.throws(() => {
          ElementsValue.fromHex(f.hex);
        }, new Error(f.expectedError));
      });
    });
  });
});
