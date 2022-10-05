import * as assert from 'assert';
import { describe, it } from 'mocha';
import { AssetHash } from '../src/asset';
import * as fixtures from './fixtures/asset.json';

describe('asset', () => {
  describe('fromHex', () => {
    it('valid', () => {
      fixtures.fromHex.valid.forEach((f) => {
        const v = AssetHash.fromHex(f.hex);
        assert.deepStrictEqual(v.hex, f.expected);
      });
    });
    it('invalid', () => {
      fixtures.fromHex.invalid.forEach((f) => {
        assert.throws(() => {
          AssetHash.fromHex(f.hex);
        }, new Error(f.expectedError));
      });
    });
  });
});
