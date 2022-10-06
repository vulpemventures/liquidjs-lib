import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as preFixtures from './fixtures/psetv2.json';
import { Pset } from '../ts_src/psetv2';

const initBuffers = (object: any): typeof preFixtures =>
  JSON.parse(JSON.stringify(object));

const fixtures = initBuffers(preFixtures);

describe('PSETv2', () => {
  describe('(De)serialization roundtrip', () => {
    describe('valid', () => {
      fixtures.roundtrip.valid.forEach((f) => {
        it(f.name, () => {
          const pset = Pset.fromBase64(f.base64);
          assert.strictEqual(
            pset.toBuffer().toString('hex'),
            Buffer.from(f.base64, 'base64').toString('hex'),
          );
        });
      });
    });
    describe('invalid', () => {
      fixtures.roundtrip.invalid.forEach((f) => {
        it(f.name, () => {
          let errMsg = '';
          try {
            Pset.fromBase64(f.base64);
          } catch (e) {
            errMsg = (e as Error).message;
          }
          assert.strictEqual(errMsg, f.expectedError);
        });
      });
    });
  });
});
