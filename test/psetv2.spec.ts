import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as preFixtures from './fixtures/psetv2.json';
import { Pset } from '../src/psetv2';

const initBuffers = (object: any): typeof preFixtures =>
  JSON.parse(JSON.stringify(object));

const fixtures = initBuffers(preFixtures);

describe('PSETv2', () => {
  describe('(De)serialization roundtrip', () => {
    fixtures.roundtrip.forEach(f => {
      it(f.name, () => {
        const pset = Pset.fromBase64(f.base64);
        assert.strictEqual(pset.toBase64(), f.base64);
      });
    });
  });
});
