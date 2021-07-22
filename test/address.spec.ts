import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as baddress from '../src/address';
import * as bscript from '../src/script';
import * as fixtures from './fixtures/address.json';

const NETWORKS = require('../src/networks');

describe('address', () => {
  describe('fromBase58Check', () => {
    fixtures.standard.forEach(f => {
      if (!f.base58check) return;

      it('decodes ' + f.base58check, () => {
        const decode = baddress.fromBase58Check(f.base58check);

        assert.strictEqual(decode.version, f.version);
        assert.strictEqual(decode.hash.toString('hex'), f.hash);
      });
    });

    // fixtures.invalid.fromBase58Check.forEach(f => {
    //   it('throws on ' + f.exception, () => {
    //     assert.throws(() => {
    //       baddress.fromBase58Check(f.address);
    //     }, new RegExp(f.address + ' ' + f.exception));
    //   });
    // });
  });

  describe('fromBech32', () => {
    fixtures.standard.forEach(f => {
      if (!f.bech32) return;

      it('decodes ' + f.bech32, () => {
        const actual = baddress.fromBech32(f.bech32);

        assert.strictEqual(actual.version, f.version);
        assert.strictEqual(actual.prefix, NETWORKS[f.network].bech32);
        assert.strictEqual(actual.data.toString('hex'), f.data);
      });
    });

    // fixtures.invalid.bech32.forEach(f => {
    //   it('decode fails for ' + f.address + '(' + f.exception + ')', () => {
    //     assert.throws(() => {
    //       baddress.fromBech32(f.address);
    //     }, new RegExp(f.exception));
    //   });
    // });
  });

  describe('fromBlech32', () => {
    fixtures.standard.forEach(f => {
      if (!f.bech32) return;

      it('decodes ' + f.confidentialAddress, () => {
        const actual = baddress.fromBlech32(f.confidentialAddress);
        const expected = Buffer.concat([
          Buffer.from([f.version, f.data!.length / 2]),
          Buffer.from(f.data!, 'hex'),
        ]).toString('hex');
        assert.strictEqual(actual.version, f.version);
        assert.strictEqual(actual.pubkey.toString('hex'), f.blindkey);
        assert.strictEqual(actual.data.toString('hex'), expected);
      });
    });

    // fixtures.invalid.bech32.forEach(f => {
    //   it('decode fails for ' + f.address + '(' + f.exception + ')', () => {
    //     assert.throws(() => {
    //       baddress.fromBech32(f.address);
    //     }, new RegExp(f.exception));
    //   });
    // });
  });

  describe('fromOutputScript', () => {
    fixtures.standard.forEach(f => {
      it('encodes ' + f.script.slice(0, 30) + '... (' + f.network + ')', () => {
        const script = bscript.fromASM(f.script);
        const address = baddress.fromOutputScript(script, NETWORKS[f.network]);

        assert.strictEqual(address, (f.base58check || f.bech32)!);
      });
    });

    // fixtures.invalid.fromOutputScript.forEach(f => {
    //   it('throws when ' + f.script.slice(0, 30) + '... ' + f.exception, () => {
    //     const script = bscript.fromASM(f.script);

    //     assert.throws(() => {
    //       baddress.fromOutputScript(script);
    //     }, new RegExp(f.exception));
    //   });
    // });
  });

  describe('fromConfidential', () => {
    fixtures.standard.forEach(f => {
      if (!f.confidentialAddress) return;

      it(
        'extract address from a confidential address ' + f.confidentialAddress,
        () => {
          const t = baddress.fromConfidential(f.confidentialAddress);

          assert.strictEqual(t.blindingKey.toString('hex'), f.blindkey);
          assert.strictEqual(
            t.unconfidentialAddress,
            (f.base58check || f.bech32)!,
          );
        },
      );
    });
  });

  describe('toBase58Check', () => {
    fixtures.standard.forEach(f => {
      if (!f.base58check) return;

      it('encodes ' + f.hash + ' (' + f.network + ')', () => {
        const address = baddress.toBase58Check(
          Buffer.from(f.hash, 'hex'),
          f.version,
        );

        assert.strictEqual(address, f.base58check);
      });
    });
  });

  describe('toBech32', () => {
    fixtures.bech32.forEach(f => {
      if (!f.address) return;
      const data = Buffer.from(f.data, 'hex');

      it('encode ' + f.address, () => {
        assert.deepStrictEqual(
          baddress.toBech32(data, f.version, f.prefix),
          f.address,
        );
      });
    });

    // fixtures.invalid.bech32.forEach((f: any) => {
    //   if (!f.prefix || f.version === undefined || f.data === undefined) return;

    //   it('encode fails (' + f.exception, () => {
    //     assert.throws(() => {
    //       baddress.toBech32(Buffer.from(f.data, 'hex'), f.version, f.prefix);
    //     }, new RegExp(f.exception));
    //   });
    // });
  });

  describe('toBlech32', () => {
    fixtures.blech32.forEach(f => {
      if (!f.address) return;
      const data = Buffer.concat([
        Buffer.from([f.version, f.data.length / 2]),
        Buffer.from(f.data, 'hex'),
      ]);
      const blindkey = Buffer.from(f.blindkey, 'hex');

      it('encode ' + f.address, () => {
        assert.deepStrictEqual(
          baddress.toBlech32(data, blindkey, f.prefix),
          f.address,
        );
      });
    });

    // fixtures.invalid.bech32.forEach((f: any) => {
    //   if (!f.prefix || f.version === undefined || f.data === undefined) return;

    //   it('encode fails (' + f.exception, () => {
    //     assert.throws(() => {
    //       baddress.toBech32(Buffer.from(f.data, 'hex'), f.version, f.prefix);
    //     }, new RegExp(f.exception));
    //   });
    // });
  });

  describe('toOutputScript', () => {
    fixtures.standard.forEach(f => {
      it('decodes ' + f.script.slice(0, 30) + '... (' + f.network + ')', () => {
        let script = baddress.toOutputScript(
          (f.base58check || f.bech32)!,
          NETWORKS[f.network],
        );

        assert.strictEqual(bscript.toASM(script), f.script);

        script = baddress.toOutputScript(
          f.confidentialAddress,
          NETWORKS[f.network],
        );
        assert.deepStrictEqual(bscript.toASM(script), f.script);
      });
    });

    // fixtures.invalid.toOutputScript.forEach(f => {
    //   it('throws when ' + f.exception, () => {
    //     assert.throws(() => {
    //       baddress.toOutputScript(f.address, f.network as any);
    //     }, new RegExp(f.address + ' ' + f.exception));
    //   });
    // });
  });

  describe('toConfidential', () => {
    fixtures.standard.forEach(f => {
      it(
        'create confidential address from ' +
          (f.base58check || f.bech32)! +
          ' and ' +
          f.blindkey,
        () => {
          const t = baddress.toConfidential(
            (f.base58check || f.bech32)!,
            Buffer.from(f.blindkey, 'hex'),
          );
          assert.strictEqual(t, f.confidentialAddress);
        },
      );
    });
  });
});
