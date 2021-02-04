import * as assert from 'assert';
import { describe, it } from 'mocha';
import {
  // bip32,
  ECPair,
  networks as NETWORKS,
  Psbt,
} from '..';
const { satoshiToConfidentialValue } = require('../src/confidential');
const bscript = require('../src/script');
import * as preFixtures from './fixtures/psbt.json';

const initBuffers = (object: any): typeof preFixtures =>
  JSON.parse(JSON.stringify(object), (_, value) => {
    const regex = new RegExp(/^Buffer.from\(['"](.*)['"], ['"](.*)['"]\)$/);
    const result = regex.exec(value);
    if (!result) return value;

    const data = result[1];
    const encoding = result[2];

    return Buffer.from(data, encoding as BufferEncoding);
  });

const fixtures = initBuffers(preFixtures);

const upperCaseFirstLetter = (str: string): string =>
  str.replace(/^./, s => s.toUpperCase());

describe('Psbt', () => {
  describe('BIP174 Test Vectors', () => {
    fixtures.bip174.creator.forEach((f: any) => {
      it('Creates expected PSBT', () => {
        const psbt = new Psbt();
        for (const input of f.inputs) {
          psbt.addInput(input);
        }
        for (const output of f.outputs) {
          const script =
            output.script.length > 0
              ? bscript.fromASM(output.script)
              : output.script;
          psbt.addOutput({ ...output, script });
        }
        assert.strictEqual(psbt.toBase64(), f.result);
      });
    });

    fixtures.bip174.updater.forEach(f => {
      it('Updates PSBT to the expected result', () => {
        const psbt = Psbt.fromBase64(f.psbt);

        for (const inputOrOutput of ['input', 'output']) {
          const fixtureData = (f as any)[`${inputOrOutput}Data`];
          if (fixtureData) {
            for (const [i, data] of fixtureData.entries()) {
              const txt = upperCaseFirstLetter(inputOrOutput);
              if (
                typeof data === 'object' &&
                data.hasOwnProperty('redeemScript')
              ) {
                data.redeemScript = Buffer.from(data.redeemScript, 'hex');
              }
              (psbt as any)[`update${txt}`](i, data);
            }
          }
        }
        assert.strictEqual(psbt.toBase64(), f.result);
      });
    });

    fixtures.bip174.signer.forEach(f => {
      it('Signs PSBT to the expected result', () => {
        const psbt = Psbt.fromBase64(f.psbt);

        f.keys.forEach(({ inputToSign, WIF }) => {
          const keyPair = ECPair.fromWIF(WIF, NETWORKS.regtest);
          psbt.signInput(inputToSign, keyPair);
        });

        assert.strictEqual(psbt.toBase64(), f.result);
      });
    });

    fixtures.bip174.finalizer.forEach(f => {
      it('Finalizes PSBT to the expected result', () => {
        const psbt = Psbt.fromBase64(f.psbt);
        psbt.finalizeAllInputs();
        assert.strictEqual(psbt.toBase64(), f.result);
      });
    });

    fixtures.bip174.extractor.forEach(f => {
      it('Extracts PSBT to the expected result', () => {
        const psbt = Psbt.fromBase64(f.psbt);
        const tx = psbt.extractTransaction();
        assert.strictEqual(tx.toHex(), f.transaction);
      });
    });

    it('should keep the proofs inside witness utxos when encode/decode base64 confidential psbt.', () => {
      const psbt = new Psbt();

      const witnessUtxo = {
        script: Buffer.from(
          '76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac',
          'hex',
        ),
        asset: Buffer.concat([
          Buffer.from('0a', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
        value: satoshiToConfidentialValue(10),
        nonce: Buffer.from(
          '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f',
          'hex',
        ),
        rangeProof: Buffer.from(
          '4024cfdf01b235e6e17c51d1ba70db19ba96ca9c251fb8a125bca489075a51f4d280a87f9f4735729569609a6d852eec8ef45c9d00822af3cce60290935d0439c97d133b66fa4d3ebc9400aefd9c372688c01ff2386af9205726a13c9701bfaa6603fa2cd79fe49934f63a9fd37c187cdcf0b6ce1894cbc34a819daf7d967cf7aad343c28a3dd0e6582f8911145e850a26bf8d7ea06f5e9446cc5f2b6a9f82f9b3107cdfa2ddf838b890346e996416151d23fac97a641fc173842a266023e3fe44bd7878af21b22b1b7b066d4980ed0611c73c722ba65e142359f5332bb680dccfe24b40d76f5a322738cb730f2a0a4bc705d62abfada8fe4167847dc4bc6efb18ff0c75a82a17672c6eb4b94d71bc63803b6884f6a7d69896cd864e967d1b9ec498edbaffcacebc10f2e974da6c9f39e77ef4d263e4a749c266b504209d39ce784bea6d60049fe745450ce44d84ad60184b5fff0fa11855dd5738ed2ed213afa9101bda59feaa21c05c4cdb4953f0dfba1e2989544d302412c802a660fbe0056bc38ca127d9091898c9c6424ac693da66a9405d7c1a759e19a90fe9c5dd01019303416094fb2c6296db2096ec11df1f169037c08fe48eb2039d20827c9046b02f0d10d3c5baf4672e0747e1a52c555698b7f528489710aa7874a7d1c5cdec6c7f359751b505f597bbf20f0749fdf3dfbff411b91a41a639f09f9a008e09fdf5e87faf3312da31e47c20abc47c757ecae7cf6ef87cfdc48d266c72c581d18c0f33cbbbe2e6d065afe608fd1d2dbe57abfa01726545a3c2b9c85568d5f8f6b743d3e91871859433edf2a5ae5c33f61d05b52ba8d11215f5955e22207f56a80731cfd3d5a86be04e44020043226151e3edeb150522df68a0c6f3d28d5ae12a517095644451dc5cf2773c2e2abb6ca0c39b8b9dc565b07ff35ab49a1170ef87e77606d728abbdbfbd9c699ea5c039ccb8b17c52f14ffb93db491d0fa6704c9155c0f8c4bf3e817686b15b444582beffabd9dba920a8d96c247493c0184e82cca1beef7c8f16141fd26467071b28a881f1d1e4d201b6dfb1173b87f8e6f7de1d5e5533175bac5f9d6d63c00f7adb16268a7c2bc374bc9993d9b5a084a718c8cb91c6403b3494b71822f8dfe2c3af949d5c8c9275a167938adfbe13cd960dce2c6904ff6e07140f27b58e0ed73e3cabdcea8d321e48bd000cf4f568e5da0b89aa139ec66a6ae2c75db15b616e2ee03e941a8d71e5ed7d62bb507af175ec6bde9a1ff8730ecae93f724cd890cfeaffe23fd77faf768033a6b71a35fbf19544a8c762c80d8a44aaad5eaa08bb118d156476478b8615f7c7235d1f375e6bcda1381eed23d28f3ffc33f2fd4121c150e0adbb971f7622014f9ffc8d4ae916d44ad59e6bc9923bba5c6450fb42d5a9a589412c3688bec3b527ac15594f8181cccd5c8466a6e2a0d31de9562f5abfbd34a2fb766961c3e368ee025f7e9f071bd23da46d3b20d39c187df373b647445995c7111c406c3e5a9cd74ebc3eae76cb0539291f3bbd6ec038dc1a693a25aa51d5c458dec91bd90bf53f6ca169edabbcdf8ea73e200794ad9a4a6c265c881c36e6702a20ddb04a68e19d564be553e49aa3f95ee3ab3f05c9f3c02707b666f459e78e57a6d9137739be9f4f2fb85ab40026b5eed57fb2740265878939e1f4206656c9e20403b7e1c6f6bc4256ea2c7fa7c832dbb290bbae1b8084564cac8c34ce980e155f1caac0466a7b59430cc345d7898b91cd53626007ef44bbbd9e1d7a174b5ab818090426c2773928f41bf41aacc8fb45f4c2a8a270f11a409607c4404d67ae1f5b352439ed3bb822687f4eaa6dbf03982c1abbe437bc99ca44b0e5e4a4ca8bea06c79e9c61ade5418dd2cdaf1627912721c5fa5b4f53c1dacdf6d3f7c977a98ea69c399205e51173f13c74cb5993f7186ee6e1c1f7b3bfde06affc80fa271d08d3a239ddd104390e8c68b631a91d2dcf313ff6ab4f68360f323f71606da5c81495be0de9f3031c9f8823332246b66bed20fece4dfd5f6d941188b2eecdaad987a9a268cfb43de818818b4b3b1e3ad58779df32d47ddaa4d2e94ac40f07f413c36d962ebaf82e1abdecb251041d41dd85494cfafcdbf3af426d91740ed6658f70fa65b59ec309529f4b58154f5c6a76e56f6ebe02c3f03d766b460c2919b1ad7ee96a4319198309c3c78e7bfc6c4eaa2a58c8733e81cc3f1d96cb2389ae6d925438169b481c12893eed0822acf379dc053741c8fb9c95e16ec4bd9d350a34284a702c48cac7d62d00616d3e8daa9bed71569d4ad788c72ca7cdbb562d065d8b2dda835dab612407d398467b5b9272b2784ee026e54b3fbccb98fa4ee7b8dea2f673ccf865c4e14a34b6804a26ff6fbad5efd67f711b20c33a754ed143d0f80525ef5b4d74fee1ea093de56daae104596d16a6c23aedf6193ec78b28d7d4eebc3e91bd779d3be58e52d7f785a8264e435edaacb67368e8d4a096643449375426eb7cb81af820d22ecb86ba2c4649bce5427025cbc3f6319829076031c7759ab0825b4960b2849d653757791f43e17e0f97555be5a1846acd681571f859e6d3c6cd411602bc196acb234078391bce1116e66bcfc5bf23f2c7b545122f9112b9aeafc1ea001164b72db16f579550914b1fa0ead1576c1e9e92b923e4d7ff713cb2a62e2b0ed28db2ec9ca22efaf987fd465877e68bf2201e0fff5e116fd225c545500556958f9684a6a2859b867d32386882ab30718af64677f3026e682904c3d794016685d2dedf67381af9dfb385e523115635ffaa1b98d7f2db759c24f3e9979fa52644e8221f88a398ff2a4b8b30027b72bc3ef8b2837a03e688b582b6474f9a283bb40d173d91612c45bbd685b91edb754c2afb6977eeded2196d5faa6f31d1dc332db85462b976a086eee8f93852c7811d51984df3ee43f00466f9974b60d65567ea3437b2ff88d92e9dbba1399edf559fec42057fcf6d1e84538dc892b0c4c3464d1554ccc0d42f7d857ee5ab5510ff439806e4344abe376cc8bd8e0c24a4ca47a5658d2ea4959257bf85055455c51aad47ec65d8b4cd11c3da1f346ae2ae16119c088ed211eb76d01ef527183057f436a42af31f386e9cf31951688e3ebbf590e9377ee33d4f9a630d4c93237e14d543a78db67adddd7e13ca028c94c6c8fb6060b81ad6d47f5ac366d3938f0a41f5e471a7cf7ed4304cf3bea1827285284f5a233e13da4fcc18cc18d04dbfac14be365c1dfba3c88c5232023a4285ed9ce833b1cd56c71bb14882008ecc4828aa558d69ac79827d0cb37b438785f57bc73d8807b572f5cb5a96fb9f76b8d2d8aedce8a056fdc7c779f12ca55b54d1e0984a97dce56ab65dbf1abb8a192d0fba61e72005d4b689f63bc2170ac8642c8eb4bbc38e4baa1ee1f6dac5f9adf3c244acb371768c6faf5143c8330602ea5393bf594241e8f0ae85c8e826fe7061e3c842562b87b4f40f9935b1451c9fc88d4c52cb50491b9a2a156699245c3f3e502334d0b2805648478a615171eb4c26652ed989ecca43637c23cbf2d8e25f8e7feae56db8607084a07b12836fdc55e76bb425b4efec6c5bd1f60a710cb93ef8a94fb36eec384a8c42b00c9852af105273ff35da4e055671bef3960b7a428e999b8bd0f10c6e7d5a4c799e1ec84c509efe3386bda4e67c61eab1ccea3911e3d35bbdc464784b03b69e7514aeccdb42a9a647c847b861cbfec3e062628f9a832d4712b342e9017a0db86e1d47a2c17198cd5929265c7bc36737eb0373e33bee9dc2fcddf9ce275c5900b29e616cc3ca878267f560a5629c76aafa133aa4806d581596f6f6ab89d06c526b3886b91e53f6db61d4947550b62564f31c6aa6b43aca25fa8b568e7cc262e0e351c31f56c55d951b4e74ba09963048673a45ce46b574c964c98acc8ab449b15ee5df95c4d1cb1fc899733955f8c04acd8e4c439ff4b94cab9691bba48657499d4ee3936db4966925621772d47ea75cf6738990eb8013be7e8f0b7e0ed2952e4c3c8cc7c051ad27c5bd4ac5101de9652c2b0ade8fa113f94aba6f0fca4445bf2c6154115524487c5d96189a3e9d8e91fc5042130687bd94b7a0362030a6e2f731497b19ba4b9b25426be79ddd2495975f7a6888a774a319906b81d5ea3cd8868c5800df526f8361abac3e59e0878631b1bb8319de314e382510e21113b12c7a0861',
          'hex',
        ),
        surjectionProof: Buffer.from(
          '0100013f038e1a201a6cecf538bf712bca62e5d2f868ea0e6078c4298adf10ed61a557c78237c1899cb38aea419aef38161ffa7f82e90c0d19df8e5f37eb7d37193ce8',
          'hex',
        ),
      };

      psbt.addInput({
        hash:
          '9d64f0343e264f9992aa024185319b349586ec4cbbfcedcda5a05678ab10e580',
        index: 0,
        witnessUtxo,
        sighashType: 1,
      });
      psbt.addOutput({
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
        nonce: Buffer.from('00', 'hex'),
        script: Buffer.from(
          '76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac',
          'hex',
        ),
        value: satoshiToConfidentialValue(80000),
      });

      const encodedBase64Tx = psbt.toBase64();
      const decodedTx = Psbt.fromBase64(encodedBase64Tx);
      const decodedWitnessUtxo = decodedTx.data.inputs[0].witnessUtxo;

      assert.deepStrictEqual(decodedWitnessUtxo, witnessUtxo);
    });
  });
  // describe('signInputAsync', () => {
  //   fixtures.signInput.checks.forEach(f => {
  //     it(f.description, async () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotReject(async () => {
  //           await psbtThatShouldsign.signInputAsync(
  //             f.shouldSign.inputToCheck,
  //             ECPair.fromWIF(f.shouldSign.WIF),
  //             f.shouldSign.sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.rejects(async () => {
  //           await psbtThatShouldThrow.signInputAsync(
  //             f.shouldThrow.inputToCheck,
  //             ECPair.fromWIF(f.shouldThrow.WIF),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp(f.shouldThrow.errorMessage));
  //         assert.rejects(async () => {
  //           await (psbtThatShouldThrow.signInputAsync as any)(
  //             f.shouldThrow.inputToCheck,
  //           );
  //         }, new RegExp('Need Signer to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signInput', () => {
  //   fixtures.signInput.checks.forEach(f => {
  //     it(f.description, () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotThrow(() => {
  //           psbtThatShouldsign.signInput(
  //             f.shouldSign.inputToCheck,
  //             ECPair.fromWIF(f.shouldSign.WIF),
  //             f.shouldSign.sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.throws(() => {
  //           psbtThatShouldThrow.signInput(
  //             f.shouldThrow.inputToCheck,
  //             ECPair.fromWIF(f.shouldThrow.WIF),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp(f.shouldThrow.errorMessage));
  //         assert.throws(() => {
  //           (psbtThatShouldThrow.signInput as any)(f.shouldThrow.inputToCheck);
  //         }, new RegExp('Need Signer to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signAllInputsAsync', () => {
  //   fixtures.signInput.checks.forEach(f => {
  //     if (f.description === 'checks the input exists') return;
  //     it(f.description, async () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotReject(async () => {
  //           await psbtThatShouldsign.signAllInputsAsync(
  //             ECPair.fromWIF(f.shouldSign.WIF),
  //             f.shouldSign.sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.rejects(async () => {
  //           await psbtThatShouldThrow.signAllInputsAsync(
  //             ECPair.fromWIF(f.shouldThrow.WIF),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp('No inputs were signed'));
  //         assert.rejects(async () => {
  //           await (psbtThatShouldThrow.signAllInputsAsync as any)();
  //         }, new RegExp('Need Signer to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signAllInputs', () => {
  //   fixtures.signInput.checks.forEach(f => {
  //     if (f.description === 'checks the input exists') return;
  //     it(f.description, () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotThrow(() => {
  //           psbtThatShouldsign.signAllInputs(
  //             ECPair.fromWIF(f.shouldSign.WIF),
  //             f.shouldSign.sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.throws(() => {
  //           psbtThatShouldThrow.signAllInputs(
  //             ECPair.fromWIF(f.shouldThrow.WIF),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp('No inputs were signed'));
  //         assert.throws(() => {
  //           (psbtThatShouldThrow.signAllInputs as any)();
  //         }, new RegExp('Need Signer to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signInputHDAsync', () => {
  //   fixtures.signInputHD.checks.forEach(f => {
  //     it(f.description, async () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotReject(async () => {
  //           await psbtThatShouldsign.signInputHDAsync(
  //             f.shouldSign.inputToCheck,
  //             bip32.fromBase58(f.shouldSign.xprv),
  //             (f.shouldSign as any).sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.rejects(async () => {
  //           await psbtThatShouldThrow.signInputHDAsync(
  //             f.shouldThrow.inputToCheck,
  //             bip32.fromBase58(f.shouldThrow.xprv),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp(f.shouldThrow.errorMessage));
  //         assert.rejects(async () => {
  //           await (psbtThatShouldThrow.signInputHDAsync as any)(
  //             f.shouldThrow.inputToCheck,
  //           );
  //         }, new RegExp('Need HDSigner to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signInputHD', () => {
  //   fixtures.signInputHD.checks.forEach(f => {
  //     it(f.description, () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotThrow(() => {
  //           psbtThatShouldsign.signInputHD(
  //             f.shouldSign.inputToCheck,
  //             bip32.fromBase58(f.shouldSign.xprv),
  //             (f.shouldSign as any).sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.throws(() => {
  //           psbtThatShouldThrow.signInputHD(
  //             f.shouldThrow.inputToCheck,
  //             bip32.fromBase58(f.shouldThrow.xprv),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp(f.shouldThrow.errorMessage));
  //         assert.throws(() => {
  //           (psbtThatShouldThrow.signInputHD as any)(
  //             f.shouldThrow.inputToCheck,
  //           );
  //         }, new RegExp('Need HDSigner to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signAllInputsHDAsync', () => {
  //   fixtures.signInputHD.checks.forEach(f => {
  //     it(f.description, async () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotReject(async () => {
  //           await psbtThatShouldsign.signAllInputsHDAsync(
  //             bip32.fromBase58(f.shouldSign.xprv),
  //             (f.shouldSign as any).sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.rejects(async () => {
  //           await psbtThatShouldThrow.signAllInputsHDAsync(
  //             bip32.fromBase58(f.shouldThrow.xprv),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp('No inputs were signed'));
  //         assert.rejects(async () => {
  //           await (psbtThatShouldThrow.signAllInputsHDAsync as any)();
  //         }, new RegExp('Need HDSigner to sign input'));
  //       }
  //     });
  //   });
  // });

  // describe('signAllInputsHD', () => {
  //   fixtures.signInputHD.checks.forEach(f => {
  //     it(f.description, () => {
  //       if (f.shouldSign) {
  //         const psbtThatShouldsign = Psbt.fromBase64(f.shouldSign.psbt);
  //         assert.doesNotThrow(() => {
  //           psbtThatShouldsign.signAllInputsHD(
  //             bip32.fromBase58(f.shouldSign.xprv),
  //             (f.shouldSign as any).sighashTypes || undefined,
  //           );
  //         });
  //       }

  //       if (f.shouldThrow) {
  //         const psbtThatShouldThrow = Psbt.fromBase64(f.shouldThrow.psbt);
  //         assert.throws(() => {
  //           psbtThatShouldThrow.signAllInputsHD(
  //             bip32.fromBase58(f.shouldThrow.xprv),
  //             (f.shouldThrow as any).sighashTypes || undefined,
  //           );
  //         }, new RegExp('No inputs were signed'));
  //         assert.throws(() => {
  //           (psbtThatShouldThrow.signAllInputsHD as any)();
  //         }, new RegExp('Need HDSigner to sign input'));
  //       }
  //     });
  //   });
  // });

  describe('finalizeAllInputs', () => {
    // fixtures.finalizeAllInputs.forEach(f => {
    //   it(`Finalizes inputs of type "${f.type}"`, () => {
    //     const psbt = Psbt.fromBase64(f.psbt);

    //     psbt.finalizeAllInputs();

    //     assert.strictEqual(psbt.toBase64(), f.result);
    //   });
    // });
    it('fails if no script found', () => {
      const psbt = new Psbt();
      psbt.addInput({
        hash:
          '0000000000000000000000000000000000000000000000000000000000000000',
        index: 0,
      });
      assert.throws(() => {
        psbt.finalizeAllInputs();
      }, new RegExp('No script found for input #0'));
      psbt.updateInput(0, {
        witnessUtxo: {
          script: Buffer.from(
            '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
            'hex',
          ),
          value: satoshiToConfidentialValue(2e5),
          nonce: Buffer.from('00', 'hex'),
          asset: Buffer.concat([
            Buffer.from('01', 'hex'),
            Buffer.from(NETWORKS.regtest.assetHash, 'hex').reverse(),
          ]),
        },
      });
      assert.throws(() => {
        psbt.finalizeAllInputs();
      }, new RegExp('Can not finalize input #0'));
    });
  });

  describe('addInput', () => {
    fixtures.addInput.checks.forEach(f => {
      it(f.description, () => {
        const psbt = new Psbt();

        if (f.exception) {
          assert.throws(() => {
            psbt.addInput(f.inputData as any);
          }, new RegExp(f.exception));
          assert.throws(() => {
            psbt.addInputs([f.inputData as any]);
          }, new RegExp(f.exception));
        } else {
          assert.doesNotThrow(() => {
            psbt.addInputs([f.inputData as any]);
            if (f.equals) {
              assert.strictEqual(psbt.toBase64(), f.equals);
            }
          });
          assert.throws(() => {
            psbt.addInput(f.inputData as any);
          }, new RegExp('Duplicate input detected.'));
        }
      });
    });
  });

  describe('addOutput', () => {
    fixtures.addOutput.checks.forEach(f => {
      it(f.description, () => {
        const psbt = new Psbt();
        const out = {
          script: Buffer.from(f.outputData.script),
          value:
            typeof f.outputData.value === 'number'
              ? satoshiToConfidentialValue(f.outputData.value)
              : f.outputData.value,
          asset: Buffer.concat([
            Buffer.from('01', 'hex'),
            Buffer.from(f.outputData.asset, 'hex').reverse(),
          ]),
          nonce: Buffer.from('00', 'hex'),
        };
        if (f.exception) {
          assert.throws(() => {
            psbt.addOutput(out as any);
          }, new RegExp(f.exception));
          assert.throws(() => {
            psbt.addOutputs([out as any]);
          }, new RegExp(f.exception));
        } else {
          assert.doesNotThrow(() => {
            psbt.addOutput(out as any);
          });
          assert.doesNotThrow(() => {
            psbt.addOutputs([out as any]);
          });
        }
      });
    });
  });

  describe('setVersion', () => {
    it('Sets the version value of the unsigned transaction', () => {
      const psbt = new Psbt();

      assert.strictEqual(psbt.extractTransaction().version, 2);
      psbt.setVersion(1);
      assert.strictEqual(psbt.extractTransaction(true).version, 1);
    });
  });

  describe('setLocktime', () => {
    it('Sets the nLockTime value of the unsigned transaction', () => {
      const psbt = new Psbt();

      assert.strictEqual(psbt.extractTransaction().locktime, 0);
      psbt.setLocktime(1);
      assert.strictEqual(psbt.extractTransaction(true).locktime, 1);
    });
  });

  describe('setInputSequence', () => {
    it('Sets the sequence number for a given input', () => {
      const psbt = new Psbt();
      psbt.addInput({
        hash:
          '0000000000000000000000000000000000000000000000000000000000000000',
        index: 0,
      });

      assert.strictEqual(psbt.inputCount, 1);
      assert.strictEqual(
        (psbt as any).__CACHE.__TX.ins[0].sequence,
        0xffffffff,
      );
      psbt.setInputSequence(0, 0);
      assert.strictEqual((psbt as any).__CACHE.__TX.ins[0].sequence, 0);
    });

    it('throws if input index is too high', () => {
      const psbt = new Psbt();
      psbt.addInput({
        hash:
          '0000000000000000000000000000000000000000000000000000000000000000',
        index: 0,
      });

      assert.throws(() => {
        psbt.setInputSequence(1, 0);
      }, new RegExp('Input index too high'));
    });
  });

  describe('clone', () => {
    it('Should clone a psbt exactly with no reference', () => {
      const f = fixtures.clone;
      const psbt = Psbt.fromBase64(f.psbt);
      const notAClone = Object.assign(new Psbt(), psbt); // references still active
      const clone = psbt.clone();

      assert.strictEqual(psbt.validateSignaturesOfAllInputs(), true);

      assert.strictEqual(clone.toBase64(), psbt.toBase64());
      assert.strictEqual(clone.toBase64(), notAClone.toBase64());
      assert.strictEqual(psbt.toBase64(), notAClone.toBase64());
      (psbt as any).__CACHE.__TX.version |= 0xff0000;
      assert.notStrictEqual(clone.toBase64(), psbt.toBase64());
      assert.notStrictEqual(clone.toBase64(), notAClone.toBase64());
      assert.strictEqual(psbt.toBase64(), notAClone.toBase64());
    });
  });

  // describe('setMaximumFeeRate', () => {
  //   it('Sets the maximumFeeRate value', () => {
  //     const psbt = new Psbt();

  //     assert.strictEqual((psbt as any).opts.maximumFeeRate, 5000);
  //     psbt.setMaximumFeeRate(6000);
  //     assert.strictEqual((psbt as any).opts.maximumFeeRate, 6000);
  //   });
  // });

  describe('validateSignaturesOfInput', () => {
    const f = fixtures.validateSignaturesOfInput;
    it('Correctly validates a signature', () => {
      const psbt = Psbt.fromBase64(f.psbt);

      assert.strictEqual(psbt.validateSignaturesOfInput(f.index), true);
      assert.throws(() => {
        psbt.validateSignaturesOfInput(f.nonExistantIndex);
      }, new RegExp('No signatures to validate'));
    });

    it('Correctly validates a signature against a pubkey', () => {
      const psbt = Psbt.fromBase64(f.psbt);
      assert.strictEqual(
        psbt.validateSignaturesOfInput(f.index, f.pubkey as any),
        true,
      );
      assert.throws(() => {
        psbt.validateSignaturesOfInput(f.index, f.incorrectPubkey as any);
      }, new RegExp('No signatures for this pubkey'));
    });
  });

  // describe('getFeeRate', () => {
  //   it('Throws error if called before inputs are finalized', () => {
  //     const f = fixtures.getFeeRate;
  //     const psbt = Psbt.fromBase64(f.psbt);

  //     assert.throws(() => {
  //       psbt.getFeeRate();
  //     }, new RegExp('PSBT must be finalized to calculate fee rate'));

  //     psbt.finalizeAllInputs();

  //     assert.strictEqual(psbt.getFeeRate(), f.fee);
  //     (psbt as any).__CACHE.__FEE_RATE = undefined;
  //     assert.strictEqual(psbt.getFeeRate(), f.fee);
  //   });
  // });

  describe('create 1-to-1 transaction', () => {
    const alice = ECPair.fromWIF(
      'cPNMJD4VyFnQjGbGs3kcydRzAbDCXrLAbvH6wTCqs88qg1SkZT3J',
      NETWORKS.regtest,
    );
    const psbt = new Psbt();
    psbt.addInput({
      hash: '9d64f0343e264f9992aa024185319b349586ec4cbbfcedcda5a05678ab10e580',
      index: 0,
      nonWitnessUtxo: Buffer.from(
        '0200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6' +
          'd428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e' +
          '9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c5325954387' +
          '2e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c40' +
          '1dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2dda' +
          'b03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3' +
          'c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2dda' +
          'b03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000190000000000000',
        'hex',
      ),
      sighashType: 1,
    });
    psbt.addOutput({
      asset: Buffer.concat([
        Buffer.from('01', 'hex'),
        Buffer.from(
          '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
          'hex',
        ).reverse(),
      ]),
      nonce: Buffer.from('00', 'hex'),
      script: Buffer.from(
        '76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac',
        'hex',
      ),
      value: satoshiToConfidentialValue(80000),
    });
    psbt.signInput(0, alice);
    assert.throws(() => {
      psbt.setVersion(3);
    }, new RegExp('Can not modify transaction, signatures exist.'));
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    assert.throws(() => {
      psbt.setVersion(3);
    }, new RegExp('Can not modify transaction, signatures exist.'));
    assert.strictEqual(
      psbt.extractTransaction().toHex(),
      '02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f' +
        '0649d000000006b483045022100f91ae1cb73b3afae669ceb8768a564176effa9ccce4d' +
        '791eabd2b47078bdebd50220154c08cf3e42f3678f5bf7cf461dc4656538dc7c1cd9fc4' +
        '31ae08cd754f3cd4401210251464420fcc98a2e4cd347afe28a32d769287dacd861476a' +
        'b858baa43bd308f3ffffffff010125b251070e29ca19043cf33ccd7324e2ddab03ecc4a' +
        'e0b5e77c4fc0e5cf6c95a010000000000013880001976a91439397080b51ef22c59bd74' +
        '69afacffbeec0da12e88ac00000000',
    );
  });

  // describe('Method return types', () => {
  //   it('fromBuffer returns Psbt type (not base class)', () => {
  //     const psbt = Psbt.fromBuffer(
  //       Buffer.from(
  //         '70736274ff01000a01000000000000000000000000',
  //         'hex', // cHNldP8BAAoBAAAAAAAAAAAAAAAA
  //       ),
  //     );
  //     assert.strictEqual(psbt instanceof Psbt, true);
  //     assert.ok((psbt as any).__CACHE.__TX);
  //   });
  //   it('fromBase64 returns Psbt type (not base class)', () => {
  //     const psbt = Psbt.fromBase64('cHNldP8BAAoBAAAAAAAAAAAAAAAA');
  //     assert.strictEqual(psbt instanceof Psbt, true);
  //     assert.ok((psbt as any).__CACHE.__TX);
  //   });
  //   it('fromHex returns Psbt type (not base class)', () => {
  //     const psbt = Psbt.fromHex('70736274ff01000a01000000000000000000000000');
  //     assert.strictEqual(psbt instanceof Psbt, true);
  //     assert.ok((psbt as any).__CACHE.__TX);
  //   });
  // });

  // describe('Cache', () => {
  //   it('non-witness UTXOs are cached', () => {
  //     const f = fixtures.cache.nonWitnessUtxo;
  //     const psbt = Psbt.fromBase64(f.psbt);
  //     const index = f.inputIndex;

  //     // Cache is empty
  //     assert.strictEqual(
  //       (psbt as any).__CACHE.__NON_WITNESS_UTXO_BUF_CACHE[index],
  //       undefined,
  //     );

  //     // Cache is populated
  //     psbt.updateInput(index, { nonWitnessUtxo: f.nonWitnessUtxo as any });
  //     const value = psbt.data.inputs[index].nonWitnessUtxo;
  //     assert.ok(
  //       (psbt as any).__CACHE.__NON_WITNESS_UTXO_BUF_CACHE[index].equals(value),
  //     );
  //     assert.ok(
  //       (psbt as any).__CACHE.__NON_WITNESS_UTXO_BUF_CACHE[index].equals(
  //         f.nonWitnessUtxo,
  //       ),
  //     );

  //     // Cache is rebuilt from internal transaction object when cleared
  //     psbt.data.inputs[index].nonWitnessUtxo = Buffer.from([1, 2, 3]);
  //     (psbt as any).__CACHE.__NON_WITNESS_UTXO_BUF_CACHE[index] = undefined;
  //     assert.ok((psbt as any).data.inputs[index].nonWitnessUtxo.equals(value));
  //   });
  // });
});
