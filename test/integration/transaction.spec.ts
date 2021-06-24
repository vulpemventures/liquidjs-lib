import * as assert from 'assert';
import * as bip32 from 'bip32';
import * as liquid from '../..';
import * as regtestUtils from './_regtest';

import { describe, it } from 'mocha';

import { networks as NETWORKS } from '../..';

const rng = require('randombytes');
const { regtest } = NETWORKS;
const {
  satoshiToConfidentialValue,
  unblindOutputWithKey,
} = liquid.confidential;

// See bottom of file for some helper functions used to make the payment objects needed.

describe('liquidjs-lib (transactions with psbt)', () => {
  const alice = liquid.ECPair.fromWIF(
    'cPNMJD4VyFnQjGbGs3kcydRzAbDCXrLAbvH6wTCqs88qg1SkZT3J',
    regtest,
  );
  const bob = liquid.ECPair.fromWIF(
    'cQ7z41awTvKtmiD9p6zkjbgvYbV8g5EDDNcTnKZS9aZ8XdjQiZMU',
    regtest,
  );

  const nonce = Buffer.from('00', 'hex');
  const asset = Buffer.concat([
    Buffer.from('01', 'hex'),
    Buffer.from(regtest.assetHash, 'hex').reverse(),
  ]);

  it('can create a 1-to-1 Transaction', () => {
    const psbt = new liquid.Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput({
      // if hash is string, txid, if hash is Buffer, is reversed compared to txid
      hash: '9d64f0343e264f9992aa024185319b349586ec4cbbfcedcda5a05678ab10e580',
      index: 0,
      // non-segwit inputs now require passing the whole previous tx as Buffer
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
    });
    psbt.addOutputs([
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.confidential.satoshiToConfidentialValue(50000000),
        script: Buffer.from(
          '76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac',
          'hex',
        ),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.confidential.satoshiToConfidentialValue(49999100),
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.confidential.satoshiToConfidentialValue(500),
        script: Buffer.alloc(0),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
    ]);
    psbt.signInput(0, alice);
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    assert.strictEqual(
      psbt.extractTransaction().toHex(),
      '02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f' +
        '0649d000000006a47304402201e868b2bea22df05229746a27e7df2ca0f584880546f7f' +
        '6d55dad71cbd50d35302203a04a4cc49fca739c8974c97d3de924c99835e15ad1d85b96' +
        'ad24ea072d2e63e01210251464420fcc98a2e4cd347afe28a32d769287dacd861476ab8' +
        '58baa43bd308f3ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0' +
        'b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469' +
        'afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e7' +
        '7c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3' +
        'a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4f' +
        'c0e5cf6c95a0100000000000001f4000000000000',
    );
  });

  it('can create a 1-to-1 confidential Transaction', () => {
    const blindingPrivkeys = [
      Buffer.from(
        '13d4dbfdb5074705e6b9758d1542d7dd8c03055086c0da421620eaa04717a9f7',
        'hex',
      ),
    ];
    const bliningPubkeys = [''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );
    const psbt = new liquid.Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput({
      // if hash is string, txid, if hash is Buffer, is reversed compared to txid
      hash: 'dd983c9c0419fce6bcc0eaf875b54a2c19f9d6e761faa58b1afd199638275475',
      index: 0,
      // non-segwit inputs now require passing the whole previous tx as Buffer
      nonWitnessUtxo: Buffer.from(
        '020000000101bb6d18772599ae3ad9c44c524d63b666747c1c195c6f516a41a8d5f4a' +
          '32eef05010000001716001408a2534a4b37e12c371886ead381981413eec5edfdffff' +
          'ff030b0cbc7820f47ecff027603c63c52f715884852f2bebbbf66e7cedb6de6682f3c' +
          'e089815430f14f51d3453af022276eebc951f24c2f0426c8f5abe1ce9c0a96dd5c502' +
          '49acd8a6f58a01e252221749432d2698d844c9e41e9f41783974aaf855f05c9f1976a' +
          '9145ced4a2aefa685ae6df3d3a80e1bcdbdc10b748688ac0b645f88d6c4578afcfaac' +
          '9a0a8467578f8ead7e6eb69d0fec6d789f566c9edd1a0848ff4f7b458e6e0d7dcec88' +
          '88867a60478de16020e851a3b09e7fccc0929871f0288cf3434028f883d787039eb2f' +
          '2914b387e87f7e645939db81eb6b992302909c17a9149791858e4777dcc414a3df9cf' +
          'd575356040c3336870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77' +
          'c4fc0e5cf6c95a01000000000000aa7800000902000000000247304402202878cc5e9' +
          '9cf2d4e975eb3f4bcf09d704a607383348a0015d54af7e0aac1408602200106ac19ce' +
          'b108e2b618f805ef2f69c64670adce166cb804b2c98894a184123a012102b821ade98' +
          '31d6d30a8f8869bd8cbcffaa9621a5fab6de2332215c1dc56dc93ef00430100014e87' +
          '67b846b91d00fbce65f4237b91075568bde843d3d825dd434695e444f10f3f2b6515f' +
          '9bcd9eb9d04607bbbcad6f45bb86f7060377c71808d0061d0ad8cfefd4d0b60230000' +
          '0000000000019a900126613909c9d892d9d7900429dde9f4b253e7a6a5869efcc6b62' +
          '847423108377323937ce4c109553fce4df91697bcf188da1c91056abe31957ac360c4' +
          'b7836a442fff84c5d944c7c2b19396c4659914437a8fbd38e6a7a26c45c8870206500' +
          '25d802ed0140cde45d354481732a8dd6073c8a6a4e4ebd9e8e64c9559a7d240690c29' +
          'ed77261718b1c82aad645896f645d1ea2114227dcd8c65ca31f049f5cdda3593ffbe1' +
          'd198307e0a2b921c264d657f0e6df3600e509ce0c5c9201d856454278e59261ba6576' +
          'deb96736a54f4c167dfeb25059100a2613e926ff7a1c700f08ebe719d0df245183109' +
          'f2ceb7c0d0d683adbada40e638d9764606e125321b38c6b20ec742bf9cc76318ef011' +
          'fe968d52c78402053ca495769deb6b20e38e473f4efa751a8c1e59b2e60aeb6a65c67' +
          '59fc482a5d75c83e28666785aa481a15722a97497e35b5f79c0fa0cd12bc52847c5ec' +
          'ee473a4828062fb18eaf7df69b92182a69981ce0e354c52d95c26ed0b6017005b1eaf' +
          '1ba5124d457a3f90f363fb2f6c080ecaff037855c34f07398906d6f959710cdccd99b' +
          'efbbcdc4a67b76abbb94f876e855e5b6e5a158151e9e3f30d67f47c5eed75965e48db' +
          '2bdca30f6fa922889bd2cb2c4476260886efdfec46f8a079792ab563ae1179b943639' +
          '67481db61eed7558198d08c9e9d559859c41f7941cc3f8de5c2b1a5a20d1d5a5f5dd8' +
          'c99b1df710a4aedce155da417228fddc367e3d69d510b0f82d891fe1211d5b954ecfb' +
          '622f31e0353ddb67283f892788c922f6f0c215f9ee61a1fbf8c62465e1442b38fc242' +
          'ae83f754cc223595cc2a9f05796b89818b0ee62079ad15694c6d56c9a4d08ce2f4071' +
          '9cd47c8cc90b8015bb8833b716161dbdfd46040b2cb8b5f4c881075bc0f973cb5f38f' +
          'd1d92a8929f042b5d016605cefe6897ae517768c84d358e607b5e3dec35244ab2a8b8' +
          'd3afa7b15464d59003737d10c87e939c6b90dfc7055706691fbdf2221d515333b0ebd' +
          'f34b0635bb133fb5e9f8fa578976f1e1a99b4645bbb6630b5d6f00097217c46f6ba1f' +
          '7ebf8ef947e82f17f97f9633212455b50b56cb646c4155399dd9627093fb66bb78239' +
          'dfefe4b410979751f5cfd082239fd3bd39ddbc87fd55b492928805b6825cdefec6b07' +
          'e5194c5e661b863b04734019f7a90403d23d2f15634b639b627fdd34abf7ecfe0990a' +
          '221d3b516014c48cac4edbaa1257a6a6a3493394c0645c418f7341a0dcfbe614dbf78' +
          'b0384715e6f844bf41ac4e99a1e3398320f8f955fe628b6a0ba4bb8cbe36d141c7d21' +
          'e4886c3beabfaebb7807ff391bb93189eb0d2345eaa154ab6a0ded4fc042458904e2c' +
          'a41335e70225759bc77f2115990da8e55305910d13770958c908ed5f55fa289260f66' +
          'b520d20dd644b2d12ff1b71d1f67e315f1f54e9b7b6ce2bb20b613a93d95fb943e7a3' +
          'f512be065e1e05d59ae0018b75a126d510a30d1b4c5aaff8a3cb21d0347eca5ae93e5' +
          '36ffa4659dd9b868c4e2590a70102a03fbe980c409875fca7ef40c9be632ae0709137' +
          '1a5d2e65448a9a51129885fd51dbca34080bf10bfaf70b6e256a8627af30b550892e1' +
          '011f5fb9b165b9a9dc735336f67fd3032b21a4643c61d0990a625c04cd667cb327e21' +
          '740fa40399caeea4f4360ed41b7590d71c4bc65d3d79912fe442d312f2e32bea5efbe' +
          'edec7f1d317d81c9d8592c6d772f636d1733813668bb72039d5c8968ba640262f0932' +
          '602b5149b59a787dfce302167e3f11e59473d10e4f0fdd9e14fd2736d073c20ff646a' +
          '9e66819622a5f7495cb0045c3bf1d3fe3feee1d1ab14bbee70385ea24a43029478609' +
          '90381151374498dbc6c9db6415e153ac9944bf9aeeefec0036dab51ea026895870624' +
          '5ced580435a706aa270bffe0b605be08ae738abdbbf94f01e371774c0110a9d07c55c' +
          '5363891b081816aeff5d1a553ce46638af49b75b4404e83b8d898936b1c0abec8463c' +
          '0bdd3c1ee3bb8229bf6e36de7fe5d3436436db413ead501ddf6f1ca17fdbfffd6e9d8' +
          '87ab4975ec563e446cc6fc77952848d76e7c593fbdca0827f455914e3e28aa5b1f2dc' +
          '65bf89cb47dc5b35c6a938b078d6603377181da94562ae542951a3f2566dd1c565488' +
          '2a076d0738e208a86d3385e139e741a126f3e3b59b7da737df6ac163b42fd4d60a819' +
          '45a146256194759884ef99170fd060319388025ee7c87d75c9ca8318d4a80f8d9212e' +
          'bfa858b4918287161f3c32c592766f83fa2794e184225968e9892c9bcf70119d4c3cb' +
          '1dbc1b8b554fe4d70bdf483d17223b2acf19f544fb724516c93e604bc9f2da90350b7' +
          'fbba32adfe78c9fa6b31af1102da48d0b30ceab09c8cb850a1d96ef648a8b6cac6334' +
          'c815ff1898a72dfff656f8d256113d8bda6af910ee5857c77234bb2209e3fe24b353c' +
          '06eae93fc01225c9aa4fe395bd9ab3b73dc8ad697717e9a4cd87167637e09ce1ec1c9' +
          'a4d764afe5835740b31fcbfc366c0bc31bf2ad53df16c812b5f243da47a19e0c23091' +
          'b5feeacc50c9f9694997d90d95d8d0d850df09704db04b9f1ab8343393893f46cea4a' +
          '82ce7a3368aa7e2de736ebf13a3fd6a8a73e7f984ac822cf13c615ee8320b10f88479' +
          '22dbe5dab0f2f25545616f06106068a0c45342f4ddbd86d3da3d9ab45b9122c05fd74' +
          '176a441dfdd10202a99e40ee67d06c452980cd9c24b2638fc07213211edb839a35cbf' +
          'e714358850ebf68fce3a0e8f2e9723460af3b11cf32d63e8b1958702c0eb63fcef9c4' +
          'e218eb88b4af2658469d4f655197e79b6bf9e5d1707db3381b280ebc2bfdfffcf11fb' +
          '6d5bced64cb5819a6dc189746ff7baa83d766917223cc32a3ac5f66f701b710c63282' +
          'fa21fd863ce3bb7aca3b6f1a0fac2add641fb519cbf6bde10aa52876d016f7ca4adc1' +
          '306f239b652164c9a63051cc27cc906f5e829ec8634192c72319caccffb58b5bb5692' +
          '39771e3b04685f189e0b948f882bd6e280bba96ea7fa5cdfe3b9706f5371e75937aef' +
          '7316f1e20e742f05b258991d5dd69f5f59514eb64880299bf2fa9cc2e4d49695d861f' +
          '5dbf87710cbc572721617da35212a6935bb10d5e80b9011cad6d2407c7fb5b6020fd6' +
          '15010cae3f409a301202944443deb2c22df40dd436e1d6ef8a4a5e2535adf74c47d4e' +
          '57c1cbb0d5f9e492ef03cba9501eb5a08f47be0fe65c0e83759c4569968fcc3a61226' +
          'f67fbd90d56606844e3f1cda1a2a1cf7c2f18bf4ce3097cb39a780c68fca5640b17e9' +
          '4ea61f55bcd594f46b9bf889472f962efafc02e8071db3a8d6cd328388f01bb95981c' +
          '3ec9c86dbad4e9fb2ee2cdbc44b48bcc96a50c5d3ca5cf922a792e223fe0a93582adb' +
          '026981c953f91f7c147434fd4feabe5fa3c0dc7c4767cbef845756eb7cd6030ba7c95' +
          '4e4423fc7e8ee88777755f6f645356d6d3929705bb973d938cb08dd0f16d8e8fda8c1' +
          '6496ea308e0dd3ce9f5b718f68d555d8f46e733e65f4800a2f5c531cb65b92e57dec6' +
          '2fe754f75261691e28e80af993e71bcbd9ba2667896462de0b053d057d5b545c98bcd' +
          'bd5a5e872b3a58c539d93b50e51973cc52e58d06b5f50eca057fca6ca1cdfc76bcc83' +
          '366aeebb0d8c59fc95d8f214ca1a2d7adc4bda43fed79b9a097e6ed553f0ff9f6126f' +
          'acadf26f3df9ad1178e4a2e0dc42e4677fd8b676f2f5ecbdc05268f61d66e1658bfba' +
          '5d785b69f7fca1d33aedebe20519d6ab1c443df1e8a7143e92de228bda0977a26dd2e' +
          '9efdfe8ceb61ee97ef24e7acf22b274a6aebbba0bbd2f8dae470fee408fd7dbea6c61' +
          '1ad68ae73d2efdf0b3b558da4e5781217ec5dc0193fd3df4827c2b29676723d7dae2e' +
          'b9072e842b770f49af55b9252209d7057a7d4215c1e9f87236d839854529e1a120cd6' +
          'a1dcdbe2c8bbd4adfa24987e58fa648b97077d1e3766f3ed585f30ee17fcacd1ca629' +
          '7a442325e528f3599d64ee28685825aa6c767f45abadb16ba40e1fb86b7403c35ceaa' +
          'e4dee4daf998ae1c37d5baba2913415f520733c9f37a6cca57e9370a947710e3865cc' +
          '7e5e5575fb8700bc38b8cbaac36b88199067194b95c16e856f843010001b4208e911f' +
          'cbd4cf295756aebb8e39bd29684d5a6eae34c1863c7a9b0ae03001804505f6132e7a0' +
          '387d08425967b8b50fce5830657096b1d1c90b273e893f6d9fd0e1060320000000000' +
          '0000016145ca0118a0cf5eaf1b6b219fa484a9babce8e76dab8908416b5ccb532daf2' +
          '68c76a73d50d16b2d8cf3f2a13e0d5e9e96733e1263b7dac0879afdc284b8af845fc2' +
          '01ce2ac53b9921d8830fb13e4156ec7eb7db3638704bc594d8f5a6a14f892623da42b' +
          '0a630d7bf50ba231f4aeda109feee405fd04c332bdba34fd77e4989e5505b24928d9c' +
          '7eb3ba838a66f44ff846f442d5cf3e7ed9fdf7711a99d0daa5b2af0c7f18fa11a6f6f' +
          '3e931e6ae61142fa7292581a075fb080f0339602c120a773435024da786c1c2cbbe64' +
          '11435a58ecb6b31e6de3210515bc0d3c0b903f0b2f939d135eba5913296ed823ab3c3' +
          'd2e774838cd27799b1f43fbccf9ff64db3214c910d691a356f1b959fa5ce07c6d5a75' +
          'd637c1a59d2233fea34a57004784d8557a9b653d2754bfbcc60ec34c227f49eb9b2db' +
          '68675089595d72796cb6280bd3ef52c7e19416c30288f54617d45fe037a86179b2202' +
          '13d3e4115e5ff6b031afef243d6bba40ea6e5d0c2e6c42b26f195fda6e1c67eef6794' +
          '608ee7ecbe26ea219b80d430e95e660ad35bb6feb72e99c851b71d9f101368b1de73b' +
          '59e424ca6bb74e5142262b2a38713d8154c64e5649c48bc842d9a9ed956026b7dcc0b' +
          '9b91304966b009080fff2fdd1d719c52b7792353eb2c23d062597fdd4d80d737b70de' +
          '94af9b88175dbe4c196e2a0565b419e5415857d3892f4353cf37de11e20204b9b99da' +
          'f570627208c17a546192f287b27ce19d66905a7040aa56fa529afc4de9f5b73f09fde' +
          '2f750b728435cef1cff3d4d409c5580105dc42638a86dca082fb765ca09456430c9c7' +
          '6fa2e2ad036713ddf6febca85516c190ea9ea86cded46d31876a990cfc289c83dd931' +
          '26540db778e82d70eb30d838b4bd15138db1627771d47cd72fc9b1d5f173c68c240d3' +
          'd93078b81e40e9b604581170db777c52af957c923dbe63f1a2dd2cb4b2154ce6eda4f' +
          '4799aa1d992301ffb6a7e12fa6d299e92d1fb3635b37c35c4caf9dd2e0fee314ea428' +
          '91eaffeef99866eb8a2098e51805f34d1d0f2db0a7bee452f0ccdfd9f269d3231db36' +
          '3e1b75336a7d8e658e6ee46881c380db88a71a7b3d365e7b1557bde479150d3b411b6' +
          'afd70a3e7ade9e161e59b6a87264870a5a4b5e68c6cebf00afb4413fc562406e328a0' +
          '163e0f39220a79b6d655b3e2a12cc26152ea8b96a4183a5b68c5fbadc6071fd4f232e' +
          'a7bae9199af7bb23044a83038037b8af8e43be708bd5278c68cdce7c0cdf8c8a3b497' +
          '48967009b3df43f04e3d946612957c9db49cf25d68933f7bda7c66dd820d1ed096717' +
          'b646d24190572c251f6f51b648aa10444a2f783f07a4b8ff226f20651cf32a5001046' +
          '69b3afa369a7b7bab77f4460961afa6cab57722372c91f909d5e214a625be4e53ecac' +
          'a3bc5ca1fabbd1b2b89306b5ce799e1e4513836cffbfc3d74621d7bd7e10c19fcac10' +
          'db93c6da69492d705db8429012de03d91c1ed47ce185cc1252679a2e55461381feb21' +
          'ca8be684f605aad3386acb3e2a3fa1672bfbeea80a0fe25ff98294779df2321fa8669' +
          '8871f57eefad2150129409bf054b0a626cc13f9a84e09766982490c7070f73deda4b1' +
          '586480065bb5b2cb53d84a25d127c26537c76c187e34d1bdc8fd37b5931d7b9a351d8' +
          '6d300ccceb901057f6314cbc7d5a0758d19255c73db773678f424cafd55f466d6220b' +
          '7439fc115264e5c6756f140f651419b770a342e387b6e95b991b79e4cac24a8a17dbd' +
          '15a5eaf60653d1d2d9ad5166d77338f6e404098e4872f94ce957c8d7dbcbbdaae42e4' +
          'c19c681a5a3cd90da9b9ea977ac6fe1f4d700dd432a438fcfe615d0d375b6f3587466' +
          '5a43a25f401a6789da2caa8b1124666f6168127b40ebb4a2d3da2d83872f275e41bf5' +
          '95fd7f56201a5d5190b8be46c5275f760f83e86c18088f0ecd6a36d14f772cfc5b9d0' +
          'a0c3a37d010a043c03e609ea835a9952591150fde713cc5802103787aa32b42f885c6' +
          'e33251d711d17ac5d35c3af708dbe5290671af435d1a51cc4c6e20cfa04833746cd53' +
          'dda6561dc4bb232d9789588036b870a5d482ed45a44051589c516a5b2c9f97807202a' +
          '817fc79b3029ac3ef82b062ea802269233ba47c9a131d3772f606076fddf1e7f23114' +
          '464655a28771a9bf3b95ce6ae4c63e7102d8ed9010b5f166fd1ffd7a52e3d69927bfb' +
          'd3bd5de9f6c1e0229b51d2c4358640313ccd7895b31aac41d4db2b07950fbcd84c55f' +
          '7251d03e012bc45d51f2641e2ef56554e232ca6bfbf3e882584f3203cbedf21392eeb' +
          '6bc2abdc43400838aac770e2a51bf13680828dd6f67bf98ef2edd07133d17912062c5' +
          '4a82b956d64ad37a18894d6732491d231a3763ccffcb82858e0b4be359ee0e5f7be78' +
          '282b346194020e3f351ec4a7b7a83d08af4a5f195b486c8c506fa8194313eaa1a795b' +
          '92bd972dba484cf782c88ca25b7e5a547a179d3020354d1b55bd6f0fdf0ae6b78fb24' +
          '403ab8677e6cf07c8281f55663f3dc26d95f9ec47d51b719b88f8f46350aa64b36b7a' +
          'd10f93483f34617a3ea1ec7377bc422b97352dd11b7590052801e1f8ec636ddcfcef9' +
          '99d35f0b94dd43a12dd558ce8617fdc496778c0fac27cd2c757263100638b542afd4d' +
          'd13e0802bd2880164bdf4fd0a3f87e3a7b3442f59a6bd28e6631b8d0873085bd4d06d' +
          '51fbbc934c357d8b737b08beae4d18c43a57bda8ba0f02ff30930a8559095fd70a3fb' +
          '6230d6c865cc4b6ed7852e87d2c4c736853a23da484ca78b97f3ece0ac0d953456b91' +
          'b6510b7328b32fc2aea36103ce8f1962db61598ec75195ecc1b17e1aba217807d6845' +
          'e92d0552438408b3c401d8957a633d6805590b4b04f4b5ed86469ffd907a92d4e18d8' +
          'da07100da45c8a0122450d709a5af08f9f9348574dd18abf2bb95edfee67fbf01564e' +
          '6004221235f779073caeffe4e3e8e34f05bc80a7e9fad410c2cf55bf2fb986a15afb5' +
          'edff5f43f9d4d252f3488f7bee7aa0aafbb7e77072fa2a6f00c56baa9851ec4187e75' +
          '959b9f62aeb8a6283fe0802e33d17e65057c743f0ef5e6371110ebd32ec86c40f2699' +
          '121299dfa6eb9a22e4c3eebfba94e50dedf2955018f59991ad6b8a109e56369b2a078' +
          '2cd9e609ad5d22b9858706eac690d72c6699e65a09e444eac820830495183d77b9acf' +
          '801516f83d46bb9e48cc1d38f415720f1e61ff423649b87be94ff9ee39cfb27e38ac0' +
          '1ae3de23de434d97cf2668444b0a894091324035c359918d25017c97c24c0d097f72e' +
          '4ca6d8f49ec3af125bb531c5a16b1ae713ca03e2b7b2610edebb236d8e6e36478ef8c' +
          'b3b731388a25f0c0eeb0b478defa0a87147111809fcf1bd917e9aa01aa9d443c3f859' +
          'b70e7e56d4ac5401c7cd25ea8ba341f548c4d54f79873d02704ab8ec26ddca079d35d' +
          '5aefe4351cf1bc25c30a49712795dca62b4948ad13ccf21ce6b7ea97c17d1ebc37851' +
          'd387542dd9cf6e9ce5dcf41d6c7444f22746da527092496afe132dc5373ec678a4e5d' +
          'ace9eaa292dfddc596f6dfd5df6ab23a8620ff3086f308de84340d94b6dd81dffd00d' +
          'b8bf8e01e52943f4fef50a55d3c68cf0e841a9ba24f24b2324152d24d71baa0e6c6fb' +
          '5cee4c195459f31d666bb85e5c805cbcc3e5ebb2b77a52284d846c776bd3615069aaa' +
          'f8993b6faa98a8c5c68849b12ea2310f7dabf1ca08108c1f24afaa2841a7774cf316c' +
          'bfb722f28145459f33531ee289f7cb9402130b1b705f2d5141ed7fd8aede50204929a' +
          'a2a1e75c27c77659dbd9791b931170c308e3f1097587432cb53260e408e2dcdfdf28e' +
          '9d781a2622dabee7965b9916957e8aa072df8508802bf414efa4143a1fec0253cf340' +
          '9a652c1ce6b14f5f8c71bbe322674920decc1150888b3123403b1074a648fd912544c' +
          '59237126845639e71ab1daf3a458b2bb37f2cf0973016fc9318915e9d9b7f8db32298' +
          'c30c2e1a961bb1c3dbd816aee609f746a10b555b5dcdd90b459ca5e633ee178186072' +
          '3e7ab985b57e6424b2f3a678f2546391164e1c5c8866c53c67a5930b5a57faab9d5ea' +
          '54c8ec20831f31c875785f1a0e9c86692b912d0d28fdb153fe715f3602431ae014148' +
          '1d3bfe8e66e0fcfe57799e1b8e669fc71a85e45d9918c8175144d46e8798d07f92915' +
          '3fceff1dd580cdd5b20ae69c90e12d0cdf6ae98a68e95f798112a8978e899d3f47331' +
          'a2b29f61d1bc2a3991b20b390635322bb0f10a68374897597f5f573f7d11d0e7c9cbb' +
          '3d3ee1554ad071b24067d2141cceabad8dcb45ef02c0cecbf5a08043def96b93fd328' +
          'c6bb69e0cff54453a21f81afe2a2ece8036d8e3afcdb3ac630e6cce252baafca14d2d' +
          'b5f0c93a28ea5700aa7c3da9fb5195e84a141f26b19b07c33d5da16d1c761ff282895' +
          '6107a62582f4654f2f79c3c88639d9134f4a641d9ea5e8f9500c3ccb2ab434c245dce' +
          'b54bcd22637787845df11cdeb15ca67c6d62b5ffc2ed656c9428c7e313455a45b982f' +
          '4b9daaaff4c2f7bad9ef50fec0c9f14b8fe92c7edc039aa7974317e25da3de5211756' +
          '133177661681cd0c6863fb47b3c2dfa0550f0f6042e7534500c21b39fd5d778f59f0f' +
          '422b30c861e88f4202a0192f43734715216c5edb431e1a13cb9c32fe142b6d046ce20' +
          'e0a5b026672a2f2d42ff58f2ec09ad1bdb6fac5aab0bcfec193c86ebb84f7bdfe649c' +
          '52ef6df05474546dc175f00aef053e96cf4770c3b2ff97f10ef1893e2e852d0be39f5' +
          'e476241c13ef254cf0e4289d1592d25411af783554f7b95d4bb4a81da842fecbc5e1e' +
          'ad5c40bd8b982abefe19b96616f647dceb2e6bb08573b030defbc348a4195a0248f2a' +
          '78260a4e275c5ea85faf1e97d12a1d486ff64adf2b572240242c9bf1fe0593e748035' +
          '997ef610367d56aedf82e240357b9d496bd5222a28b456d9ea518429907cee2fa8b70' +
          'ae3bd7265bbe5f4e471f40702fd457820ce530bd59c7d09248cedfe62d27143b305c1' +
          'ee5a5badb8b576c48f7ff88a11ce5108b6ef4c2c9cb997a24a9a5237845577bcc8e76' +
          'fd04892a0d5744bf88e8eb20e334b8a0e4916bf4cd03c54050da3a7415d24363d1071' +
          'bf140fee666caf3b7e0d8e768643fa4c970a75a888d459edae265d5af08e6506ac215' +
          '72aa1308e6498b19ea89bf8b18de2d2eaf2073705f98fcda5647e9253dc7e6733ba84' +
          'da21e75a9852737c49d24fb321ae7e4b5669e12e70c64f4ca182494ae518d990dc622' +
          '133ca16fd9627b267adaf8e6f2c5c56d36efeaf502146e3c33fafe55f54fd40194c4e' +
          '8b95c7aa26ab24c3bf3da6c5f456cc5bb56d83a686ae57d388b3bd4679731a87e3a7f' +
          'fa6ea1c7e6e738dccc898a14181c5b46cb48ccd587f9f4f749bbd85f7f45c1fd0e4f8' +
          'c438a39631444ea3d6822282fa70a0d9cd6bfd455890bdf6f5b1676d646f7c717a156' +
          '46cd1cc3ec4217bfb528b7a584779b1114f0baed61f7d02d8de3b3d0672bc146afcb2' +
          '9871286b7d98bce0de2482c7294aa337cb7289c696784821747aa0359cb81df7644d0' +
          '25f8e02f2a6f0973c4992691806588a43702f2d01fbe1384927c9224b90e1b22da727' +
          'c5475d8b5858098a242f186d14f4aa65daaff8ef9b9b38ffb428dfc9163ae29826fd9' +
          '6d49d116f5129706857e36969431f004455846aee64b95ca84ecc37d327886bdcdf03' +
          '078b11f7fd6376ef3b850b67813b7b0064273c5990226821a8950b485081bd9ff8500' +
          '6191e2d46545fdc8f72217bc6972f0dd3c2eac44c03e24447b86f5e79e1afaaf67ab3' +
          '0932f9eaf07f4888209b153c039e5866274d0e6a2a0b1a00336f04414ae44d380000',
        'hex',
      ),
    });
    psbt.addOutputs([
      {
        nonce,
        asset,
        value: liquid.confidential.satoshiToConfidentialValue(99996500),
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
      },
      {
        nonce,
        asset,
        value: liquid.confidential.satoshiToConfidentialValue(3500),
        script: Buffer.alloc(0),
      },
    ]);
    psbt.blindOutputs(blindingPrivkeys, bliningPubkeys);
    psbt.signInput(0, bob);
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    psbt.extractTransaction();
  });

  it('can create (and broadcast via 3PBP) a typical Transaction', async () => {
    // these are { payment: Payment; keys: ECPair[] }
    const alice1 = createPayment('p2pkh');
    const alice2 = createPayment('p2pkh');

    // give Alice 2 unspent outputs
    const inputData1 = await getInputData(alice1.payment, false, 'noredeem');
    const inputData2 = await getInputData(alice2.payment, false, 'noredeem');
    {
      const {
        hash, // string of txid or Buffer of tx hash. (txid and hash are reverse order)
        index, // the output index of the txo you are spending
        nonWitnessUtxo, // the full previous transaction as a Buffer
      } = inputData1;
      assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData1);
    }

    // network is only needed if you pass an address to addOutput
    // using script (Buffer of scriptPubkey) instead will avoid needed network.
    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData1) // alice1 unspent
      .addInput(inputData2) // alice2 unspent
      .addOutput({
        asset,
        nonce,
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        value: satoshiToConfidentialValue(150000000),
      }) // the actual spend
      .addOutput({
        asset,
        nonce,
        script: alice2.payment.output,
        value: satoshiToConfidentialValue(49999300),
      }) // Alice's change
      .addOutput({
        asset,
        nonce,
        script: Buffer.alloc(0),
        value: satoshiToConfidentialValue(700),
      }); // fees in Liquid are explicit

    // Let's show a new feature with PSBT.
    // We can have multiple signers sign in parrallel and combine them.
    // (this is not necessary, but a nice feature)

    // encode to send out to the signers
    const psbtBaseText = psbt.toBase64();

    // each signer imports
    const signer1 = liquid.Psbt.fromBase64(psbtBaseText);
    const signer2 = liquid.Psbt.fromBase64(psbtBaseText);

    // Alice signs each input with the respective private keys
    // signInput and signInputAsync are better
    // (They take the input index explicitly as the first arg)
    signer1.signAllInputs(alice1.keys[0]);
    signer2.signAllInputs(alice2.keys[0]);

    // If your signer object's sign method returns a promise, use the following
    // await signer2.signAllInputsAsync(alice2.keys[0])

    // encode to send back to combiner (signer 1 and 2 are not near each other)
    const s1text = signer1.toBase64();
    const s2text = signer2.toBase64();

    const final1 = liquid.Psbt.fromBase64(s1text);
    const final2 = liquid.Psbt.fromBase64(s2text);

    // final1.combine(final2) would give the exact same result
    psbt.combine(final1, final2);

    // Finalizer wants to check all signatures are valid before finalizing.
    // If the finalizer wants to check for specific pubkeys, the second arg
    // can be passed. See the first multisig example below.
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(psbt.validateSignaturesOfInput(1), true);

    // This step it new. Since we separate the signing operation and
    // the creation of the scriptSig and witness stack, we are able to
    psbt.finalizeAllInputs();

    // build and broadcast our RegTest network
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    // to build and broadcast to the actual Bitcoin network, see https://github.com/bitcoinjs/bitcoinjs-lib/issues/839
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction', async () => {
    // these are { payment: Payment; keys: ECPair[] }
    const alice1 = createPayment('p2pkh', undefined, undefined, true);
    const blindingPubkeys = ['', ''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );

    // give Alice 2 unspent outputs
    const inputData1 = await getInputData(alice1.payment, false, 'noredeem');
    {
      const {
        hash, // string of txid or Buffer of tx hash. (txid and hash are reverse order)
        index, // the output index of the txo you are spending
        nonWitnessUtxo, // the full previous transaction as a Buffer
      } = inputData1;
      assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData1);
    }

    // network is only needed if you pass an address to addOutput
    // using script (Buffer of scriptPubkey) instead will avoid needed network.
    let psbt = await new liquid.Psbt({ network: regtest })
      .addInput(inputData1) // alice1 unspent
      .addOutput({
        asset,
        nonce,
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        value: satoshiToConfidentialValue(50000000),
      }) // the actual spend
      .addOutput({
        asset,
        nonce,
        script: alice1.payment.output,
        value: satoshiToConfidentialValue(49993000),
      }) // Alice's change
      .addOutput({
        asset,
        nonce,
        script: Buffer.alloc(0),
        value: satoshiToConfidentialValue(7000),
      }) // fees in Liquid are explicit
      .blindOutputs(alice1.blindingKeys, blindingPubkeys);

    psbt = psbt.signAllInputs(alice1.keys[0]);

    // Finalizer wants to check all signatures are valid before finalizing.
    // If the finalizer wants to check for specific pubkeys, the second arg
    // can be passed. See the first multisig example below.
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);

    // This step it new. Since we separate the signing operation and
    // the creation of the scriptSig and witness stack, we are able to
    psbt.finalizeAllInputs();

    // build and broadcast our RegTest network
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    // to build and broadcast to the actual Bitcoin network, see https://github.com/bitcoinjs/bitcoinjs-lib/issues/839
  });

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction' +
      ' with confidential AND unconfidential outputs',
    async () => {
      // these are { payment: Payment; keys: ECPair[] }
      const alicePayment = createPayment('p2pkh', undefined, undefined, true); // confidential
      const bobPayment = createPayment('p2pkh', undefined, undefined, false); // unconfidential

      const aliceBlindingPubKey = liquid.ECPair.fromPrivateKey(
        alicePayment.blindingKeys[0],
      ).publicKey!;

      const aliceBlindingPrivateKey: Buffer = alicePayment.blindingKeys[0];

      // give Alice unspent outputs
      const inputData1 = await getInputData(
        alicePayment.payment,
        false,
        'noredeem',
      );
      {
        const {
          hash, // string of txid or Buffer of tx hash. (txid and hash are reverse order)
          index, // the output index of the txo you are spending
          nonWitnessUtxo, // the full previous transaction as a Buffer
        } = inputData1;
        assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData1);
      }

      // network is only needed if you pass an address to addOutput
      // using script (Buffer of scriptPubkey) instead will avoid needed network.
      let psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData1) // alice unspent
        .addOutput({
          asset,
          nonce,
          script: bobPayment.payment.output,
          value: satoshiToConfidentialValue(50000000),
        }) // the actual spend to bob
        .addOutput({
          asset,
          nonce,
          script: alicePayment.payment.output,
          value: satoshiToConfidentialValue(29993000),
        }) // Alice's change
        .addOutput({
          asset,
          nonce,
          script: alicePayment.payment.output,
          value: satoshiToConfidentialValue(20000000),
        }) // Alice's change bis
        .addOutput({
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: satoshiToConfidentialValue(7000),
        }) // fees in Liquid are explicit
        .blindOutputsByIndex(
          new Map().set(0, aliceBlindingPrivateKey),
          new Map().set(1, aliceBlindingPubKey).set(2, aliceBlindingPubKey),
        );

      psbt = psbt.signAllInputs(alicePayment.keys[0]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      psbt.finalizeAllInputs();

      // build and broadcast our RegTest network
      await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction' +
      ' with confidential AND unconfidential inputs',
    async () => {
      // these are { payment: Payment; keys: ECPair[] }
      const alicePaymentUnconfidential = createPayment(
        'p2pkh',
        undefined,
        undefined,
        false,
      ); // unconfidential

      const alicePaymentConfidential = createPayment(
        'p2pkh',
        undefined,
        undefined,
        true,
      ); // confidential
      const bobPayment = createPayment('p2pkh', undefined, undefined, false); // unconfidential

      const aliceBlindingPubKey = liquid.ECPair.fromPrivateKey(
        alicePaymentConfidential.blindingKeys[0],
      ).publicKey!;

      const aliceBlindingPrivateKey: Buffer =
        alicePaymentConfidential.blindingKeys[0];

      // give Alice unspent outputs
      const inputDataUnconfidential = await getInputData(
        alicePaymentUnconfidential.payment,
        false,
        'noredeem',
      );

      const inputDataConfidential = await getInputData(
        alicePaymentConfidential.payment,
        false,
        'noredeem',
      );

      // network is only needed if you pass an address to addOutput
      // using script (Buffer of scriptPubkey) instead will avoid needed network.
      let psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputDataUnconfidential) // alice unspent (unconfidential)
        .addInput(inputDataConfidential) // alice unspent (confidential)
        .addOutput({
          asset,
          nonce,
          script: bobPayment.payment.output,
          value: satoshiToConfidentialValue(99993000),
        }) // the actual spend to bob
        .addOutput({
          asset,
          nonce,
          script: alicePaymentConfidential.payment.output,
          value: satoshiToConfidentialValue(99999000),
        }) // Alice's change
        .addOutput({
          asset,
          nonce,
          script: alicePaymentConfidential.payment.output,
          value: satoshiToConfidentialValue(1000),
        }) // Alice's change bis (need two blind outputs)
        .addOutput({
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: satoshiToConfidentialValue(7000),
        }) // fees in Liquid are explicit
        .blindOutputsByIndex(
          new Map().set(1, aliceBlindingPrivateKey),
          new Map().set(1, aliceBlindingPubKey).set(2, aliceBlindingPubKey),
        );

      psbt = psbt
        .signInput(0, alicePaymentUnconfidential.keys[0])
        .signInput(1, alicePaymentConfidential.keys[0]);

      assert.doesNotThrow(() => liquid.Psbt.fromBase64(psbt.toBase64()));

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      assert.strictEqual(psbt.validateSignaturesOfInput(1), true);

      psbt.finalizeAllInputs();

      // build and broadcast our RegTest network
      await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction' +
      ' using blinders',
    async () => {
      // these are { payment: Payment; keys: ECPair[] }
      const alicePaymentConfidential = createPayment(
        'p2wpkh',
        undefined,
        undefined,
        true,
      ); // confidential

      const bobPayment = createPayment('p2pkh', undefined, undefined, false); // unconfidential

      const aliceBlindingPubKey = liquid.ECPair.fromPrivateKey(
        alicePaymentConfidential.blindingKeys[0],
      ).publicKey!;

      const aliceBlindingPrivateKey: Buffer =
        alicePaymentConfidential.blindingKeys[0];

      const inputDataConfidential = await getInputData(
        alicePaymentConfidential.payment,
        true,
        'noredeem',
      );

      const inputBlindingData = unblindOutputWithKey(
        inputDataConfidential.witnessUtxo,
        aliceBlindingPrivateKey,
      );

      // network is only needed if you pass an address to addOutput
      // using script (Buffer of scriptPubkey) instead will avoid needed network.
      const psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputDataConfidential) // alice unspent (confidential)
        .addOutput({
          asset,
          nonce,
          script: bobPayment.payment.output,
          value: satoshiToConfidentialValue(1000),
        }) // the actual spend to bob
        .addOutput({
          asset,
          nonce,
          script: alicePaymentConfidential.payment.output,
          value: satoshiToConfidentialValue(99991000),
        }) // Alice's change
        .addOutput({
          asset,
          nonce,
          script: alicePaymentConfidential.payment.output,
          value: satoshiToConfidentialValue(1000),
        }) // Alice's change bis (need two blind outputs)
        .addOutput({
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: satoshiToConfidentialValue(7000),
        }) // fees in Liquid are explicit
        .blindOutputsByIndex(
          new Map().set(0, inputBlindingData),
          new Map().set(1, aliceBlindingPubKey).set(2, aliceBlindingPubKey),
        );

      psbt.signInput(0, alicePaymentConfidential.keys[0]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);

      psbt.finalizeAllInputs();

      // build and broadcast our RegTest network
      await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction with an OP_RETURN output', async () => {
    const alice1 = createPayment('p2pkh');
    const inputData1 = await getInputData(alice1.payment, false, 'noredeem');

    const data = Buffer.from('bitcoinjs-lib', 'utf8');
    const embed = liquid.payments.embed({ data: [data] });

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData1)
      .addOutput({
        asset,
        nonce,
        script: embed.output!,
        value: liquid.confidential.satoshiToConfidentialValue(500),
      })
      .addOutput({
        asset,
        nonce,
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        value: liquid.confidential.satoshiToConfidentialValue(99999000),
      })
      .addOutput({
        asset,
        nonce,
        script: Buffer.alloc(0),
        value: liquid.confidential.satoshiToConfidentialValue(500),
      })
      .signInput(0, alice1.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    // build and broadcast to the RegTest network
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2MS(2 of 4)) (multisig) input', async () => {
    const multisig = createPayment('p2sh-p2ms(2 of 4)');
    const inputData1 = await getInputData(multisig.payment, false, 'p2sh');
    {
      const {
        hash,
        index,
        nonWitnessUtxo,
        redeemScript, // NEW: P2SH needs to give redeemScript when adding an input.
      } = inputData1;
      assert.deepStrictEqual(
        { hash, index, nonWitnessUtxo, redeemScript },
        inputData1,
      );
    }

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData1)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, multisig.keys[0])
      .signInput(0, multisig.keys[2]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, multisig.keys[0].publicKey),
      true,
    );
    assert.throws(() => {
      psbt.validateSignaturesOfInput(0, multisig.keys[3].publicKey);
    }, new RegExp('No signatures for this pubkey'));
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2WPKH) input', async () => {
    const p2sh = createPayment('p2sh-p2wpkh');
    const inputData = await getInputData(p2sh.payment, true, 'p2sh');
    const inputData2 = await getInputData(p2sh.payment, true, 'p2sh');

    {
      const {
        hash,
        index,
        witnessUtxo, // NEW: this is an object of the output being spent { script: Buffer; value: Satoshis; }
        redeemScript,
      } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, redeemScript },
        inputData,
      );
    }
    const keyPair = p2sh.keys[0];
    const outputData = {
      asset: inputData.witnessUtxo.asset,
      nonce,
      script: p2sh.payment.output, // sending to myself for fun
      value: liquid.confidential.satoshiToConfidentialValue(199999300),
    };
    const outputData2 = {
      asset: inputData.witnessUtxo.asset,
      nonce,
      script: Buffer.alloc(0), // fees
      value: liquid.confidential.satoshiToConfidentialValue(700),
    };

    const tx = new liquid.Psbt()
      .addInputs([inputData, inputData2])
      .addOutputs([outputData, outputData2])
      .signAllInputs(keyPair)
      .finalizeAllInputs()
      .extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction, w/ a P2SH(P2WPKH) input', async () => {
    const p2sh = createPayment('p2sh-p2wpkh', undefined, undefined, true);
    const inputData = await getInputData(p2sh.payment, true, 'p2sh');
    const inputData2 = await getInputData(p2sh.payment, true, 'p2sh');
    const blindingKeys = ['', ''].map(() => p2sh.blindingKeys[0]);
    const blindingPubkeys = ['', ''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );

    {
      const { hash, index, witnessUtxo, redeemScript } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, redeemScript },
        inputData,
      );
    }
    const keyPair = p2sh.keys[0];
    const outputData = {
      asset,
      nonce,
      script: p2sh.payment.output, // change
      value: liquid.confidential.satoshiToConfidentialValue(159993000),
    };
    const outputData2 = {
      asset,
      nonce,
      script: Buffer.from(
        '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
        'hex',
      ), // actual spend
      value: liquid.confidential.satoshiToConfidentialValue(40000000),
    };
    const outputData3 = {
      asset,
      nonce,
      script: Buffer.alloc(0), // fees
      value: liquid.confidential.satoshiToConfidentialValue(7000),
    };

    const psbt = await new liquid.Psbt()
      .addInputs([inputData, inputData2])
      .addOutputs([outputData, outputData2, outputData3])
      .blindOutputs(blindingKeys, blindingPubkeys);

    const tx = psbt.signAllInputs(keyPair);

    const toBroadcast = liquid.Psbt.fromBase64(tx.toBase64())
      .finalizeAllInputs()
      .extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(toBroadcast.toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2WPKH) input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2sh = createPayment('p2sh-p2wpkh');
    const inputData = await getInputData(p2sh.payment, false, 'p2sh');
    const inputData2 = await getInputData(p2sh.payment, false, 'p2sh');
    const keyPair = p2sh.keys[0];
    const outputData = {
      asset,
      nonce,
      script: p2sh.payment.output,
      value: liquid.confidential.satoshiToConfidentialValue(199999300),
    };
    const outputData2 = {
      asset,
      nonce,
      script: Buffer.alloc(0),
      value: liquid.confidential.satoshiToConfidentialValue(700),
    };
    const tx = new liquid.Psbt()
      .addInputs([inputData, inputData2])
      .addOutputs([outputData, outputData2])
      .signAllInputs(keyPair)
      .finalizeAllInputs()
      .extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
  });

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a' +
      'P2SH(P2WPKH) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2sh = createPayment('p2sh-p2wpkh', undefined, undefined, true);
      const inputData = await getInputData(p2sh.payment, false, 'p2sh');
      const inputData2 = await getInputData(p2sh.payment, false, 'p2sh');
      const blindingKeys = ['', ''].map(() => p2sh.blindingKeys[0]);
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const keyPair = p2sh.keys[0];
      const outputData = {
        asset,
        nonce,
        script: p2sh.payment.output,
        value: liquid.confidential.satoshiToConfidentialValue(199996500),
      };
      const outputData2 = {
        asset,
        nonce,
        script: Buffer.alloc(0),
        value: liquid.confidential.satoshiToConfidentialValue(3500),
      };
      const psbt = await new liquid.Psbt()
        .addInputs([inputData, inputData2])
        .addOutputs([outputData, outputData2])
        .blindOutputs(blindingKeys, blindingPubkeys);

      const tx = psbt
        .signAllInputs(keyPair)
        .finalizeAllInputs()
        .extractTransaction();

      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input', async () => {
    // the only thing that changes is you don't give a redeemscript for input data

    const p2wpkh = createPayment('p2wpkh');
    const inputData = await getInputData(p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, p2wpkh.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction, w/ a P2WPKH input', async () => {
    // the only thing that changes is you don't give a redeemscript for input data

    const p2wpkh = createPayment('p2wpkh', undefined, undefined, true);
    const blindingPubkeys = [''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );
    const inputData = await getInputData(p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    let psbt = await new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99996500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(3500),
        },
      ])
      .blindOutputs(p2wpkh.blindingKeys, blindingPubkeys);

    psbt = psbt.signInput(0, p2wpkh.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2wpkh = createPayment('p2wpkh');
    const inputData = await getInputData(p2wpkh.payment, false, 'noredeem');
    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, p2wpkh.keys[0]);
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
  });

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a' +
      'P2WPKH input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2wpkh = createPayment('p2wpkh', undefined, undefined, true);
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2wpkh.payment, false, 'noredeem');
      let psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2wpkh.blindingKeys, blindingPubkeys);

      psbt = psbt.signInput(0, p2wpkh.keys[0]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WSH(P2PK) input', async () => {
    const p2wsh = createPayment('p2wsh-p2pk');
    const inputData = await getInputData(p2wsh.payment, true, 'p2wsh');
    {
      const {
        hash,
        index,
        witnessUtxo,
        witnessScript, // NEW: A Buffer of the witnessScript
      } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, witnessScript },
        inputData,
      );
    }

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, p2wsh.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction, w/ a P2WSH(P2PK) input', async () => {
    const p2wsh = createPayment('p2wsh-p2pk', undefined, undefined, true);
    const blindingPubkeys = [''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );
    const inputData = await getInputData(p2wsh.payment, true, 'p2wsh');
    {
      const {
        hash,
        index,
        witnessUtxo,
        witnessScript, // NEW: A Buffer of the witnessScript
      } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, witnessScript },
        inputData,
      );
    }

    let psbt = await new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99996500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(3500),
        },
      ])
      .blindOutputs(p2wsh.blindingKeys, blindingPubkeys);

    psbt = psbt.signInput(0, p2wsh.keys[0]);
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WSH(P2PK) input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2wsh = createPayment('p2wsh-p2pk');
    const inputData = await getInputData(p2wsh.payment, false, 'p2wsh');
    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, p2wsh.keys[0]);
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
  });

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a' +
      'P2WSH(P2PK) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2wsh = createPayment('p2wsh-p2pk', undefined, undefined, true);
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2wsh.payment, false, 'p2wsh');
      let psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2wsh.blindingKeys, blindingPubkeys);

      psbt = psbt.signInput(0, p2wsh.keys[0]).finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
      'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input',
    async () => {
      const p2sh = createPayment('p2sh-p2wsh-p2ms(3 of 4)');
      const inputData = await getInputData(p2sh.payment, true, 'p2sh-p2wsh');
      {
        const {
          hash,
          index,
          witnessUtxo,
          redeemScript,
          witnessScript,
        } = inputData;
        assert.deepStrictEqual(
          { hash, index, witnessUtxo, redeemScript, witnessScript },
          inputData,
        );
      }

      const psbt = new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99999500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(500),
          },
        ])
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      assert.strictEqual(
        psbt.validateSignaturesOfInput(0, p2sh.keys[3].publicKey),
        true,
      );
      assert.throws(() => {
        psbt.validateSignaturesOfInput(0, p2sh.keys[1].publicKey);
      }, new RegExp('No signatures for this pubkey'));
      psbt.finalizeAllInputs();

      const tx = psbt.extractTransaction();

      // build and broadcast to the Bitcoin RegTest network
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a ' +
      'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input',
    async () => {
      const p2sh = createPayment(
        'p2sh-p2wsh-p2ms(3 of 4)',
        undefined,
        undefined,
        true,
      );
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2sh.payment, true, 'p2sh-p2wsh');
      {
        const {
          hash,
          index,
          witnessUtxo,
          redeemScript,
          witnessScript,
        } = inputData;
        assert.deepStrictEqual(
          { hash, index, witnessUtxo, redeemScript, witnessScript },
          inputData,
        );
      }

      const psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2sh.blindingKeys, blindingPubkeys);

      psbt
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      assert.strictEqual(
        psbt.validateSignaturesOfInput(0, p2sh.keys[3].publicKey),
        true,
      );
      assert.throws(() => {
        psbt.validateSignaturesOfInput(0, p2sh.keys[1].publicKey);
      }, new RegExp('No signatures for this pubkey'));
      psbt.finalizeAllInputs();

      const tx = psbt.extractTransaction();

      // build and broadcast to the Bitcoin RegTest network
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
      'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2sh = createPayment('p2sh-p2wsh-p2ms(3 of 4)');
      const inputData = await getInputData(p2sh.payment, false, 'p2sh-p2wsh');
      const psbt = new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99999500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(500),
          },
        ])
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a ' +
      'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2sh = createPayment(
        'p2sh-p2wsh-p2ms(3 of 4)',
        undefined,
        undefined,
        true,
      );
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2sh.payment, false, 'p2sh-p2wsh');
      const psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2sh.blindingKeys, blindingPubkeys);

      psbt
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3])
        .finalizeAllInputs();

      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
      'P2SH(P2MS(2 of 2)) input with nonWitnessUtxo',
    async () => {
      const myKey = liquid.ECPair.makeRandom({ network: regtest });
      const myKeys = [
        myKey,
        liquid.ECPair.fromPrivateKey(myKey.privateKey!, { network: regtest }),
      ];
      const p2sh = createPayment('p2sh-p2ms(2 of 2)', myKeys);
      const inputData = await getInputData(p2sh.payment, false, 'p2sh');
      const psbt = new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99999500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(500),
          },
        ])
        .signInput(0, p2sh.keys[0]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a ' +
      'P2SH(P2MS(2 of 2)) input with nonWitnessUtxo',
    async () => {
      const myKey = liquid.ECPair.makeRandom({ network: regtest });
      const myKeys = [
        myKey,
        liquid.ECPair.fromPrivateKey(myKey.privateKey!, { network: regtest }),
      ];
      const p2sh = createPayment('p2sh-p2ms(2 of 2)', myKeys, undefined, true);
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2sh.payment, false, 'p2sh');
      const psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2sh.blindingKeys, blindingPubkeys);

      psbt.signInput(0, p2sh.keys[0]).finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input using HD', async () => {
    const hdRoot = bip32.fromSeed(rng(64));
    const masterFingerprint = hdRoot.fingerprint;
    const path = "m/84'/0'/0'/0/0";
    const childNode = hdRoot.derivePath(path);
    const pubkey = childNode.publicKey;

    // This information should be added to your input via updateInput
    // You can add multiple bip32Derivation objects for multisig, but
    // each must have a unique pubkey.
    //
    // This is useful because as long as you store the masterFingerprint on
    // the PSBT Creator's server, you can have the PSBT Creator do the heavy
    // lifting with derivation from your m/84'/0'/0' xpub, (deriving only 0/0 )
    // and your signer just needs to pass in an HDSigner interface (ie. bip32 library)
    const updateData = {
      bip32Derivation: [
        {
          masterFingerprint,
          path,
          pubkey,
        },
      ],
    };
    const p2wpkh = createPayment('p2wpkh', [childNode]);
    const inputData = await getInputData(p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    // You can add extra attributes for updateData into the addInput(s) object(s)
    Object.assign(inputData, updateData);

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      // .updateInput(0, updateData) // if you didn't merge the bip32Derivation with inputData
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInputHD(0, hdRoot); // must sign with root!!!

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, childNode.publicKey),
      true,
    );
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction, w/ a P2WPKH input using HD', async () => {
    const hdRoot = bip32.fromSeed(rng(64));
    const masterFingerprint = hdRoot.fingerprint;
    const path = "m/84'/0'/0'/0/0";
    const childNode = hdRoot.derivePath(path);
    const pubkey = childNode.publicKey;

    // This information should be added to your input via updateInput
    // You can add multiple bip32Derivation objects for multisig, but
    // each must have a unique pubkey.
    //
    // This is useful because as long as you store the masterFingerprint on
    // the PSBT Creator's server, you can have the PSBT Creator do the heavy
    // lifting with derivation from your m/84'/0'/0' xpub, (deriving only 0/0 )
    // and your signer just needs to pass in an HDSigner interface (ie. bip32 library)
    const updateData = {
      bip32Derivation: [
        {
          masterFingerprint,
          path,
          pubkey,
        },
      ],
    };
    const p2wpkh = createPayment('p2wpkh', [childNode], undefined, true);
    const blindingPubkeys = [''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );
    const inputData = await getInputData(p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    // You can add extra attributes for updateData into the addInput(s) object(s)
    Object.assign(inputData, updateData);

    const psbt = await new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      // .updateInput(0, updateData) // if you didn't merge the bip32Derivation with inputData
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99996500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(3500),
        },
      ])
      .blindOutputs(p2wpkh.blindingKeys, blindingPubkeys);

    psbt.signInputHD(0, hdRoot); // must sign with root!!!

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, childNode.publicKey),
      true,
    );
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });
});

function createPayment(
  _type: string,
  myKeys?: any[],
  network?: any,
  confidential?: boolean,
): any {
  network = network || regtest;
  const splitType = _type.split('-').reverse();
  const isMultisig = splitType[0].slice(0, 4) === 'p2ms';
  const keys = myKeys || [];
  const blindingKeys: Buffer[] = [];
  let m: number | undefined;
  if (isMultisig) {
    const match = splitType[0].match(/^p2ms\((\d+) of (\d+)\)$/);
    m = parseInt(match![1], 10);
    let n = parseInt(match![2], 10);
    if (keys.length > 0 && keys.length !== n) {
      throw new Error('Need n keys for multisig');
    }
    while (!myKeys && n > 1) {
      keys.push(liquid.ECPair.makeRandom({ network }));
      n--;
    }
  }
  if (!myKeys) keys.push(liquid.ECPair.makeRandom({ network }));
  if (confidential)
    blindingKeys.push(liquid.ECPair.makeRandom({ network }).privateKey!);

  let payment: any;
  splitType.forEach(type => {
    if (type.slice(0, 4) === 'p2ms') {
      payment = liquid.payments.p2ms({
        m,
        pubkeys: keys.map(key => key.publicKey).sort(),
        network,
      });
    } else if (['p2sh', 'p2wsh'].indexOf(type) > -1) {
      const blindkey =
        confidential && (type === 'p2sh' || splitType.indexOf('p2sh') < 0)
          ? liquid.ECPair.fromPrivateKey(blindingKeys[0]).publicKey
          : undefined;
      payment = (liquid.payments as any)[type]({
        redeem: payment,
        network,
        blindkey,
      });
    } else {
      const blindkey =
        confidential && splitType.length === 1
          ? liquid.ECPair.fromPrivateKey(blindingKeys[0]).publicKey
          : undefined;
      payment = (liquid.payments as any)[type]({
        pubkey: keys[0].publicKey,
        network,
        blindkey,
      });
    }
  });

  return {
    payment,
    keys,
    blindingKeys,
  };
}

function getAddress(script: any, scriptType: string): string {
  if (scriptType === 'p2sh') {
    return liquid.address.toBase58Check(
      liquid.crypto.hash160(script),
      regtest.scriptHash,
    );
  }

  throw new Error('Invalid script type');
}

async function getInputData(
  payment: any,
  isSegwit: boolean,
  redeemType: string,
): Promise<any> {
  const address =
    payment.confidentialAddress ||
    payment.address! ||
    getAddress(payment.output, redeemType);
  const unspent = await regtestUtils.faucet(address);
  const utx = await regtestUtils.fetchUtxo(unspent.txid);
  // this is needed to eventually retrieve confidential proofs from tx outputs
  const prevTx = liquid.Transaction.fromHex(utx.txHex);

  // for non segwit inputs, you must pass the full transaction buffer
  const nonWitnessUtxo = Buffer.from(utx.txHex, 'hex');
  const witnessUtxo = prevTx.outs[unspent.vout];

  const mixin = isSegwit ? { witnessUtxo } : { nonWitnessUtxo };
  const mixin2: any = {};
  switch (redeemType) {
    case 'p2sh':
      mixin2.redeemScript = payment.redeem.output;
      break;
    case 'p2wsh':
      mixin2.witnessScript = payment.redeem.output;
      break;
    case 'p2sh-p2wsh':
      mixin2.witnessScript = payment.redeem.redeem.output;
      mixin2.redeemScript = payment.redeem.output;
      break;
  }

  return {
    hash: Buffer.from(unspent.txid, 'hex').reverse(),
    index: unspent.vout,
    ...mixin,
    ...mixin2,
  };
}
