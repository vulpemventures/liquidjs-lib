'use strict';
// <scriptSig> {serialized scriptPubKey script}
var __importStar =
  (this && this.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
const bscript = __importStar(require('../../script'));
const p2ms = __importStar(require('../multisig'));
const p2pk = __importStar(require('../pubkey'));
const p2pkh = __importStar(require('../pubkeyhash'));
const p2wpkho = __importStar(require('../witnesspubkeyhash/output'));
const p2wsho = __importStar(require('../witnessscripthash/output'));
function check(script, allowIncomplete) {
  const chunks = bscript.decompile(script);
  if (chunks.length < 1) return false;
  const lastChunk = chunks[chunks.length - 1];
  if (!Buffer.isBuffer(lastChunk)) return false;
  const scriptSigChunks = bscript.decompile(
    bscript.compile(chunks.slice(0, -1)),
  );
  const redeemScriptChunks = bscript.decompile(lastChunk);
  // is redeemScript a valid script?
  if (!redeemScriptChunks) return false;
  // is redeemScriptSig push only?
  if (!bscript.isPushOnly(scriptSigChunks)) return false;
  // is witness?
  if (chunks.length === 1) {
    return (
      p2wsho.check(redeemScriptChunks) || p2wpkho.check(redeemScriptChunks)
    );
  }
  // match types
  if (
    p2pkh.input.check(scriptSigChunks) &&
    p2pkh.output.check(redeemScriptChunks)
  )
    return true;
  if (
    p2ms.input.check(scriptSigChunks, allowIncomplete) &&
    p2ms.output.check(redeemScriptChunks)
  )
    return true;
  if (
    p2pk.input.check(scriptSigChunks) &&
    p2pk.output.check(redeemScriptChunks)
  )
    return true;
  return false;
}
exports.check = check;
check.toJSON = () => {
  return 'scriptHash input';
};
