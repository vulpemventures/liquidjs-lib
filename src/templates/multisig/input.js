'use strict';
// OP_0 [signatures ...]
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
const script_1 = require('../../script');
function partialSignature(value) {
  return (
    value === script_1.OPS.OP_0 || bscript.isCanonicalScriptSignature(value)
  );
}
function check(script, allowIncomplete) {
  const chunks = bscript.decompile(script);
  if (chunks.length < 2) return false;
  if (chunks[0] !== script_1.OPS.OP_0) return false;
  if (allowIncomplete) {
    return chunks.slice(1).every(partialSignature);
  }
  return chunks.slice(1).every(bscript.isCanonicalScriptSignature);
}
exports.check = check;
check.toJSON = () => {
  return 'multisig input';
};
