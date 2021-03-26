'use strict';
// {signature}
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
function check(script) {
  const chunks = bscript.decompile(script);
  return chunks.length === 1 && bscript.isCanonicalScriptSignature(chunks[0]);
}
exports.check = check;
check.toJSON = () => {
  return 'pubKey input';
};
