'use strict';
// {pubKey} OP_CHECKSIG
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
function check(script) {
  const chunks = bscript.decompile(script);
  return (
    chunks.length === 2 &&
    bscript.isCanonicalPubKey(chunks[0]) &&
    chunks[1] === script_1.OPS.OP_CHECKSIG
  );
}
exports.check = check;
check.toJSON = () => {
  return 'pubKey output';
};
