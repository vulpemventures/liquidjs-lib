'use strict';
// OP_HASH160 {scriptHash} OP_EQUAL
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
  const buffer = bscript.compile(script);
  return (
    buffer.length === 23 &&
    buffer[0] === script_1.OPS.OP_HASH160 &&
    buffer[1] === 0x14 &&
    buffer[22] === script_1.OPS.OP_EQUAL
  );
}
exports.check = check;
check.toJSON = () => {
  return 'scriptHash output';
};
