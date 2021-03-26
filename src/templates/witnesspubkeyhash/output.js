'use strict';
// OP_0 {pubKeyHash}
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
    buffer.length === 22 &&
    buffer[0] === script_1.OPS.OP_0 &&
    buffer[1] === 0x14
  );
}
exports.check = check;
check.toJSON = () => {
  return 'Witness pubKeyHash output';
};
