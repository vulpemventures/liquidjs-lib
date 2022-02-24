'use strict';
var __importDefault =
  (this && this.__importDefault) ||
  function(mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.ECPair = void 0;
const tiny_secp256k1_1 = __importDefault(require('tiny-secp256k1'));
const ecpair_1 = __importDefault(require('ecpair'));
exports.ECPair = (0, ecpair_1.default)(tiny_secp256k1_1.default);
