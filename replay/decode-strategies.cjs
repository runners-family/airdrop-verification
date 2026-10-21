'use strict';
// Mandatory raw decoding. Independent pure codec runtime; pinned SDK layouts.
const fs = require('fs'), path = require('path'), Module = require('module'), zlib = require('zlib');
const [inputs, sdkBuild, output] = process.argv.slice(2);
if (!inputs || !sdkBuild || !output) throw new Error('Expected inputs, SDK layout tree and output');
const runtime = path.dirname(__filename);
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function (request, parent, ...rest) {
  if (request === '@solana/codecs') return path.join(runtime, 'offline-codecs.cjs');
  if (request === '@solana/web3.js') return path.join(runtime, 'offline-publickey.cjs');
  return originalResolve.call(this, request, parent, ...rest);
};
const file = path.resolve(sdkBuild, 'client/vaults/accounts/exponentStrategyVault.js');
let source = fs.readFileSync(file, 'utf8');
const original = 'const vaultConfig_1 = require("../types/vaultConfig");';
if (!source.includes(original)) throw new Error('Unexpected pinned SDK layout');
source = source.replace(original, '');
source = source.replace('const codecs_1 = require("@solana/codecs");', `const codecs_1 = require("@solana/codecs");
const wp = require('../types/withdrawalPeriodSettings');
const vaultConfig_1={vaultConfigCodec:codecs_1.getStructCodec([
['reservesShareBp',codecs_1.getU32Codec()],['withdrawalPeriod',wp.withdrawalPeriodSettingsCodec],
['fastWithdrawalCutBp',codecs_1.getU32Codec()],['instantWithdrawalWindowLimitBp',codecs_1.getU32Codec()],
['managementFeeBps',codecs_1.getU64Codec()]])};`);
const instance = new Module(file, module);
instance.filename = file;
instance.paths = Module._nodeModulePaths(path.dirname(file));
instance._compile(source, file);
const decode = instance.exports.deserializeExponentStrategyVaultAccount;
const files = fs.readdirSync(inputs).filter(name => /^exponent-current-strategy-state-\d+\.json\.gz$/.test(name))
  .sort((a, b) => Number(a.match(/(\d+)\.json\.gz$/)[1]) - Number(b.match(/(\d+)\.json\.gz$/)[1]));
if (!files.length) throw new Error('Missing raw strategy batches');
const rows = [], unsupported = [];
for (const name of files) {
  const response = JSON.parse(zlib.gunzipSync(fs.readFileSync(path.join(inputs, name))));
  const keys = JSON.parse(fs.readFileSync(path.join(inputs, name.replace('.json.gz', '.metadata.json')))).rpc_request.params[0];
  if (keys.length !== response.result.value.length) throw new Error('Batch length differs');
  response.result.value.forEach((account, index) => {
    if (!account) return;
    try {
      rows.push({address: keys[index], owner: account.owner, slot: response.result.context.slot,
        data: decode(Buffer.from(account.data[0], 'base64'))});
    } catch (_) {
      unsupported.push({address: keys[index], reason: 'unsupported_pinned_layout'});
    }
  });
}
fs.mkdirSync(output, {recursive: true});
fs.writeFileSync(path.join(output, 'decoded.json'), JSON.stringify(rows, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2) + '\n');
fs.writeFileSync(path.join(output, 'unsupported.json'), JSON.stringify(unsupported, null, 2) + '\n');
process.stdout.write(JSON.stringify({decoded: rows.length, unsupported: unsupported.length, batches: files.length}) + '\n');
