'use strict';
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function encode58(raw) {
  let value = 0n;
  for (const byte of raw) value = (value << 8n) | BigInt(byte);
  let text = '';
  while (value) {
    text = alphabet[Number(value % 58n)] + text;
    value /= 58n;
  }
  let zeros = 0;
  while (zeros < raw.length && raw[zeros] === 0) zeros++;
  return '1'.repeat(zeros) + text;
}
exports.PublicKey = class PublicKey {
  constructor(raw) {
    this.raw = new Uint8Array(raw);
    if (this.raw.length !== 32) throw new Error('Invalid public key length');
  }
  toBytes() {return new Uint8Array(this.raw);}
  toBase58() {return encode58(this.raw);}
  toJSON() {return this.toBase58();}
};
