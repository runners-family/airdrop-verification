'use strict';
// Independent decoding subset for the pinned Exponent SDK declarations.
// No encoding, network clients, package downloads or environment lookups.
function need(bytes, offset, count) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(count) || offset < 0 || count < 0 || offset + count > bytes.length)
    throw new Error('Truncated account layout');
}
function codec(read) {
  return {read, decode(bytes) {return read(new Uint8Array(bytes), 0)[0];}};
}
function integer(size, big = false) {
  return codec((bytes, offset) => {
    need(bytes, offset, size);
    let value = 0n;
    for (let i = size - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[offset + i]);
    return [big ? value : Number(value), offset + size];
  });
}
const u8 = integer(1), u16 = integer(2), u32 = integer(4), u64 = integer(8, true);
exports.getU8Codec = () => u8;
exports.getU16Codec = () => u16;
exports.getU32Codec = () => u32;
exports.getU64Codec = () => u64;
exports.getBooleanCodec = () => codec((bytes, offset) => {
  const [value, end] = u8.read(bytes, offset);
  if (value > 1) throw new Error('Invalid boolean');
  return [value === 1, end];
});
exports.getBytesCodec = () => codec((bytes, offset) => [Buffer.from(bytes.slice(offset)), bytes.length]);
exports.fixCodecSize = (inner, size) => codec((bytes, offset) => {
  need(bytes, offset, size);
  return [inner.read(bytes.slice(offset, offset + size), 0)[0], offset + size];
});
exports.transformCodec = (inner, encode, decode) => codec((bytes, offset) => {
  const [value, end] = inner.read(bytes, offset);
  return [decode(value), end];
});
exports.getStructCodec = fields => codec((bytes, offset) => {
  const value = {};
  for (const [name, inner] of fields) {
    if (Object.prototype.hasOwnProperty.call(value, name)) throw new Error('Duplicate codec field');
    [value[name], offset] = inner.read(bytes, offset);
  }
  return [value, offset];
});
exports.getArrayCodec = inner => codec((bytes, offset) => {
  let count;
  [count, offset] = u32.read(bytes, offset);
  if (count > bytes.length) throw new Error('Array count exceeds account bound');
  const rows = [];
  for (let i = 0; i < count; i++) {
    let row;
    [row, offset] = inner.read(bytes, offset);
    rows.push(row);
  }
  return [rows, offset];
});
exports.getTupleCodec = fields => codec((bytes, offset) => {
  const rows = [];
  for (const inner of fields) {
    let value;
    [value, offset] = inner.read(bytes, offset);
    rows.push(value);
  }
  return [rows, offset];
});
exports.getDiscriminatedUnionCodec = variants => codec((bytes, offset) => {
  let index;
  [index, offset] = u8.read(bytes, offset);
  if (!variants[index]) throw new Error('Unsupported account variant');
  const [name, inner] = variants[index];
  const [value, end] = inner.read(bytes, offset);
  return [{__kind: name, ...value}, end];
});
