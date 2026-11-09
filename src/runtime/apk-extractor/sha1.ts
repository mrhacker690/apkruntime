/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - SHA-1 Digest Engine (FIPS PUB 180-1)
 * Provides standards-compliant synchronous SHA-1 calculation for DEX file signature verification
 * and independent NIST test vector validation.
 */

/**
 * Pure TypeScript SHA-1 digest calculation (Synchronous).
 * Returns 40-character lowercase hexadecimal hash string.
 */
export function pureJsSha1(message: Uint8Array): string {
  const bytes = pureJsSha1Bytes(message);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Pure TypeScript SHA-1 digest calculation (Synchronous).
 * Returns 20-byte Uint8Array.
 */
export function pureJsSha1Bytes(message: Uint8Array): Uint8Array {
  function leftRotate(n: number, b: number): number {
    return (n << b) | (n >>> (32 - b));
  }

  // Initial hash values
  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  // Pre-processing / Padding
  const len = message.length;
  // Padded length must be multiple of 64 bytes (512 bits)
  const paddedLength = ((len + 8 + 64) >>> 6) << 6;
  const words = new Uint32Array(paddedLength >>> 2);

  for (let i = 0; i < len; i++) {
    words[i >>> 2] |= message[i] << ((3 - (i & 3)) * 8);
  }
  // Append bit '1' (0x80)
  words[len >>> 2] |= 0x80 << ((3 - (len & 3)) * 8);

  // Append length in bits as 64-bit big-endian integer
  const bitLengthLow = (len * 8) >>> 0;
  const bitLengthHigh = Math.floor(len / 0x20000000);
  words[words.length - 2] = bitLengthHigh;
  words[words.length - 1] = bitLengthLow;

  const w = new Uint32Array(80);

  // Process 512-bit (64-byte) blocks
  for (let chunk = 0; chunk < words.length; chunk += 16) {
    for (let i = 0; i < 16; i++) {
      w[i] = words[chunk + i];
    }
    for (let i = 16; i < 80; i++) {
      w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i++) {
      let f = 0;
      let k = 0;

      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }

      const temp = (leftRotate(a, 5) + f + e + k + w[i]) | 0;
      e = d;
      d = c;
      c = leftRotate(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
  }

  const out = new Uint8Array(20);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0 >>> 0, false);
  outView.setUint32(4, h1 >>> 0, false);
  outView.setUint32(8, h2 >>> 0, false);
  outView.setUint32(12, h3 >>> 0, false);
  outView.setUint32(16, h4 >>> 0, false);

  return out;
}
