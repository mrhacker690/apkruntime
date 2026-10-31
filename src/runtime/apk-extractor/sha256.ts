/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * APK Runtime Engine - Cryptographic SHA-256 Digest Engine
 * Provides standards-compliant SHA-256 digest calculation via Web Crypto API
 * with an independently verifiable, pure TypeScript fallback.
 */

/**
 * Calculates SHA-256 digest using Web Crypto API when available,
 * falling back to pure TypeScript implementation.
 * Avoids redundant memory copying for large buffers.
 */
export async function calculateSha256(data: Uint8Array | ArrayBuffer): Promise<string> {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);

  if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
    try {
      // Use the underlying buffer view directly without cloning entire arrays
      const subBuffer = (bytes.buffer.byteLength === bytes.byteLength && bytes.byteOffset === 0
        ? bytes.buffer
        : bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)) as ArrayBuffer;

      const hashBuffer = await crypto.subtle.digest('SHA-256', subBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch {
      // Fallback if subtle.digest fails in restricted sandbox environments
    }
  }

  return pureJsSha256(bytes);
}

/**
 * Pure TypeScript SHA-256 implementation (FIPS PUB 180-4 standard).
 * Exported for independent unit verification and test vectors.
 */
export function pureJsSha256(message: Uint8Array): string {
  function rightRotate(value: number, amount: number): number {
    return (value >>> amount) | (value << (32 - amount));
  }

  // Pre-computed SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
  const K: number[] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  // Pre-processing (Padding)
  const len = message.length;
  // Calculate padded length: len + 1 byte (0x80) + padding zeros + 8 bytes length (bits)
  // Padded length must be multiple of 64 bytes (512 bits)
  const paddedLength = ((len + 8 + 64) >>> 6) << 6;
  const words = new Uint32Array(paddedLength >>> 2);

  for (let i = 0; i < len; i++) {
    words[i >>> 2] |= message[i] << ((3 - (i & 3)) * 8);
  }
  // Append bit '1' (0x80)
  words[len >>> 2] |= 0x80 << ((3 - (len & 3)) * 8);

  // Append length in bits as 64-bit big-endian integer (top 32 bits = 0 for sizes < 512MB)
  const bitLengthLow = (len * 8) >>> 0;
  const bitLengthHigh = Math.floor(len / 0x20000000);
  words[words.length - 2] = bitLengthHigh;
  words[words.length - 1] = bitLengthLow;

  const w = new Uint32Array(64);

  // Process 512-bit (64-byte / 16-word) blocks
  for (let chunk = 0; chunk < words.length; chunk += 16) {
    for (let i = 0; i < 16; i++) {
      w[i] = words[chunk + i];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (((w[i - 16] + s0) | 0) + ((w[i - 7] + s1) | 0)) | 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (((h + S1) | 0) + ((ch + K[i]) | 0) + w[i]) | 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }

    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
    h5 = (h5 + f) | 0;
    h6 = (h6 + g) | 0;
    h7 = (h7 + h) | 0;
  }

  function toHex(val: number): string {
    return (val >>> 0).toString(16).padStart(8, '0');
  }

  return toHex(h0) + toHex(h1) + toHex(h2) + toHex(h3) + toHex(h4) + toHex(h5) + toHex(h6) + toHex(h7);
}
