import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bech32, bech32m } from 'bech32';
import bs58 from 'bs58';

// Utility to convert hex string to Uint8Array
export const hexToBytes = (hex) => {
  hex = hex.replace(/^0x/, '');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return array;
};

// Utility to convert Uint8Array to hex string
export const bytesToHex = (bytes) => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

// Cryptographic Wrapper
export const cryptoUtils = {
  sha256: (data) => bytesToHex(sha256(typeof data === 'string' ? data : data)),
  ripemd160: (data) => bytesToHex(ripemd160(data)),
  hash160: (data) => bytesToHex(ripemd160(sha256(data))),
  hmacSha512: (key, data) => bytesToHex(hmac(sha512, key, data)),
  pbkdf2Sha512: async (password, salt, iterations, keylen) => {
    const res = await pbkdf2(sha512, password, salt, { c: iterations, dkLen: keylen });
    return bytesToHex(res);
  },
  base58check: (data) => {
    const hash = sha256(sha256(data));
    const checksum = hash.slice(0, 4);
    const combined = new Uint8Array(data.length + 4);
    combined.set(data);
    combined.set(checksum, data.length);
    return bs58.encode(combined);
  },
  bech32: (hrp, data, version = 0) => {
    const words = bech32.toWords(data);
    return bech32.encode(hrp, [version, ...words]);
  },
  bech32m: (hrp, data, version = 1) => {
    const words = bech32.toWords(data);
    return bech32m.encode(hrp, [version, ...words]);
  },
  ecMultiply: (privKeyHex) => {
    const privKey = hexToBytes(privKeyHex);
    const pubKey = secp256k1.getPublicKey(privKey, true); // true for compressed
    return bytesToHex(pubKey);
  },
  deriveChild: (parentPrivHex, parentChainCodeHex, index, hardened) => {
    const parentPriv = hexToBytes(parentPrivHex);
    const parentCC = hexToBytes(parentChainCodeHex);
    let data;
    
    if (hardened) {
      data = new Uint8Array(1 + 32 + 4);
      data[0] = 0x00;
      data.set(parentPriv, 1);
      const view = new DataView(data.buffer);
      view.setUint32(1 + 32, index + 0x80000000, false);
    } else {
      const parentPub = secp256k1.getPublicKey(parentPriv, true);
      data = new Uint8Array(33 + 4);
      data.set(parentPub, 0);
      const view = new DataView(data.buffer);
      view.setUint32(33, index, false);
    }
    
    const I = hmac(sha512, parentCC, data);
    const IL = I.slice(0, 32);
    const IR = I.slice(32, 64);
    
    const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
    const childPriv = (BigInt('0x' + bytesToHex(parentPriv)) + BigInt('0x' + bytesToHex(IL))) % n;
    
    return {
      privKey: childPriv.toString(16).padStart(64, '0'),
      chainCode: bytesToHex(IR)
    };
  }
};
