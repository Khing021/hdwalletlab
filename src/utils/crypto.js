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
  ecAdd: (pubKeyAHex, pubKeyBHex) => {
    const A = secp256k1.Point.fromHex(pubKeyAHex);
    const B = secp256k1.Point.fromHex(pubKeyBHex);
    return A.add(B).toHex(true);
  },
  taggedHash: (tag, data) => {
    const tagHash = sha256(new TextEncoder().encode(tag));
    const combined = new Uint8Array(tagHash.length * 2 + data.length);
    combined.set(tagHash);
    combined.set(tagHash, tagHash.length);
    combined.set(data, tagHash.length * 2);
    return bytesToHex(sha256(combined));
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
  },
  // Taproot Tweaking (BIP341)
  taprootTweak: (pubKeyBytes) => {
    const xOnly = pubKeyBytes.slice(1); // X-only is just the X coordinate
    const tag = "TapTweak";
    const tagHash = sha256(new TextEncoder().encode(tag));
    const tweakHash = sha256(new Uint8Array([...tagHash, ...tagHash, ...xOnly]));
    
    // BIP341 requires P to have an even Y coordinate for the tweak addition
    const evenPubKeyHex = '02' + bytesToHex(xOnly);
    const P = secp256k1.Point.fromHex(evenPubKeyHex);
    const tweak = BigInt('0x' + bytesToHex(tweakHash));
    const Q = P.add(secp256k1.Point.BASE.multiply(tweak));
    
    // Return tweaked X-only pubkey
    return hexToBytes(Q.toHex(true).slice(2)); 
  },
  // High-level Address Builders
  p2pkh: (pubKeyHex) => {
    const hash = hexToBytes(cryptoUtils.hash160(hexToBytes(pubKeyHex)));
    const payload = new Uint8Array(1 + 20);
    payload[0] = 0x00; // Network prefix
    payload.set(hash, 1);
    return cryptoUtils.base58check(payload);
  },
  p2sh_p2wpkh: (pubKeyHex) => {
    const pubHash = hexToBytes(cryptoUtils.hash160(hexToBytes(pubKeyHex)));
    const witnessProgram = new Uint8Array([0x00, 0x14, ...pubHash]);
    const scriptHash = hexToBytes(cryptoUtils.hash160(witnessProgram));
    const payload = new Uint8Array(1 + 20);
    payload[0] = 0x05; // Nested SegWit prefix
    payload.set(scriptHash, 1);
    return cryptoUtils.base58check(payload);
  },
  p2tr: (pubKeyHex) => {
    const pubKeyBytes = hexToBytes(pubKeyHex);
    const tweakedX = cryptoUtils.taprootTweak(pubKeyBytes);
    return cryptoUtils.bech32m("bc", tweakedX, 1);
  },
  // xpub/xpriv Helpers
  getFingerprint: (pubKeyHex) => {
    return cryptoUtils.hash160(hexToBytes(pubKeyHex)).slice(0, 8);
  },
  serializeXpub: (depth, fingerprint, childIndex, chainCode, pubKey, version = "0488b21e") => {
    const data = new Uint8Array(4 + 1 + 4 + 4 + 32 + 33);
    // Version: e.g. 0488b21e (mainnet xpub), 049d7cb2 (ypub), 04b24746 (zpub)
    data.set(hexToBytes(version), 0);
    data[4] = depth;
    data.set(hexToBytes(fingerprint), 5);
    const view = new DataView(data.buffer);
    view.setUint32(9, childIndex, false);
    data.set(hexToBytes(chainCode), 13);
    data.set(hexToBytes(pubKey), 45);
    return cryptoUtils.base58check(data);
  },
  base58Decode: (str) => {
    try {
      const decoded = bs58.decode(str);
      return bytesToHex(decoded);
    } catch (e) {
      throw new Error("Invalid Base58 string");
    }
  },
  bech32Decode: (str) => {
    try {
      let decoded;
      try {
        decoded = bech32.decode(str, 1024);
      } catch (e) {
        decoded = bech32m.decode(str, 1024);
      }
      const { prefix, words } = decoded;
      const version = words[0];
      const data = bech32.fromWords(words.slice(1));
      return { prefix, version, hex: bytesToHex(data) };
    } catch (e) {
      throw new Error("Invalid Bech32/m string");
    }
  }
};
