import { cryptoUtils, hexToBytes, bytesToHex } from './src/utils/crypto.js';

const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// "mnemonic" + "" 
cryptoUtils.pbkdf2Sha512(mnemonic, "mnemonic", 2048, 64).then(seed => {
  const fullKey = cryptoUtils.hmacSha512(hexToBytes("426974636f696e2073656564"), hexToBytes(seed));
  const rPriv = fullKey.slice(0, 64);
  const rCC = fullKey.slice(64, 128);

  const deriveChild = cryptoUtils.deriveChild;

  // m/86'/0'/0'/0/0
  const c1 = deriveChild(rPriv, rCC, 86, true);
  const c2 = deriveChild(c1.privKey, c1.chainCode, 0, true);
  const c3 = deriveChild(c2.privKey, c2.chainCode, 0, true);
  const c4 = deriveChild(c3.privKey, c3.chainCode, 0, false);
  const c5 = deriveChild(c4.privKey, c4.chainCode, 0, false);

  const internalPub = cryptoUtils.ecMultiply(c5.privKey);
  console.log("Internal Pub:", internalPub);
  // The address derived by cryptoUtils
  const tAddr = cryptoUtils.p2tr(internalPub);
  console.log("Addr (old logic):", tAddr);

  // New logic: force Even Y
  const xOnly = internalPub.slice(2);
  const tagHash = cryptoUtils.taggedHash("TapTweak", hexToBytes(xOnly));
  const tweakPoint = cryptoUtils.ecMultiply(tagHash);
  const evenPub = "02" + xOnly;
  
  const Q = cryptoUtils.ecAdd(evenPub, tweakPoint);
  const qXOnly = Q.slice(2);
  const expectedAddr = cryptoUtils.bech32m("bc", hexToBytes(qXOnly), 1);
  console.log("Addr (even logic):", expectedAddr);
});
