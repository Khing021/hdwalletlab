import { cryptoUtils, hexToBytes, bytesToHex } from './src/utils/crypto.js';
const getScriptPubKey = (addr) => {
    if (!addr) return '';
    try {
      if (addr.startsWith('1')) {
        const decoded = cryptoUtils.base58Decode(addr);
        const hash160 = decoded.slice(2, 42);
        return `76a914${hash160}88ac`;
      } else if (addr.startsWith('3')) {
        const decoded = cryptoUtils.base58Decode(addr);
        const hash160 = decoded.slice(2, 42);
        return `a914${hash160}87`;
      } else if (addr.startsWith('bc1q') && addr.length === 42) {
        const decoded = cryptoUtils.bech32Decode(addr);
        return `0014${decoded.hex}`;
      } else if (addr.startsWith('bc1p')) {
        const decoded = cryptoUtils.bech32Decode(addr);
        return `5120${decoded.hex}`;
      }
    } catch (e) {
      return '';
    }
  };

const pub = "023a1a582fa05b821ab96cbf846ec5c92c57fde4bb91dbcc4af5a6ba6113b2ce40";
const addrs = [
  cryptoUtils.p2pkh(pub),
  cryptoUtils.p2sh_p2wpkh(pub),
  cryptoUtils.bech32("bc", hexToBytes(cryptoUtils.hash160(hexToBytes(pub))), 0),
  cryptoUtils.p2tr(pub)
];

console.log("Addresses:", addrs);
addrs.forEach(a => console.log(a, "->", getScriptPubKey(a)));
