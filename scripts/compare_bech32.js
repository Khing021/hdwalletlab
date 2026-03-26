import { bech32 } from 'bech32';

function hexToBytes(hex) {
  hex = hex.replace(/^0x/, '');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return array;
}

const payloadHex = "4590e126160dd318a02d49f0e0912db7e211a628";
const dataHex = "00" + payloadHex;
const hrp = "bc";

const payload = hexToBytes(payloadHex);
const standardAddr = bech32.encode(hrp, [0, ...bech32.toWords(payload)]);
const manualData = hexToBytes(dataHex);
const manualAddr = bech32.encode(hrp, bech32.toWords(manualData));

console.log("Standard:", standardAddr);
console.log("Manual (v0 prepended to bytes):", manualAddr);
