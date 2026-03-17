import { bech32, bech32m } from 'bech32';

const hexToBytes = (hex) => {
  hex = hex.replace(/^0x/, '');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return array;
};

const encodePath = (primaryClean, version, hrp) => {
    try {
        const dataBytes = hexToBytes(primaryClean);
        const words = bech32.toWords(dataBytes);
        const fullEncoding = version === 0 
          ? bech32.encode(hrp, [0, ...words])
          : bech32m.encode(hrp, [1, ...words]);
        
        return fullEncoding.split('1').pop();
    } catch (e) {
        return "Error: " + e.message;
    }
}

const inputHex = "ac7fc8874b11a7d9eb9cbd15cb29d0bc6dd311a0d3b6ced8a8ddefc5264130d7";
const result = encodePath(inputHex, 1, "bc");
console.log("Result:", result);
