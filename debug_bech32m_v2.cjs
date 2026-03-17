const { bech32, bech32m } = require('bech32');

const hexToBytes = (hex) => {
  hex = hex.replace(/^0x/, '');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    array[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return array;
};

const input = "00020f04060b0b0a0c03020009090e0f030107040608060500010a060f0409010c080d0c080c0f000a020a060f0e0808010a020c0f0f0d0406000d050d0400070f0f";
try {
    const dataBytes = hexToBytes(input);
    console.log("Data binary length:", dataBytes.length);
    const words = bech32.toWords(dataBytes);
    console.log("Words length:", words.length);
    const result = bech32m.encode('bc', [1, ...words], 1023);
    console.log("Result:", result);
} catch (e) {
    console.log("Error:", e.message);
}
