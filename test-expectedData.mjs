import { cryptoUtils, hexToBytes, bytesToHex } from './src/utils/crypto.js';

const keys = [
  { id: 1, priv: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", pub: "023a1a582fa05b821ab96cbf846ec5c92c57fde4bb91dbcc4af5a6ba6113b2ce40", addr: "1PZMRhRk84Urd8uK8qW5F8fT5F6Uxt8zYv" }, 
  { id: 2, priv: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", pub: "023a1a582fa05b821ab96cbf846ec5c92c57fde4bb91dbcc4af5a6ba6113b2ce40", addr: "35q8h1Xg2Dhy1Jb5z1yFjG6v2h1j3h1j3" }, 
  { id: 3, priv: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", pub: "023a1a582fa05b821ab96cbf846ec5c92c57fde4bb91dbcc4af5a6ba6113b2ce40", addr: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" }, 
  { id: 4, priv: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", pub: "023a1a582fa05b821ab96cbf846ec5c92c57fde4bb91dbcc4af5a6ba6113b2ce40", addr: "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297" }  
];

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
  return '';
};

for (const key of keys) {
  try {
    const txData = {
      utxos: [{ txid: "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098", vout: 0, value: 5000000000, addr: key.addr, priv: key.priv }],
      outputs: [{ id: 1, addr: "", value: 0 }]
    };

    const inputs = txData.utxos;
    const outputs = txData.outputs.filter(o => o.addr && o.value > 0);

    const version = "02000000";
    const locktime = "00000000";
    const hashType = "01000000";

    let outputsHex = "";
    outputs.forEach(out => {
      const valHex = cryptoUtils.toLittleEndian(out.value || 0, 8);
      const spk = getScriptPubKey(out.addr);
      const spkLen = (spk.length / 2).toString(16).padStart(2, '0');
      outputsHex += valHex + spkLen + spk;
    });

    let prevoutsHex = "";
    let sequencesHex = "";
    inputs.forEach(inp => {
      const txidRev = inp.txid.match(/.{2}/g).reverse().join('');
      const voutHex = cryptoUtils.toLittleEndian(inp.vout, 4);
      prevoutsHex += txidRev + voutHex;
      sequencesHex += "ffffffff";
    });

    const hashPrevouts = cryptoUtils.doubleSha256(prevoutsHex);
    const hashSequence = cryptoUtils.doubleSha256(sequencesHex);
    const hashOutputs = cryptoUtils.doubleSha256(outputsHex);

    const expectedSighashes = [];
    const expectedSignatures = [];
    const inputTypes = [];

    inputs.forEach((inp, i) => {
      const txidRev = inp.txid.match(/.{2}/g).reverse().join('');
      const voutHex = cryptoUtils.toLittleEndian(inp.vout, 4);
      const outpoint = txidRev + voutHex;
      const valueHex = cryptoUtils.toLittleEndian(inp.value, 8);

      let sighash = "";
      let type = "unknown";

      if (inp.addr.startsWith('1')) {
        type = "legacy";
        let txHex = version;
        txHex += inputs.length.toString(16).padStart(2, '0');
        inputs.forEach((in2, j) => {
          const in2TxidRev = in2.txid.match(/.{2}/g).reverse().join('');
          const in2Vout = cryptoUtils.toLittleEndian(in2.vout, 4);
          if (i === j) {
            const spk = getScriptPubKey(inp.addr);
            const spkLen = (spk.length / 2).toString(16).padStart(2, '0');
            txHex += in2TxidRev + in2Vout + spkLen + spk + "ffffffff";
          } else {
            txHex += in2TxidRev + in2Vout + "00" + "ffffffff";
          }
        });
        txHex += outputs.length.toString(16).padStart(2, '0') + outputsHex;
        txHex += locktime + hashType;
        sighash = cryptoUtils.doubleSha256(txHex);
      } else if (inp.addr.startsWith('3') || (inp.addr.startsWith('bc1q') && inp.addr.length === 42)) {
        type = inp.addr.startsWith('3') ? "nested" : "native";
        let scriptCode = "";
        const keyObj = keys.find(k => k.addr === inp.addr);
        const pubKeyHash = cryptoUtils.hash160(hexToBytes(keyObj?.pub || ""));
        scriptCode = `1976a914${pubKeyHash}88ac`;

        let preimage = version + hashPrevouts + hashSequence + outpoint + scriptCode + valueHex + "ffffffff" + hashOutputs + locktime + hashType;
        sighash = cryptoUtils.doubleSha256(preimage);
      } else if (inp.addr.startsWith('bc1p')) {
        type = "taproot";
        let preimage = "00"; 
        preimage += "00"; 
        preimage += version;
        preimage += locktime;
        preimage += hashPrevouts;
        
        let amountsHex = "";
        let spksHex = "";
        inputs.forEach(in2 => {
          amountsHex += cryptoUtils.toLittleEndian(in2.value, 8);
          const spk = getScriptPubKey(in2.addr);
          spksHex += (spk.length / 2).toString(16).padStart(2, '0') + spk;
        });
        preimage += cryptoUtils.doubleSha256(amountsHex);
        preimage += cryptoUtils.doubleSha256(spksHex);
        preimage += hashSequence;
        preimage += hashOutputs;

        preimage += "00000000"; 
        preimage += cryptoUtils.toLittleEndian(i, 4); 

        sighash = cryptoUtils.taggedHash("TapSighash", hexToBytes(preimage));
      }

      inputTypes.push(type);
      expectedSighashes.push(sighash);

      const keyObj = keys.find(k => k.addr === inp.addr);
      if (keyObj) {
        if (type === "taproot") {
          expectedSignatures.push(cryptoUtils.schnorrSign(keyObj.priv, sighash));
        } else {
          expectedSignatures.push(cryptoUtils.sign(keyObj.priv, sighash));
        }
      } else {
        expectedSignatures.push("");
      }
    });

    let rawTx = version;
    const hasSegwit = inputTypes.some(t => t !== "legacy");
    if (hasSegwit) {
      rawTx += "0001"; 
    }
    
    rawTx += inputs.length.toString(16).padStart(2, '0');
    inputs.forEach((inp, i) => {
      const txidRev = inp.txid.match(/.{2}/g).reverse().join('');
      const voutHex = cryptoUtils.toLittleEndian(inp.vout, 4);
      let scriptSig = "";
      if (inputTypes[i] === "legacy") {
        const sig = expectedSignatures[i]; 
        const pub = keys.find(k => k.addr === inp.addr)?.pub || "";
        scriptSig = (sig.length / 2).toString(16).padStart(2, '0') + sig + (pub.length / 2).toString(16).padStart(2, '0') + pub;
      } else if (inputTypes[i] === "nested") {
        const pubHash = cryptoUtils.hash160(hexToBytes(keys.find(k => k.addr === inp.addr)?.pub || ""));
        const redeemScript = `0014${pubHash}`;
        scriptSig = (redeemScript.length / 2).toString(16).padStart(2, '0') + redeemScript;
      }
      const scriptSigLen = (scriptSig.length / 2).toString(16).padStart(2, '0');
      rawTx += txidRev + voutHex + scriptSigLen + scriptSig + "ffffffff";
    });

    rawTx += outputs.length.toString(16).padStart(2, '0') + outputsHex;

    if (hasSegwit) {
      inputs.forEach((inp, i) => {
        if (inputTypes[i] === "legacy") {
          rawTx += "00"; 
        } else if (inputTypes[i] === "native" || inputTypes[i] === "nested") {
          const sig = expectedSignatures[i];
          const pub = keys.find(k => k.addr === inp.addr)?.pub || "";
          rawTx += "02"; 
          rawTx += (sig.length / 2).toString(16).padStart(2, '0') + sig;
          rawTx += (pub.length / 2).toString(16).padStart(2, '0') + pub;
        } else if (inputTypes[i] === "taproot") {
          const sig = expectedSignatures[i];
          rawTx += "01"; 
          rawTx += (sig.length / 2).toString(16).padStart(2, '0') + sig;
        }
      });
    }

    rawTx += locktime;
    console.log(`Success for type: ${key.addr}`);
  } catch (err) {
    console.error(`Crash for ${key.addr}:`, err.stack);
  }
}
