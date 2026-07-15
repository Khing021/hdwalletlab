import { useState, useMemo, useEffect } from 'react';
import { cryptoUtils, hexToBytes, bytesToHex } from '../utils/crypto';
import StepCard from './StepCard';

const SIGHASH_TYPES = {
  legacy: [
    { name: 'SIGHASH_ALL', hex: '01000000' },
    { name: 'SIGHASH_NONE', hex: '02000000' },
    { name: 'SIGHASH_SINGLE', hex: '03000000' },
    { name: 'SIGHASH_ALL | ANYONECANPAY', hex: '81000000' },
    { name: 'SIGHASH_NONE | ANYONECANPAY', hex: '82000000' },
    { name: 'SIGHASH_SINGLE | ANYONECANPAY', hex: '83000000' }
  ],
  taproot: [
    { name: 'SIGHASH_DEFAULT', hex: '00' },
    { name: 'SIGHASH_ALL', hex: '01' },
    { name: 'SIGHASH_NONE', hex: '02' },
    { name: 'SIGHASH_SINGLE', hex: '03' },
    { name: 'SIGHASH_ALL | ANYONECANPAY', hex: '81' },
    { name: 'SIGHASH_NONE | ANYONECANPAY', hex: '82' },
    { name: 'SIGHASH_SINGLE | ANYONECANPAY', hex: '83' }
  ]
};

function TransactionJourney() {
  const [step, setStep] = useState(1);
  const [keys, setKeys] = useState([{ id: Date.now(), priv: '', pub: '', addr: '' }]);
  const [txData, setTxData] = useState({
    utxos: [],
    outputs: [{ id: Date.now(), addr: '', value: 0 }],
    step4Inputs: [],
    step5Outputs: [],
    step6TxBase: { version: '', marker: '', flag: '', vinSize: '', vins: [], voutSize: '', vouts: [], locktime: '' },
    step7Sighash: [],
    step8Sigs: [],
    finalTx: '',
    step10Txid: { base: '', hash: '' }
  });

  useEffect(() => {
    setTxData(prev => {
      let changed = false;
      const next = { ...prev };

      if (!next.step4Inputs || next.step4Inputs.length !== prev.utxos.length) {
        next.step4Inputs = prev.utxos.map((u, i) => (next.step4Inputs && next.step4Inputs[i]) || { txid: '', vout: '', value: '', spk: '', sequence: '' });
        changed = true;
      }
      if (!next.step5Outputs || next.step5Outputs.length !== prev.outputs.length) {
        next.step5Outputs = prev.outputs.map((o, i) => (next.step5Outputs && next.step5Outputs[i]) || { value: '', spk: '' });
        changed = true;
      }
      if (!next.step6TxBase) {
        next.step6TxBase = { version: '', marker: '', flag: '', vinSize: '', vins: [], voutSize: '', vouts: [], locktime: '' };
        changed = true;
      }
      if (!next.step6TxBase.vins || next.step6TxBase.vins.length !== prev.utxos.length) {
        next.step6TxBase.vins = prev.utxos.map((u, i) => (next.step6TxBase.vins && next.step6TxBase.vins[i]) || '');
        changed = true;
      }
      if (!next.step6TxBase.vouts || next.step6TxBase.vouts.length !== prev.outputs.length) {
        next.step6TxBase.vouts = prev.outputs.map((o, i) => (next.step6TxBase.vouts && next.step6TxBase.vouts[i]) || '');
        changed = true;
      }
      if (!next.step7Sighash || next.step7Sighash.length !== prev.utxos.length) {
        next.step7Sighash = prev.utxos.map((u, i) => {
          return (next.step7Sighash && next.step7Sighash[i]) || { type: '', preimage: '', message: '' };
        });
        changed = true;
      }
      if (!next.step8Sigs || next.step8Sigs.length !== prev.utxos.length) {
        next.step8Sigs = prev.utxos.map((u, i) => (next.step8Sigs && next.step8Sigs[i]) || { priv: '', tweakedPriv: '', signature: '' });
        changed = true;
      }
      if (!next.step10Txid) {
        next.step10Txid = { base: '', hash: '' };
        changed = true;
      }

      return changed ? next : prev;
    });
  }, [txData.utxos, txData.outputs]);
  const [satoshiTx, setSatoshiTx] = useState(null);

  const generateSatoshiTx = () => {
    const myAddrs = keys.filter(k => k.addr).map(k => k.addr);
    const numOutputs = Math.max(myAddrs.length, Math.floor(Math.random() * (11 - myAddrs.length)) + myAddrs.length);
    const outputs = [];
    const totalOutputBTC = 49;

    let remainingBTC = totalOutputBTC;

    const getRandomAddr = () => {
      const type = Math.floor(Math.random() * 4);
      const randPriv = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      const randPub = cryptoUtils.ecMultiply(randPriv);
      if (type === 0) return cryptoUtils.p2pkh(randPub);
      if (type === 1) return cryptoUtils.p2sh_p2wpkh(randPub);
      if (type === 2) return cryptoUtils.p2tr(randPub);
      return cryptoUtils.bech32("bc", hexToBytes(cryptoUtils.hash160(hexToBytes(randPub))), 0);
    };

    const outputStructs = [];
    myAddrs.forEach(addr => outputStructs.push({ addr, isMine: true }));
    while (outputStructs.length < numOutputs) {
      outputStructs.push({ addr: getRandomAddr(), isMine: false });
    }

    for (let i = outputStructs.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [outputStructs[i], outputStructs[j]] = [outputStructs[j], outputStructs[i]];
    }

    // Initialize each output with 1 BTC
    outputStructs.forEach(out => {
      out.valueBTC = 1;
    });

    // Distribute remaining BTC randomly
    let remaining = totalOutputBTC - outputStructs.length;
    while (remaining > 0) {
      const randIdx = Math.floor(Math.random() * outputStructs.length);
      outputStructs[randIdx].valueBTC += 1;
      remaining--;
    }

    // Convert to satoshis
    outputStructs.forEach(out => {
      out.value = out.valueBTC * 100000000;
      delete out.valueBTC;
      outputs.push(out);
    });

    const txid = cryptoUtils.sha256(Math.random().toString());
    setSatoshiTx({
      txid,
      input: { txid: '0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098', vout: 0, value: 50 * 100000000 },
      outputs,
      fee: 1 * 100000000
    });
  };

  useEffect(() => {
    if (step === 2 && !satoshiTx) {
      generateSatoshiTx();
    }
  }, [step, satoshiTx]);

  const addKey = () => {
    if (keys.length < 5) {
      setKeys([...keys, { id: Date.now() + keys.length, priv: '', pub: '', addr: '' }]);
    }
  };

  const removeKey = (id) => {
    if (keys.length > 1) {
      setKeys(keys.filter(k => k.id !== id));
    }
  };

  const updateKey = (id, field, value) => {
    setKeys(keys.map(k => {
      if (k.id === id) {
        return { ...k, [field]: value };
      }
      return k;
    }));
  };

  const randomKey = (id, type) => {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    const priv = bytesToHex(arr);
    const pub = cryptoUtils.ecMultiply(priv);

    let addr = '';
    if (type === 'legacy') addr = cryptoUtils.p2pkh(pub);
    else if (type === 'nested') addr = cryptoUtils.p2sh_p2wpkh(pub);
    else if (type === 'native') addr = cryptoUtils.bech32("bc", hexToBytes(cryptoUtils.hash160(hexToBytes(pub))), 0);
    else if (type === 'taproot') addr = cryptoUtils.p2tr(pub);

    setKeys(keys.map(k => {
      if (k.id === id) {
        return { ...k, priv, pub, addr };
      }
      return k;
    }));
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const isKeyValid = (key) => {
    if (!key.priv || !key.pub || !key.addr) return false;
    try {
      const expectedPub = cryptoUtils.ecMultiply(key.priv);
      if (expectedPub !== key.pub.toLowerCase()) return false;

      const addrLegacy = cryptoUtils.p2pkh(expectedPub);
      const addrNested = cryptoUtils.p2sh_p2wpkh(expectedPub);
      const addrNative = cryptoUtils.bech32("bc", hexToBytes(cryptoUtils.hash160(hexToBytes(expectedPub))), 0);
      const addrTaproot = cryptoUtils.p2tr(expectedPub);

      return [addrLegacy, addrNested, addrNative, addrTaproot].includes(key.addr);
    } catch (e) {
      return false;
    }
  };

  const allKeysValid = useMemo(() => {
    return keys.every(isKeyValid);
  }, [keys]);

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

  const expectedData = useMemo(() => {
    if (step < 3) return {};

    const inputs = txData.utxos;
    const outputs = txData.outputs.filter(o => o.addr && o.value > 0);

    let version = "02000000";
    if (txData.step6TxBase?.version) {
      const v = txData.step6TxBase.version.toLowerCase();
      if (v === "01000000" || v === "02000000") version = v;
    }
    let locktime = "00000000";
    if (txData.step6TxBase?.locktime && /^[0-9a-f]{8}$/i.test(txData.step6TxBase.locktime)) {
      locktime = txData.step6TxBase.locktime.toLowerCase();
    }

    // Detect if we have any segwit/taproot
    let hasSegwit = false;
    let hasTaproot = false;
    inputs.forEach(inp => {
      if (inp.addr.startsWith('3') || inp.addr.startsWith('bc1q')) hasSegwit = true;
      if (inp.addr.startsWith('bc1p')) { hasSegwit = true; hasTaproot = true; }
    });

    const marker = hasSegwit ? "00" : "";
    const flag = hasSegwit ? "01" : "";
    const vinSize = inputs.length.toString(16).padStart(2, '0');
    const voutSize = outputs.length.toString(16).padStart(2, '0');

    // Step 4 Expected
    const step4 = inputs.map((inp, i) => {
      const txidLE = inp.txid.match(/.{2}/g).reverse().join('');
      const voutLE = cryptoUtils.toLittleEndian(inp.vout, 4);
      const valueLE = cryptoUtils.toLittleEndian(inp.value, 8);
      const spk = getScriptPubKey(inp.addr);
      let sequence = "ffffffff";
      if (txData.step4Inputs?.[i]?.sequence && /^[0-9a-f]{8}$/i.test(txData.step4Inputs[i].sequence)) {
        sequence = txData.step4Inputs[i].sequence.toLowerCase();
      }
      return { txid: txidLE, vout: voutLE, value: valueLE, spk, sequence };
    });

    // Step 5 Expected
    const step5 = outputs.map(out => {
      const valueLE = cryptoUtils.toLittleEndian(out.value, 8);
      const spk = getScriptPubKey(out.addr);
      return { value: valueLE, spk };
    });

    // Step 6 Expected
    const step6Vins = inputs.map((inp, i) => {
      return step4[i].txid + step4[i].vout + "00" + step4[i].sequence;
    });

    const step6Vouts = outputs.map((out, i) => {
      const spkLen = (step5[i].spk.length / 2).toString(16).padStart(2, '0');
      return step5[i].value + spkLen + step5[i].spk;
    });

    // Compute hashes for Segwit
    let prevoutsHex = "";
    let sequencesHex = "";
    let amountsHex = "";
    let spksHex = "";
    let outputsHex = "";

    inputs.forEach((inp, i) => {
      const txidLE = inp.txid.match(/.{2}/g).reverse().join('');
      const voutLE = cryptoUtils.toLittleEndian(inp.vout, 4);
      prevoutsHex += txidLE + voutLE;
      sequencesHex += step4[i].sequence;
      amountsHex += cryptoUtils.toLittleEndian(inp.value, 8);
      const spk = getScriptPubKey(inp.addr);
      spksHex += (spk.length / 2).toString(16).padStart(2, '0') + spk;
    });

    outputs.forEach((out, i) => {
      outputsHex += step6Vouts[i];
    });

    const hashPrevouts = cryptoUtils.doubleSha256(prevoutsHex);
    const hashSequence = cryptoUtils.doubleSha256(sequencesHex);
    const hashOutputs = cryptoUtils.doubleSha256(outputsHex);

    const hashPrevoutsTaproot = cryptoUtils.sha256(prevoutsHex);
    const hashAmountsTaproot = cryptoUtils.sha256(amountsHex);
    const hashSpksTaproot = cryptoUtils.sha256(spksHex);
    const hashSequenceTaproot = cryptoUtils.sha256(sequencesHex);
    const hashOutputsTaproot = cryptoUtils.sha256(outputsHex);

    // Step 7 & 8 Expected
    const step7 = [];
    const step8 = [];
    const inputTypes = [];
    const expectedPreimageParts = [];

    const deriveTaprootTweakedPriv = (privHex, pubHex) => {
      if (!privHex || !pubHex) return "";
      const xOnly = pubHex.startsWith('02') || pubHex.startsWith('03') ? pubHex.substring(2) : pubHex;
      const tweakScalar = cryptoUtils.taprootTweakScalar(xOnly);
      return cryptoUtils.bigIntAddModN(privHex, tweakScalar);
    };

    inputs.forEach((inp, i) => {
      let type = "unknown";
      if (inp.addr.startsWith('1')) type = "legacy";
      else if (inp.addr.startsWith('3')) type = "nested";
      else if (inp.addr.startsWith('bc1q') && inp.addr.length === 42) type = "native";
      else if (inp.addr.startsWith('bc1p')) type = "taproot";
      inputTypes.push(type);

      const userHashName = txData.step7Sighash?.[i]?.hashName || (type === "taproot" ? "SIGHASH_DEFAULT" : "SIGHASH_ALL");
      const hashOptions = type === "taproot" ? SIGHASH_TYPES.taproot : SIGHASH_TYPES.legacy;
      const expectedHashHex = hashOptions.find(o => o.name === userHashName)?.hex || (type === "taproot" ? "00" : "01000000");

      const userHashType = expectedHashHex;

      let preimage = "";
      let message = "";
      let sig = "";
      let key = keys.find(k => k.addr === inp.addr);
      const parts = [];

      const isNone = userHashName.includes("SIGHASH_NONE");
      const isSingle = userHashName.includes("SIGHASH_SINGLE");
      const isAnyoneCanPay = userHashName.includes("ANYONECANPAY");

      if (type === "legacy") {
        parts.push({ label: 'Version', value: version, desc: '4 Bytes LE' });
        if (isAnyoneCanPay) {
          parts.push({ label: 'Input Count', value: "01", desc: 'VarInt (ANYONECANPAY)' });
          preimage = version + "01";
          const spkLen = (step4[i].spk.length / 2).toString(16).padStart(2, '0');
          parts.push({ label: `In#${i} TxID`, value: step4[i].txid, desc: '32 Bytes LE' });
          parts.push({ label: `In#${i} Vout`, value: step4[i].vout, desc: '4 Bytes LE' });
          parts.push({ label: `In#${i} Script Len`, value: spkLen, desc: 'VarInt' });
          parts.push({ label: `In#${i} ScriptSig`, value: step4[i].spk, desc: 'Current Input uses its ScriptPubKey' });
          parts.push({ label: `In#${i} nSequence`, value: step4[i].sequence, desc: '4 Bytes' });
          preimage += step4[i].txid + step4[i].vout + spkLen + step4[i].spk + step4[i].sequence;
        } else {
          const inputCount = inputs.length.toString(16).padStart(2, '0');
          parts.push({ label: 'Input Count', value: inputCount, desc: 'VarInt' });
          preimage = version + inputCount;
          inputs.forEach((in2, j) => {
            let seq = step4[j].sequence;
            if (i !== j && (isNone || isSingle)) {
              seq = "00000000";
            }
            parts.push({ label: `In#${j} TxID`, value: step4[j].txid, desc: '32 Bytes LE' });
            parts.push({ label: `In#${j} Vout`, value: step4[j].vout, desc: '4 Bytes LE' });
            if (i === j) {
              const spkLen = (step4[i].spk.length / 2).toString(16).padStart(2, '0');
              parts.push({ label: `In#${j} Script Len`, value: spkLen, desc: 'VarInt' });
              parts.push({ label: `In#${j} ScriptSig`, value: step4[i].spk, desc: 'Current Input uses its ScriptPubKey' });
              parts.push({ label: `In#${j} nSequence`, value: seq, desc: '4 Bytes' });
              preimage += step4[j].txid + step4[j].vout + spkLen + step4[i].spk + seq;
            } else {
              parts.push({ label: `In#${j} Script Len`, value: "00", desc: 'Empty (00) for other inputs' });
              parts.push({ label: `In#${j} nSequence`, value: seq, desc: '4 Bytes' });
              preimage += step4[j].txid + step4[j].vout + "00" + seq;
            }
          });
        }

        if (isNone) {
          parts.push({ label: 'Output Count', value: "00", desc: 'VarInt (SIGHASH_NONE)' });
          preimage += "00";
        } else if (isSingle) {
          if (i >= outputs.length) {
            parts.push({ label: 'Output Count', value: "00", desc: 'VarInt (SIGHASH_SINGLE BUG)' });
            preimage += "00";
          } else {
            const outputCount = (i + 1).toString(16).padStart(2, '0');
            parts.push({ label: 'Output Count', value: outputCount, desc: 'VarInt' });
            preimage += outputCount;
            for (let k = 0; k <= i; k++) {
              if (k < i) {
                parts.push({ label: `Out#${k} (Empty)`, value: "ffffffffffffffff00", desc: 'Empty output for SIGHASH_SINGLE' });
                preimage += "ffffffffffffffff00";
              } else {
                parts.push({ label: `Out#${k}`, value: step6Vouts[k], desc: 'Selected Output' });
                preimage += step6Vouts[k];
              }
            }
          }
        } else {
          const outputCount = outputs.length.toString(16).padStart(2, '0');
          parts.push({ label: 'Output Count', value: outputCount, desc: 'VarInt' });
          parts.push({ label: 'Outputs', value: outputsHex, desc: 'Serialized Outputs' });
          preimage += outputCount + outputsHex;
        }

        parts.push({ label: 'Locktime', value: locktime, desc: '4 Bytes LE' });
        parts.push({ label: 'Sighash Type', value: userHashType, desc: '4 Bytes LE' });
        preimage += locktime + userHashType;

        if (isSingle && i >= outputs.length) {
          message = "0100000000000000000000000000000000000000000000000000000000000000";
        } else {
          message = cryptoUtils.doubleSha256(preimage);
        }
        if (key) sig = cryptoUtils.sign(key.priv, message) + userHashType.substring(0, 2);

      } else if (type === "nested" || type === "native") {
        const outpoint = step4[i].txid + step4[i].vout;
        const pubKeyHash = cryptoUtils.hash160(hexToBytes(key?.pub || ""));
        const scriptCode = `1976a914${pubKeyHash}88ac`;
        const inputAmount = inp.value || 0;
        const amountLE = cryptoUtils.toLittleEndian(inputAmount, 8);

        let localHashPrevouts = hashPrevouts;
        let localHashSequence = hashSequence;
        let localHashOutputs = hashOutputs;
        
        if (isAnyoneCanPay) {
          localHashPrevouts = "0000000000000000000000000000000000000000000000000000000000000000";
          localHashSequence = "0000000000000000000000000000000000000000000000000000000000000000";
        }
        
        if (isNone) {
          localHashOutputs = "0000000000000000000000000000000000000000000000000000000000000000";
          if (!isAnyoneCanPay) {
            localHashSequence = "0000000000000000000000000000000000000000000000000000000000000000";
          }
        } else if (isSingle) {
          if (i < outputs.length) {
            localHashOutputs = cryptoUtils.doubleSha256(step6Vouts[i]);
          } else {
            localHashOutputs = "0000000000000000000000000000000000000000000000000000000000000000";
          }
          if (!isAnyoneCanPay) {
            localHashSequence = "0000000000000000000000000000000000000000000000000000000000000000";
          }
        }

        parts.push({ label: 'Version', value: version, desc: '4 Bytes LE' });
        parts.push({ label: 'HashPrevouts', value: localHashPrevouts, desc: isAnyoneCanPay ? 'Zeroed (ANYONECANPAY)' : 'Double SHA-256 of all outpoints' });
        parts.push({ label: 'HashSequence', value: localHashSequence, desc: (isNone || isSingle) && !isAnyoneCanPay ? 'Zeroed (SIGHASH_NONE/SINGLE)' : (isAnyoneCanPay ? 'Zeroed (ANYONECANPAY)' : 'Double SHA-256 of all nSequences') });
        parts.push({ label: 'Outpoint', value: outpoint, desc: 'Current Input TxID + Vout' });
        parts.push({ label: 'ScriptCode Len', value: "19", desc: 'Length of ScriptCode' });
        parts.push({ label: 'ScriptCode', value: scriptCode.substring(2), desc: 'P2PKH of this input' });
        parts.push({ label: 'Amount', value: amountLE, desc: '8 Bytes LE from the selected UTXO' });
        parts.push({ label: 'nSequence', value: step4[i].sequence, desc: '4 Bytes' });
        parts.push({ label: 'HashOutputs', value: localHashOutputs, desc: isNone ? 'Zeroed (SIGHASH_NONE)' : (isSingle ? 'Double SHA-256 of ONE output' : 'Double SHA-256 of all outputs') });
        parts.push({ label: 'Locktime', value: locktime, desc: '4 Bytes LE' });
        parts.push({ label: 'Sighash Type', value: userHashType, desc: '4 Bytes LE' });

        preimage = version + localHashPrevouts + localHashSequence + outpoint + scriptCode + amountLE + step4[i].sequence + localHashOutputs + locktime + userHashType;
        message = cryptoUtils.doubleSha256(preimage);
        if (key) sig = cryptoUtils.sign(key.priv, message) + userHashType.substring(0, 2);

      } else if (type === "taproot") {
        const inputIndexHex = cryptoUtils.toLittleEndian(i, 4);
        parts.push({ label: 'Epoch', value: "00", desc: 'Always 00 for Taproot' });
        parts.push({ label: 'Sighash Type', value: userHashType, desc: '1 Byte' });
        parts.push({ label: 'Version', value: version, desc: '4 Bytes LE' });
        parts.push({ label: 'Locktime', value: locktime, desc: '4 Bytes LE' });
        
        preimage = "00" + userHashType + version + locktime;

        if (!isAnyoneCanPay) {
          parts.push({ label: 'HashPrevouts', value: hashPrevoutsTaproot, desc: 'SHA-256 of all outpoints' });
          parts.push({ label: 'HashAmounts', value: hashAmountsTaproot, desc: 'SHA-256 of all amounts' });
          parts.push({ label: 'HashScriptPubKeys', value: hashSpksTaproot, desc: 'SHA-256 of all SPKs' });
          parts.push({ label: 'HashSequence', value: hashSequenceTaproot, desc: 'SHA-256 of all nSequences' });
          preimage += hashPrevoutsTaproot + hashAmountsTaproot + hashSpksTaproot + hashSequenceTaproot;
        }

        if (!isNone && !isSingle) {
          parts.push({ label: 'HashOutputs', value: hashOutputsTaproot, desc: 'SHA-256 of all outputs' });
          preimage += hashOutputsTaproot;
        } else if (isSingle && i < outputs.length) {
          const localHashOutputsTaproot = cryptoUtils.sha256(step6Vouts[i]);
          parts.push({ label: 'HashOutputs', value: localHashOutputsTaproot, desc: 'SHA-256 of ONE output' });
          preimage += localHashOutputsTaproot;
        }

        parts.push({ label: 'Spend Type / Ext', value: "00", desc: 'Key Path (00) + No Annex / No Extensions' });
        preimage += "00";

        if (isAnyoneCanPay) {
          const outpoint = step4[i].txid + step4[i].vout;
          parts.push({ label: 'Outpoint', value: outpoint, desc: 'TxID + Vout' });
          
          const inputAmount = inp.value || 0;
          const amountLE = cryptoUtils.toLittleEndian(inputAmount, 8);
          parts.push({ label: 'Amount', value: amountLE, desc: '8 Bytes LE' });
          
          const spk = getScriptPubKey(inp.addr);
          const spkLen = (spk.length / 2).toString(16).padStart(2, '0');
          parts.push({ label: 'ScriptPubKey', value: spkLen + spk, desc: 'VarInt + SPK' });
          
          parts.push({ label: 'nSequence', value: step4[i].sequence, desc: '4 Bytes' });
          
          preimage += outpoint + amountLE + spkLen + spk + step4[i].sequence;
        } else {
          parts.push({ label: 'Input Index', value: inputIndexHex, desc: '4 Bytes LE' });
          preimage += inputIndexHex;
        }

        message = cryptoUtils.taggedHash("TapSighash", hexToBytes(preimage));
        const tweakedPriv = deriveTaprootTweakedPriv(key?.priv || "", key?.pub || "");
        if (tweakedPriv) sig = cryptoUtils.schnorrSign(tweakedPriv, message);
        if (userHashType !== "00" && sig) sig += userHashType.substring(0, 2);
      }

      step7.push({ type: userHashType, preimage, message });
      step8.push({ priv: key ? key.priv : "", tweakedPriv: type === "taproot" ? deriveTaprootTweakedPriv(key?.priv || "", key?.pub || "") : "", signature: sig });
      expectedPreimageParts.push(parts);
    });

    // Step 9 Expected Final Tx
    const finalTxSegments = [];
    finalTxSegments.push({ text: version, color: 'text-blue-400', label: 'Version' });
    if (hasSegwit) {
      finalTxSegments.push({ text: marker, color: 'text-pink-400', label: 'Marker' });
      finalTxSegments.push({ text: flag, color: 'text-pink-500', label: 'Flag' });
    }
    finalTxSegments.push({ text: vinSize, color: 'text-purple-400', label: 'Vin Size' });

    let finalTx = version + marker + flag + vinSize;

    inputs.forEach((inp, i) => {
      let scriptSig = "";
      if (inputTypes[i] === "legacy") {
        const sig = step8[i].signature;
        const pub = keys.find(k => k.addr === inp.addr)?.pub || "";
        if (sig && pub) {
          scriptSig = (sig.length / 2).toString(16).padStart(2, '0') + sig + (pub.length / 2).toString(16).padStart(2, '0') + pub;
        }
      } else if (inputTypes[i] === "nested") {
        const pubHash = cryptoUtils.hash160(hexToBytes(keys.find(k => k.addr === inp.addr)?.pub || ""));
        const redeemScript = `0014${pubHash}`;
        scriptSig = (redeemScript.length / 2).toString(16).padStart(2, '0') + redeemScript;
      }
      const scriptSigLen = (scriptSig.length / 2).toString(16).padStart(2, '0');

      const vinText = step4[i].txid + step4[i].vout + scriptSigLen + scriptSig + step4[i].sequence;
      finalTxSegments.push({ text: vinText, color: 'text-indigo-400', label: `Vin ${i + 1} (incl. ScriptSig)` });
      finalTx += vinText;
    });

    finalTxSegments.push({ text: voutSize, color: 'text-amber-400', label: 'Vout Size' });
    finalTx += voutSize;

    outputs.forEach((out, i) => {
      finalTxSegments.push({ text: step6Vouts[i], color: 'text-yellow-400', label: `Vout ${i + 1}` });
    });
    finalTx += outputsHex;

    if (hasSegwit) {
      inputs.forEach((inp, i) => {
        let wit = "";
        if (inputTypes[i] === "legacy") {
          wit = "00";
        } else if (inputTypes[i] === "native" || inputTypes[i] === "nested") {
          const sig = step8[i].signature;
          const pub = keys.find(k => k.addr === inp.addr)?.pub || "";
          wit = "02" + (sig.length / 2).toString(16).padStart(2, '0') + sig + (pub.length / 2).toString(16).padStart(2, '0') + pub;
        } else if (inputTypes[i] === "taproot") {
          const sig = step8[i].signature;
          wit = "01" + (sig.length / 2).toString(16).padStart(2, '0') + sig;
        }
        if (wit) {
          finalTxSegments.push({ text: wit, color: 'text-teal-400', label: `Witness ${i + 1}` });
          finalTx += wit;
        }
      });
    }

    finalTxSegments.push({ text: locktime, color: 'text-green-400', label: 'Locktime' });
    finalTx += locktime;

    // Calculate TxID Base (Legacy serialization without witness)
    let txidBase = version + vinSize;
    inputs.forEach((inp, i) => {
      let scriptSig = "";
      if (inputTypes[i] === "legacy") {
        const sig = step8[i].signature;
        const pub = keys.find(k => k.addr === inp.addr)?.pub || "";
        if (sig && pub) {
          scriptSig = (sig.length / 2).toString(16).padStart(2, '0') + sig + (pub.length / 2).toString(16).padStart(2, '0') + pub;
        }
      } else if (inputTypes[i] === "nested") {
        const pubHash = cryptoUtils.hash160(hexToBytes(keys.find(k => k.addr === inp.addr)?.pub || ""));
        const redeemScript = `0014${pubHash}`;
        scriptSig = (redeemScript.length / 2).toString(16).padStart(2, '0') + redeemScript;
      }
      const scriptSigLen = (scriptSig.length / 2).toString(16).padStart(2, '0');
      txidBase += step4[i].txid + step4[i].vout + scriptSigLen + scriptSig + step4[i].sequence;
    });
    txidBase += voutSize + outputsHex + locktime;
    const txid = cryptoUtils.doubleSha256(txidBase).match(/.{2}/g).reverse().join('');

    const txTotalSize = finalTx.length / 2;
    const txBaseSize = txidBase.length / 2;
    const weight = (txBaseSize * 3) + txTotalSize;
    const vSize = Math.ceil(weight / 4);

    return {
      hasSegwit,
      step4,
      step5,
      step6: { version, marker, flag, vinSize, vins: step6Vins, voutSize, vouts: step6Vouts, locktime },
      step7,
      step8,
      finalTx: finalTx.toLowerCase(),
      finalTxSegments: finalTxSegments.map(s => ({ ...s, text: s.text.toLowerCase() })),
      txidBase: txidBase.toLowerCase(),
      txid,
      inputTypes,
      expectedPreimageParts,
      metrics: {
        size: txTotalSize,
        vsize: vSize,
        weight: weight
      }
    };
  }, [txData.utxos, txData.outputs, keys, step, txData.step7Sighash, txData.step4Inputs, txData.step6TxBase]);

  const totalInput = txData.utxos.reduce((sum, u) => sum + u.value, 0);
  const totalOutput = txData.outputs.reduce((sum, o) => sum + (o.value || 0), 0);
  const fee = totalInput - totalOutput;
  const estimatedVB = 10 + (68 * txData.utxos.length) + (32 * txData.outputs.length);
  const estimatedFeeRate = fee / estimatedVB;
  const isStep3Valid = txData.utxos.length > 0 && txData.outputs.length > 0 && txData.outputs.every(o => getScriptPubKey(o.addr) && o.value > 0) && fee > 0;

  const parseSequenceTags = (seqHex) => {
    if (!seqHex || !/^[0-9a-f]{8}$/i.test(seqHex)) return null;
    const bytes = seqHex.match(/.{2}/g);
    const beHex = [...bytes].reverse().join('');
    const seqInt = parseInt(beHex, 16);

    const absolute = seqInt < 0xffffffff ? 'Enable' : 'Disable';
    const rbf = seqInt < 0xfffffffe ? 'Enable' : 'Disable';

    const disableRel = (seqInt & 0x80000000) !== 0;
    let relative = 'Disable';

    if (!disableRel) {
      const typeFlag = (seqInt & 0x400000) !== 0;
      const value = seqInt & 0x0000ffff;
      if (typeFlag) {
        const seconds = value * 512;
        let timeStr = [];
        let rem = seconds;
        if (rem >= 86400) { timeStr.push(`${Math.floor(rem / 86400)} Days`); rem %= 86400; }
        if (rem >= 3600) { timeStr.push(`${Math.floor(rem / 3600)} Hrs`); rem %= 3600; }
        if (rem >= 60) { timeStr.push(`${Math.floor(rem / 60)} Mins`); rem %= 60; }
        if (rem > 0 || seconds === 0) { timeStr.push(`${rem} Secs`); }
        relative = timeStr.join(' ');
      } else {
        relative = `${value} Blocks`;
      }
    }

    return { absolute, rbf, relative };
  };

  const checkBip68Violation = (seqHex) => {
    if (!seqHex || seqHex.length !== 8) return false;
    const bytes = seqHex.match(/.{2}/g);
    if (!bytes) return false;
    const beHex = [...bytes].reverse().join('');
    const seqInt = parseInt(beHex, 16);
    // If bit 31 is 0 (relative locktime enabled)
    if ((seqInt & 0x80000000) === 0) {
      // Check reserved bits 16-21 and 23-30 (mask: 0x7FBF0000)
      if ((seqInt & 0x7FBF0000) !== 0) {
        return true;
      }
    }
    return false;
  };

  const step6VersionHex = txData.step6TxBase?.version || '';
  let effectiveVersion = 1;
  if (step6VersionHex.length === 8) {
    const bytes = step6VersionHex.match(/.{2}/g);
    if (bytes) {
      effectiveVersion = parseInt([...bytes].reverse().join(''), 16);
    }
  }

  const bip68Violations = txData.utxos.map((u, i) => {
    if (effectiveVersion >= 2) {
      return checkBip68Violation(txData.step4Inputs?.[i]?.sequence);
    }
    return false;
  });

  const hasBip68Violation = bip68Violations.some(v => v);

  const isStep4Valid = txData.utxos.length > 0 && txData.utxos.every((u, i) => {
    const s = txData.step4Inputs?.[i];
    const e = expectedData.step4?.[i];
    if (!s || !e) return false;
    const requireNValue = expectedData.inputTypes?.[i] !== 'legacy' || expectedData.inputTypes?.includes('taproot');
    return s.txid === e.txid &&
      s.vout === e.vout &&
      (!requireNValue || s.value === e.value) &&
      s.spk === e.spk &&
      s.sequence === e.sequence;
  });

  const isStep5Valid = txData.outputs.length > 0 && txData.outputs.every((o, i) => {
    const s = txData.step5Outputs?.[i];
    const e = expectedData.step5?.[i];
    return s && e && s.value === e.value && s.spk === e.spk;
  });

  const parseLocktimeTags = (locktimeHex) => {
    if (!locktimeHex || !/^[0-9a-f]{8}$/i.test(locktimeHex)) return null;
    const bytes = locktimeHex.match(/.{2}/g);
    const beHex = [...bytes].reverse().join('');
    const lockInt = parseInt(beHex, 16);

    if (lockInt === 0 || lockInt === 4294967295) return { type: 'Disable', text: 'Disabled' };
    if (lockInt < 500000000) return { type: 'Block', text: `Block Height ${lockInt}` };

    const date = new Date(lockInt * 1000);
    return { type: 'Time', text: date.toLocaleString('en-GB') };
  };

  const isStep6Valid = (() => {
    const s = txData.step6TxBase;
    const e = expectedData.step6;
    if (!s || !e) return false;
    const markerFlagValid = !expectedData.hasSegwit || (s.marker === e.marker && s.flag === e.flag);
    return s.version === e.version &&
      markerFlagValid &&
      s.vinSize === e.vinSize &&
      s.vins.every((v, i) => v === e.vins[i]) &&
      s.voutSize === e.voutSize &&
      s.vouts.every((v, i) => v === e.vouts[i]) &&
      s.locktime === e.locktime &&
      !hasBip68Violation;
  })();

  const isStep7Valid = txData.utxos.length > 0 && txData.utxos.every((u, i) => {
    const s = txData.step7Sighash?.[i];
    const e = expectedData.step7?.[i];
    return s && e && s.type === e.type && s.preimage === e.preimage && s.message === e.message;
  });

  const isStep8Valid = txData.utxos.length > 0 && txData.utxos.every((u, i) => {
    const s = txData.step8Sigs?.[i];
    const e = expectedData.step8?.[i];
    const type = expectedData.inputTypes?.[i];
    if (!s || !e) return false;
    if (type === 'taproot') return s.priv === e.priv && s.tweakedPriv === e.tweakedPriv && s.signature === e.signature;
    return s.priv === e.priv && s.signature === e.signature;
  });



  const isStep9Valid = txData.finalTx === expectedData.finalTx;
  const isStep10Valid = txData.step10Txid?.base === expectedData.txidBase && txData.step10Txid?.hash === expectedData.txid;

  const checkCheatCode = (e, expectedValue, setter) => {
    if (e.target.value.includes('///')) {
      setter(expectedValue);
      e.target.value = expectedValue;
      return true;
    }
    return false;
  };

  return (
    <div className="max-w-4xl mx-auto space-y-12 pb-32">
      <StepCard
        number="01"
        title="Prepare Your Bitcoin Address"
        isActive={step === 1}
        isLocked={false}
        isCompleted={step > 1}
        hint="เตรียม Private Key, Public Key, และ Address ให้พร้อม (กำหนดชุดคีย์ของคุณอย่างน้อย 1 แถว สูงสุด 5 แถว คีย์สามารถเป็นประเภทใดก็ได้)"
      >
        <div className="space-y-6">
          <div className="text-center space-y-2">
            <h3 className="text-xl font-black text-purple-400 uppercase tracking-widest hidden">UTXO Owners</h3>
            <p className="text-sm text-gray-400">เพื่อที่จะเป็นเจ้าของบิตคอยน์ เราจำเป็นต้องมี Private Key, Public Key และ Address เสียก่อน</p>
          </div>

          <div className="space-y-4">
            {keys.map((key, index) => (
              <div key={key.id} className="p-6 bg-purple-900/10 rounded-3xl border border-purple-500/20 flex flex-col gap-4 relative group transition-all hover:border-purple-500/40">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest bg-purple-500/10 px-3 py-1 rounded-full">Key #{index + 1}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] text-gray-500 font-bold uppercase tracking-widest mr-1">Random:</span>
                    <div className="flex gap-1">
                      <button onClick={() => randomKey(key.id, 'legacy')} className="text-[9px] px-2 py-1 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 rounded transition-all">Legacy</button>
                      <button onClick={() => randomKey(key.id, 'nested')} className="text-[9px] px-2 py-1 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 rounded transition-all">Nested SegWit</button>
                      <button onClick={() => randomKey(key.id, 'native')} className="text-[9px] px-2 py-1 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 rounded transition-all">Native SegWit</button>
                      <button onClick={() => randomKey(key.id, 'taproot')} className="text-[9px] px-2 py-1 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 rounded transition-all">Taproot</button>
                    </div>
                    {index > 0 && (
                      <button
                        onClick={() => removeKey(key.id)}
                        className="text-red-500/50 hover:text-red-500 transition-colors p-1"
                        title="Remove key"
                      >
                        🗑️
                      </button>
                    )}
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="grid grid-cols-1 gap-4">
                    <div className="space-y-1">
                      <div className="flex justify-between items-center px-1">
                        <label className="text-[9px] font-bold text-gray-500 tracking-wider">Private Key (Hex)</label>
                        <button onClick={() => copyToClipboard(key.priv)} className="text-[9px] text-purple-500 hover:underline">📋 Copy</button>
                      </div>
                      <input
                        type="text"
                        value={key.priv}
                        onChange={(e) => updateKey(key.id, 'priv', e.target.value.trim().toLowerCase())}
                        className={`w-full bg-black/40 border-2 rounded-xl p-3 text-xs font-mono text-purple-200 outline-none transition-all ${key.priv ? (isKeyValid(key) ? 'border-green-500/30' : 'border-purple-500/30') : 'border-gray-800'
                          } focus:border-purple-500/50`}
                        placeholder="32-byte hex..."
                      />
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between items-center px-1">
                        <label className="text-[9px] font-bold text-gray-500 tracking-wider">Public Key</label>
                        <button onClick={() => copyToClipboard(key.pub)} className="text-[9px] text-purple-500 hover:underline">📋 Copy</button>
                      </div>
                      <input
                        type="text"
                        value={key.pub}
                        onChange={(e) => updateKey(key.id, 'pub', e.target.value.trim().toLowerCase())}
                        className={`w-full bg-black/40 border-2 rounded-xl p-3 text-xs font-mono text-purple-200 outline-none transition-all ${key.pub ? (isKeyValid(key) ? 'border-green-500/30' : 'border-purple-500/30') : 'border-gray-800'
                          } focus:border-purple-500/50`}
                      />
                    </div>

                    <div className="space-y-1">
                      <div className="flex justify-between items-center px-1">
                        <label className="text-[9px] font-bold text-gray-500 tracking-wider">Address</label>
                        <button onClick={() => copyToClipboard(key.addr)} className="text-[9px] text-purple-500 hover:underline">📋 Copy</button>
                      </div>
                      <input
                        type="text"
                        value={key.addr}
                        onChange={(e) => updateKey(key.id, 'addr', e.target.value.trim())}
                        className={`w-full bg-black/40 border-2 rounded-xl p-3 text-xs font-mono text-purple-200 outline-none transition-all ${key.addr ? (isKeyValid(key) ? 'border-green-500/30' : 'border-purple-500/30') : 'border-gray-800'
                          } focus:border-purple-500/50`}
                      />
                    </div>
                  </div>
                </div>
                {key.priv && isKeyValid(key) && (
                  <span className="text-[9px] text-green-500 font-bold uppercase tracking-widest px-1 animate-pulse">✓ Key pair verified</span>
                )}
              </div>
            ))}

            {keys.length < 5 && (
              <button
                onClick={addKey}
                className="w-full py-4 border-2 border-dashed border-purple-500/20 rounded-3xl text-purple-400 font-bold hover:bg-purple-500/5 transition-all uppercase text-[10px] tracking-widest"
              >
                + Add Key Row
              </button>
            )}
          </div>

          <div className="flex justify-center pt-6">
            <button
              onClick={() => allKeysValid && setStep(2)}
              disabled={!allKeysValid}
              className={`px-12 py-4 rounded-2xl font-black uppercase tracking-widest transition-all shadow-xl ${allKeysValid
                ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-purple-500/20 hover:scale-105 active:scale-95'
                : 'bg-gray-800 text-gray-600 cursor-not-allowed opacity-50'
                }`}
            >
              Confirm Keys & Proceed
            </button>
          </div>
        </div>
      </StepCard>

      <StepCard
        number="02"
        title="Satoshi is back!"
        isActive={step === 2}
        isLocked={step < 2}
        isCompleted={step > 2}
        hint={
          <span>
            ซาโตชิใช้ 50 BTC ที่เขาได้รับเป็นรางวัลจากการขุด <a href="https://mempool.space/th/block/00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048" target="_blank" rel="noreferrer" className="underline hover:text-amber-500">บล็อก #1</a> มาเป็น input สำหรับธุรกรรมนี้<br />--- นี่คือ UTXO แรกสุดในระบบที่สามารถนำมาใช้งานจริงได้ และมันยังไม่เคยขยับเลยมาจนถึงปัจจุบัน
          </span>
        }
      >
        <div className="space-y-6">
          <div className="text-center space-y-2">
            <h3 className="text-2xl font-black text-purple-400 uppercase tracking-tighter">ซาโตชิกลับมาแล้ว!!!</h3>
            <p className="text-sm text-gray-400 uppercase tracking-widest">เขาสุ่มโอนเงินให้คุณ (และคนอื่นๆ ในรายการนี้) เพื่อฉลองการกลับมา</p>
          </div>

          {satoshiTx && (
            <div className="p-6 bg-purple-900/20 rounded-[32px] border border-purple-500/30 space-y-6 relative overflow-hidden">
              <div className="flex justify-between items-center border-b border-purple-500/20 pb-4">
                <div className="space-y-1">
                  <span className="text-[10px] text-purple-400 font-bold uppercase tracking-widest">Transaction Hash</span>
                  <p className="text-xs font-mono text-purple-200 break-all">{satoshiTx.txid}</p>
                </div>
                <button
                  onClick={generateSatoshiTx}
                  className="p-2 bg-purple-500/10 hover:bg-purple-500/20 rounded-xl transition-all border border-purple-500/20 text-[10px] font-bold text-purple-300 uppercase tracking-widest"
                >
                  🎲 RANDOM
                </button>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 relative">
                <div className="space-y-4">
                  <h4 className="text-[10px] text-gray-500 font-bold uppercase tracking-wider flex justify-between">
                    <span>Inputs (1)</span>
                    <span className="text-purple-400 font-mono">50.00 BTC</span>
                  </h4>
                  <div className="p-4 bg-black/40 rounded-2xl border border-purple-500/10 space-y-2">
                    <div className="flex justify-between items-center text-[10px] font-bold text-gray-500 uppercase tracking-widest">
                      <span className="flex items-center gap-2">
                        <span className="text-purple-500/50">#0</span> Coinbase Block #1
                      </span>
                      <span className="text-purple-300 font-mono">50.00 BTC</span>
                    </div>
                    <p className="text-[9px] font-mono text-gray-600 truncate">{satoshiTx.input.txid}:0</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <h4 className="text-[10px] text-gray-500 font-bold uppercase tracking-wider flex justify-between">
                    <span>Outputs ({satoshiTx.outputs.length})</span>
                    <span className="text-purple-400 font-mono">49.00 BTC</span>
                  </h4>
                  <div className="space-y-2 pr-2">
                    {satoshiTx.outputs.map((out, idx) => (
                      <div key={idx} className={`p-3 rounded-xl border flex justify-between items-center group transition-all ${out.isMine
                        ? 'bg-green-500/10 border-green-500/30'
                        : 'bg-black/40 border-purple-500/10'
                        }`}>
                        <div className="flex gap-3 items-center flex-1">
                          <span className={`text-[9px] font-bold font-mono ${out.isMine ? 'text-green-500' : 'text-purple-500/50'}`}>#{idx}</span>
                          <div className="space-y-0.5 flex-1">
                            <p className={`text-[9px] font-mono break-all leading-tight ${out.isMine ? 'text-green-400' : 'text-gray-400'}`}>{out.addr}</p>
                            {out.isMine && <span className="text-[8px] font-black bg-green-500 text-white px-1 rounded inline-block mt-0.5">YOU</span>}
                          </div>
                        </div>
                        <div className={`text-xs font-mono font-bold shrink-0 ${out.isMine ? 'text-green-400' : 'text-purple-300'}`}>
                          {(out.value / 100000000).toFixed(2)} BTC
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="flex justify-between items-center pt-4 border-t border-purple-500/10 text-[10px] font-bold uppercase tracking-widest">
                <span className="text-gray-500">Miner Fee</span>
                <span className="text-red-400 font-mono">1.00 BTC</span>
              </div>
            </div>
          )}

          <div className="flex justify-center pt-4">
            <button
              onClick={() => setStep(3)}
              className="px-12 py-5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white rounded-2xl font-black uppercase tracking-widest transition-all shadow-2xl shadow-purple-500/30 hover:scale-105 active:scale-95"
            >
              Get My Coins!
            </button>
          </div>
        </div>
      </StepCard>

      <StepCard number="03" title="Transaction Structure" isActive={step === 3} isLocked={step < 3} isCompleted={step > 3} hint="กำหนด Input (เลือกลำดับจาก UTXO) และ Output (เพิ่ม Address/Amount และเงินทอน)">
        <div className="space-y-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="space-y-4">
              <h4 className="text-xs font-bold text-purple-400 uppercase tracking-widest border-b border-purple-500/20 pb-2">1. Inputs Selection</h4>
              <div className="space-y-2">
                {satoshiTx?.outputs.filter(out => out.isMine).map((out, i) => {
                  const outVout = satoshiTx.outputs.indexOf(out);
                  const selectedIndex = txData.utxos.findIndex(u => u.txid === satoshiTx.txid && u.vout === outVout);
                  const isSelected = selectedIndex !== -1;
                  return (
                    <div key={i}
                      className={`w-full p-4 bg-black/40 border rounded-2xl text-left transition-all flex items-center gap-3 ${isSelected ? 'border-green-500 bg-green-500/10' : 'border-purple-500/20'}`}
                    >
                      <button onClick={() => {
                        if (isSelected) {
                          setTxData({ ...txData, utxos: txData.utxos.filter((_, idx) => idx !== selectedIndex) });
                        } else {
                          setTxData({ ...txData, utxos: [...txData.utxos, { txid: satoshiTx.txid, vout: outVout, value: out.value, addr: out.addr, priv: keys.find(k => k.addr === out.addr)?.priv }] });
                        }
                      }}
                        className={`w-6 h-6 flex-shrink-0 rounded-md flex items-center justify-center font-bold text-xs cursor-pointer hover:scale-110 transition-transform ${isSelected ? 'bg-green-500 text-white shadow-md shadow-green-500/20' : 'bg-purple-900/50 text-gray-500 hover:bg-purple-800/50'}`}>
                        {isSelected ? selectedIndex + 1 : ''}
                      </button>
                      <div className="flex-1 overflow-hidden">
                        <div className="text-[10px] font-bold text-gray-500 mb-1 selection:bg-purple-500/30">{out.addr}</div>
                        <div className="text-xs font-mono text-green-400 selection:bg-green-500/30">{(out.value / 100000000).toFixed(8)} BTC</div>
                      </div>
                    </div>
                  )
                })}
              </div>
              <div className="text-right text-sm font-mono text-purple-300">Total In: {(totalInput / 100000000).toFixed(8)} BTC</div>
            </div>

            <div className="space-y-4">
              <h4 className="text-xs font-bold text-purple-400 uppercase tracking-widest border-b border-purple-500/20 pb-2">2. Outputs Configuration</h4>
              <div className="space-y-4">
                {txData.outputs.map((out, i) => (
                  <div key={out.id} className="p-4 bg-black/40 border border-purple-500/20 rounded-2xl space-y-3 relative group">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] font-bold text-gray-500">Output #{i + 1}</span>
                      {txData.outputs.length > 1 && (
                        <button onClick={() => setTxData({ ...txData, outputs: txData.outputs.filter(o => o.id !== out.id) })} className="text-red-500/50 hover:text-red-500">🗑️</button>
                      )}
                    </div>
                    <input type="text" placeholder="Recipient Address" value={out.addr} onChange={(e) => {
                      const newOutputs = [...txData.outputs];
                      newOutputs[i].addr = e.target.value.trim();
                      setTxData({ ...txData, outputs: newOutputs });
                    }} className="w-full bg-black/40 border border-purple-500/20 rounded-xl p-3 text-xs font-mono text-purple-200 outline-none focus:border-purple-500" />
                    <input type="number" placeholder="Amount (BTC)" step="0.00000001" value={out.valueStr !== undefined ? out.valueStr : (out.value ? (out.value / 100000000) : '')} onChange={(e) => {
                      const newOutputs = [...txData.outputs];
                      let valStr = e.target.value;
                      if (valStr.includes('.')) {
                        const parts = valStr.split('.');
                        if (parts[1].length > 8) {
                          valStr = parts[0] + '.' + parts[1].substring(0, 8);
                        }
                      }
                      newOutputs[i].valueStr = valStr;
                      newOutputs[i].value = Math.floor(parseFloat(valStr || 0) * 100000000);
                      setTxData({ ...txData, outputs: newOutputs });
                    }} className="w-full bg-black/40 border border-purple-500/20 rounded-xl p-3 text-xs font-mono text-purple-200 outline-none focus:border-purple-500" />
                  </div>
                ))}
                <button onClick={() => setTxData({ ...txData, outputs: [...txData.outputs, { id: Date.now(), addr: '', value: 0 }] })} disabled={txData.outputs.length >= 5} className="w-full py-3 bg-purple-500/10 text-purple-400 rounded-xl text-xs font-bold uppercase disabled:opacity-50">+ Add Output</button>
              </div>
              <div className="text-right text-sm font-mono text-purple-300">Total Out: {(totalOutput / 100000000).toFixed(8)} BTC</div>
            </div>
          </div>

          <div className="p-4 bg-purple-900/10 rounded-2xl border border-purple-500/20 flex flex-wrap justify-between items-center text-sm">
            <div className="space-y-1">
              <div className="text-gray-500 text-[10px] uppercase font-bold tracking-widest">Calculated Fee</div>
              <div className={`font-mono font-bold ${fee > 0 ? 'text-green-400' : 'text-red-500'}`}>{(fee / 100000000).toFixed(8)} BTC</div>
            </div>
            <div className="space-y-1 text-right">
              <div className="text-gray-500 text-[10px] uppercase font-bold tracking-widest">Est. Size / Fee Rate</div>
              <div className="font-mono text-purple-300">~{estimatedVB} vB @ {(estimatedFeeRate || 0).toFixed(1)} sat/vB</div>
            </div>
          </div>

          <div className="flex flex-col items-center gap-2 pt-4">
            {!isStep3Valid && (
              <div className="text-red-400 text-xs font-bold bg-red-500/10 px-4 py-2 rounded-lg">
                {!txData.utxos.length ? '⚠️ Please select at least 1 Input (UTXO).'
                  : !txData.outputs.length ? '⚠️ Please add at least 1 Output.'
                    : txData.outputs.some(o => !o.addr || !getScriptPubKey(o.addr)) ? '⚠️ One or more Output Addresses are invalid.'
                      : txData.outputs.some(o => !o.value || o.value <= 0) ? '⚠️ All Outputs must have an amount > 0.'
                        : fee <= 0 ? '⚠️ Total Input must be greater than Total Output (Fee must be > 0).'
                          : '⚠️ Invalid structure.'}
              </div>
            )}
            <button disabled={!isStep3Valid} onClick={() => setStep(4)} className={`px-12 py-4 rounded-2xl font-black uppercase tracking-widest shadow-xl transition-all ${isStep3Valid ? 'bg-purple-600 text-white hover:bg-purple-700 hover:scale-105' : 'bg-gray-800 text-gray-600 cursor-not-allowed'}`}>Confirm Structure</button>
          </div>
        </div>
      </StepCard>

      <StepCard number="04" title="Input Data Preparation (Little Endian)" isActive={step === 4} isLocked={step < 4} isCompleted={step > 4} hint="แปลงข้อมูลดิบของแต่ละ Input ให้อยู่ในรูปแบบ Little Endian และเตรียม ScriptPubKey รวมถึงใส่ Sequence ให้ถูกต้องตามกฎ RBF /// ScriptPubKey --- Legacy(P2PKH): 76a914[PubkeyHash]88ac // NativeSegwit(P2WPKH): 0014[PubkeyHash] // NestedSegwit(P2SH-P2WPKH): a914[PubkeyHash]87 // P2TR(Taproot): 5120[XonlyPubkey]">
        <div className="space-y-6">
          <p className="text-gray-400 text-sm">การทำงานกับ Bitcoin จำเป็นต้องแปลงตัวเลข (TxID, Vout, Amount) ให้อยู่ในรูปแบบ Little Endian (สลับไบต์จากหลังมาหน้า) เสมอ</p>

          <div className="space-y-6">
            {txData.utxos.map((u, i) => {
              const reqNValue = expectedData.inputTypes?.[i] !== 'legacy' || expectedData.inputTypes?.includes('taproot');
              return (
                <div key={i} className="p-4 bg-black/40 border border-purple-500/20 rounded-2xl space-y-4">
                  <div className="flex justify-between items-center border-b border-purple-500/10 pb-2 gap-2">
                    <span className="text-xs font-bold text-gray-400 uppercase shrink-0">Input #{i + 1}</span>
                    <div className="flex items-center gap-2 justify-end flex-wrap">
                      <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-1 rounded">{expectedData.inputTypes?.[i]?.toUpperCase()}</span>
                      <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-1 rounded break-all">{u.addr}</span>
                    </div>
                  </div>

                  <div className="space-y-4">
                    {/* Line 1: TXID Full Width */}
                    <div>
                      <label className="text-[10px] font-bold text-gray-500 tracking-widest">TxID (Reversed / Little Endian) - 32 Bytes</label>
                      <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step4Inputs?.[i]?.txid === expectedData.step4?.[i]?.txid ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="32 byte hex LE" value={txData.step4Inputs?.[i]?.txid || ''} onChange={(e) => {
                        const newArr = [...txData.step4Inputs];
                        if (checkCheatCode(e, expectedData.step4[i].txid, (v) => { newArr[i] = { ...newArr[i], txid: v }; setTxData({ ...txData, step4Inputs: newArr }); })) return;
                        newArr[i] = { ...newArr[i], txid: e.target.value.toLowerCase().replace(/\s/g, '') };
                        setTxData({ ...txData, step4Inputs: newArr });
                      }} />
                    </div>

                    {/* Line 2: Vout and nValue Half Width */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="text-[10px] font-bold text-gray-500 tracking-widest">Vout (4 Bytes LE)</label>
                        <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step4Inputs?.[i]?.vout === expectedData.step4?.[i]?.vout ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="4 byte hex LE" value={txData.step4Inputs?.[i]?.vout || ''} onChange={(e) => {
                          const newArr = [...txData.step4Inputs];
                          if (checkCheatCode(e, expectedData.step4[i].vout, (v) => { newArr[i] = { ...newArr[i], vout: v }; setTxData({ ...txData, step4Inputs: newArr }); })) return;
                          newArr[i] = { ...newArr[i], vout: e.target.value.toLowerCase().replace(/\s/g, '') };
                          setTxData({ ...txData, step4Inputs: newArr });
                        }} />
                      </div>
                      <div>
                        <label className="text-[10px] font-bold text-gray-500 tracking-widest">nValue / Amount (8 Bytes LE) {reqNValue ? '' : '(N/A for Legacy)'}</label>
                        <input type="text" disabled={!reqNValue} className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${!reqNValue ? 'opacity-20 cursor-not-allowed' : txData.step4Inputs?.[i]?.value === expectedData.step4?.[i]?.value ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="8 byte hex LE" value={reqNValue ? (txData.step4Inputs?.[i]?.value || '') : 'NOT REQUIRED'} onChange={(e) => {
                          if (!reqNValue) return;
                          const newArr = [...txData.step4Inputs];
                          if (checkCheatCode(e, expectedData.step4[i].value, (v) => { newArr[i] = { ...newArr[i], value: v }; setTxData({ ...txData, step4Inputs: newArr }); })) return;
                          newArr[i] = { ...newArr[i], value: e.target.value.toLowerCase().replace(/\s/g, '') };
                          setTxData({ ...txData, step4Inputs: newArr });
                        }} />
                      </div>
                    </div>

                    {/* Line 3: ScriptPubKey Full Width */}
                    <div>
                      <label className="text-[10px] font-bold text-gray-500 tracking-widest">ScriptPubKey (Hex)</label>
                      <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step4Inputs?.[i]?.spk === expectedData.step4?.[i]?.spk ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="Hex" value={txData.step4Inputs?.[i]?.spk || ''} onChange={(e) => {
                        const newArr = [...txData.step4Inputs];
                        if (checkCheatCode(e, expectedData.step4[i].spk, (v) => { newArr[i] = { ...newArr[i], spk: v }; setTxData({ ...txData, step4Inputs: newArr }); })) return;
                        newArr[i] = { ...newArr[i], spk: e.target.value.toLowerCase().replace(/\s/g, '') };
                        setTxData({ ...txData, step4Inputs: newArr });
                      }} />
                    </div>

                    {/* Line 4: nSequence */}
                    <div className="w-full">
                      <label className="text-[10px] font-bold text-gray-500 tracking-widest block mb-2">nSequence (4 Bytes)</label>
                      <div className="flex flex-col md:flex-row items-stretch md:items-center gap-4">
                        <div className="w-full md:w-1/2 flex flex-col gap-1">
                          <input type="text" className={`w-full bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${bip68Violations[i] ? 'border-red-500 text-red-400 focus:border-red-500' : (/^[0-9a-f]{8}$/i.test(txData.step4Inputs?.[i]?.sequence || '') ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500')}`} placeholder="4 byte hex LE" value={txData.step4Inputs?.[i]?.sequence || ''} onChange={(e) => {
                            const newArr = [...txData.step4Inputs];
                            if (checkCheatCode(e, expectedData.step4[i].sequence, (v) => { newArr[i] = { ...newArr[i], sequence: v }; setTxData({ ...txData, step4Inputs: newArr }); })) return;
                            newArr[i] = { ...newArr[i], sequence: e.target.value.toLowerCase().replace(/\s/g, '') };
                            setTxData({ ...txData, step4Inputs: newArr });
                          }} />
                          {bip68Violations[i] && (
                            <span className="text-[9px] font-bold text-red-400 animate-pulse mt-1">⚠️ Invalid BIP 68 Sequence (Reserved bits must be 0)</span>
                          )}
                        </div>

                        {(() => {
                          const tags = parseSequenceTags(txData.step4Inputs?.[i]?.sequence);
                          if (!tags) return null;
                          return (
                            <div className="w-full md:w-1/2 text-[10px] font-mono p-3 bg-purple-900/20 border border-purple-500/30 rounded-xl flex flex-wrap gap-x-3 gap-y-1 text-purple-300 min-h-[44px] items-center">
                              <span>Absolute Locktime [<span className={tags.absolute === 'Enable' ? 'text-green-400 font-bold' : 'text-red-400 font-bold'}>{tags.absolute}</span>] /</span>
                              <span>RBF [<span className={tags.rbf === 'Enable' ? 'text-green-400 font-bold' : 'text-red-400 font-bold'}>{tags.rbf}</span>] /</span>
                              <span>Relative Locktime [<span className={tags.relative !== 'Disable' ? 'text-green-400 font-bold' : 'text-red-400 font-bold'}>{tags.relative}</span>]</span>
                            </div>
                          );
                        })()}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex justify-center pt-4">
            <button disabled={!isStep4Valid} onClick={() => setStep(5)} className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest ${isStep4Valid ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-lg shadow-purple-500/30' : 'bg-gray-800 text-gray-600 cursor-not-allowed'}`}>Proceed</button>
          </div>
        </div>
      </StepCard>

      <StepCard number="05" title="Output Data Preparation" isActive={step === 5} isLocked={step < 5} isCompleted={step > 5} hint="ScriptPubKey --- Legacy(P2PKH): 76a914[PubkeyHash]88ac // NativeSegwit(P2WPKH): 0014[PubkeyHash] // NestedSegwit(P2SH-P2WPKH): a914[PubkeyHash]87 // P2TR(Taproot): 5120[XonlyPubkey]">
        <div className="space-y-6">
          <p className="text-gray-400 text-sm">เตรียมข้อมูลสำหรับผู้รับปลายทาง โดยต้องสลับไบต์ Amount เป็น Little Endian เช่นเดียวกัน</p>

          <div className="space-y-6">
            {txData.outputs.map((out, i) => (
              <div key={out.id} className="p-4 bg-black/40 border border-purple-500/20 rounded-2xl space-y-4">
                <div className="flex justify-between items-center border-b border-purple-500/10 pb-2">
                  <span className="text-xs font-bold text-gray-400 uppercase shrink-0">Output #{i + 1}</span>
                  <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-1 rounded break-all text-right">{out.addr}</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="md:col-span-1">
                    <label className="text-[10px] font-bold text-gray-500 tracking-widest">Amount (8 Bytes LE)</label>
                    <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step5Outputs?.[i]?.value === expectedData.step5?.[i]?.value ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="8 byte hex LE" value={txData.step5Outputs?.[i]?.value || ''} onChange={(e) => {
                      const newArr = [...txData.step5Outputs];
                      if (checkCheatCode(e, expectedData.step5[i].value, (v) => { newArr[i] = { ...newArr[i], value: v }; setTxData({ ...txData, step5Outputs: newArr }); })) return;
                      newArr[i] = { ...newArr[i], value: e.target.value.toLowerCase().replace(/\s/g, '') };
                      setTxData({ ...txData, step5Outputs: newArr });
                    }} />
                  </div>
                  <div className="md:col-span-2">
                    <label className="text-[10px] font-bold text-gray-500 tracking-widest">ScriptPubKey (Hex)</label>
                    <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step5Outputs?.[i]?.spk === expectedData.step5?.[i]?.spk ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="Hex" value={txData.step5Outputs?.[i]?.spk || ''} onChange={(e) => {
                      const newArr = [...txData.step5Outputs];
                      if (checkCheatCode(e, expectedData.step5[i].spk, (v) => { newArr[i] = { ...newArr[i], spk: v }; setTxData({ ...txData, step5Outputs: newArr }); })) return;
                      newArr[i] = { ...newArr[i], spk: e.target.value.toLowerCase().replace(/\s/g, '') };
                      setTxData({ ...txData, step5Outputs: newArr });
                    }} />
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-center pt-4">
            <button disabled={!isStep5Valid} onClick={() => setStep(6)} className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest ${isStep5Valid ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-lg shadow-purple-500/30' : 'bg-gray-800 text-gray-600 cursor-not-allowed'}`}>Proceed</button>
          </div>
        </div>
      </StepCard>

      <StepCard number="06" title="Raw Transaction Skeleton" isActive={step === 6} isLocked={step < 6} isCompleted={step > 6} hint="ประกอบร่างธุรกรรมเบื้องต้น (ยังไม่ต้องใส่ลายเซ็นใน ScriptSig)">
        <div className="space-y-6">
          <p className="text-gray-400 text-sm">การประกอบร่างธุรกรรมเบื้องต้น (Skeleton) ก่อนนำไปแฮชและเซ็น หรือใช้เป็นร่างหลักสำหรับการแทรกลายเซ็น</p>

          <div className="p-4 bg-black/40 border border-purple-500/20 rounded-2xl space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-[10px] font-bold text-gray-500 tracking-widest">Version (4 Bytes LE)</label>
                <div className="flex flex-col gap-1">
                  <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${hasBip68Violation ? 'border-red-500 text-red-400 focus:border-red-500' : (txData.step6TxBase?.version === expectedData.step6?.version ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500')}`} placeholder="4 byte hex LE" value={txData.step6TxBase?.version || ''} onChange={(e) => {
                    if (checkCheatCode(e, expectedData.step6.version, (v) => setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, version: v } }))) return;
                    setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, version: e.target.value.toLowerCase().replace(/\s/g, '') } });
                  }} />
                  {hasBip68Violation && (
                    <span className="text-[9px] font-bold text-red-400 animate-pulse mt-1">⚠️ Version 2 requires valid BIP 68 nSequence in Step 4</span>
                  )}
                </div>
              </div>
              <div>
                <label className="text-[10px] font-bold text-gray-500 tracking-widest">Marker {expectedData.hasSegwit ? '' : '(N/A)'}</label>
                <input type="text" disabled={!expectedData.hasSegwit} className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${!expectedData.hasSegwit ? 'opacity-20 cursor-not-allowed' : txData.step6TxBase?.marker === expectedData.step6?.marker ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="1 byte hex" value={expectedData.hasSegwit ? (txData.step6TxBase?.marker || '') : 'NOT REQUIRED'} onChange={(e) => {
                  if (!expectedData.hasSegwit) return;
                  if (checkCheatCode(e, expectedData.step6.marker, (v) => setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, marker: v } }))) return;
                  setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, marker: e.target.value.toLowerCase().replace(/\s/g, '') } });
                }} />
              </div>
              <div>
                <label className="text-[10px] font-bold text-gray-500 tracking-widest">Flag {expectedData.hasSegwit ? '' : '(N/A)'}</label>
                <input type="text" disabled={!expectedData.hasSegwit} className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${!expectedData.hasSegwit ? 'opacity-20 cursor-not-allowed' : txData.step6TxBase?.flag === expectedData.step6?.flag ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="1 byte hex" value={expectedData.hasSegwit ? (txData.step6TxBase?.flag || '') : 'NOT REQUIRED'} onChange={(e) => {
                  if (!expectedData.hasSegwit) return;
                  if (checkCheatCode(e, expectedData.step6.flag, (v) => setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, flag: v } }))) return;
                  setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, flag: e.target.value.toLowerCase().replace(/\s/g, '') } });
                }} />
              </div>
            </div>

            <div className="w-full md:w-1/3 pt-4 border-t border-purple-500/10">
              <label className="text-[10px] font-bold text-gray-500 tracking-widest">Vin Size (Hex)</label>
              <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step6TxBase?.vinSize === expectedData.step6?.vinSize ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="VarInt" value={txData.step6TxBase?.vinSize || ''} onChange={(e) => {
                if (checkCheatCode(e, expectedData.step6.vinSize, (v) => setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, vinSize: v } }))) return;
                setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, vinSize: e.target.value.toLowerCase().replace(/\s/g, '') } });
              }} />
            </div>

            <div className="space-y-4 pt-2">
              <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Inputs (TxID + Vout + ScriptSig + Sequence)</h5>
              {txData.utxos.map((u, i) => (
                <div key={`vin-${i}`}>
                  <label className="text-[9px] font-bold text-gray-600">Vin #{i + 1} (Empty ScriptSig: 00)</label>
                  <input type="text" className={`w-full mt-1 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step6TxBase?.vins?.[i] === expectedData.step6?.vins?.[i] ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="Hex" value={txData.step6TxBase?.vins?.[i] || ''} onChange={(e) => {
                    const newArr = [...(txData.step6TxBase?.vins || [])];
                    if (checkCheatCode(e, expectedData.step6.vins[i], (v) => { newArr[i] = v; setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, vins: newArr } }); })) return;
                    newArr[i] = e.target.value.toLowerCase().replace(/\s/g, '');
                    setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, vins: newArr } });
                  }} />
                </div>
              ))}
            </div>

            <div className="space-y-4 pt-4 border-t border-purple-500/10">
              <div className="w-full md:w-1/3">
                <label className="text-[10px] font-bold text-gray-500 tracking-widest">Vout Size (Hex)</label>
                <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step6TxBase?.voutSize === expectedData.step6?.voutSize ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="VarInt" value={txData.step6TxBase?.voutSize || ''} onChange={(e) => {
                  if (checkCheatCode(e, expectedData.step6.voutSize, (v) => setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, voutSize: v } }))) return;
                  setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, voutSize: e.target.value.toLowerCase().replace(/\s/g, '') } });
                }} />
              </div>
              <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mt-4">Outputs (Amount + SPK Length + ScriptPubKey)</h5>
              {txData.outputs.map((o, i) => (
                <div key={`vout-${i}`}>
                  <label className="text-[9px] font-bold text-gray-600">Vout #{i + 1}</label>
                  <input type="text" className={`w-full mt-1 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step6TxBase?.vouts?.[i] === expectedData.step6?.vouts?.[i] ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="Hex" value={txData.step6TxBase?.vouts?.[i] || ''} onChange={(e) => {
                    const newArr = [...(txData.step6TxBase?.vouts || [])];
                    if (checkCheatCode(e, expectedData.step6.vouts[i], (v) => { newArr[i] = v; setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, vouts: newArr } }); })) return;
                    newArr[i] = e.target.value.toLowerCase().replace(/\s/g, '');
                    setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, vouts: newArr } });
                  }} />
                </div>
              ))}
            </div>

            <div className="pt-4 border-t border-purple-500/10">
              <label className="text-[10px] font-bold text-gray-500 tracking-widest block mb-2">Locktime (4 Bytes LE)</label>
              <div className="flex flex-col md:flex-row items-stretch md:items-center gap-4">
                <input type="text" className={`w-full md:w-1/3 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step6TxBase?.locktime === expectedData.step6?.locktime ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="4 byte hex LE" value={txData.step6TxBase?.locktime || ''} onChange={(e) => {
                  if (checkCheatCode(e, expectedData.step6.locktime, (v) => setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, locktime: v } }))) return;
                  setTxData({ ...txData, step6TxBase: { ...txData.step6TxBase, locktime: e.target.value.toLowerCase().replace(/\s/g, '') } });
                }} />
                {(() => {
                  const tag = parseLocktimeTags(txData.step6TxBase?.locktime);
                  if (!tag) return null;
                  return (
                    <div className="w-full md:w-2/3 text-[10px] font-mono p-3 bg-purple-900/20 border border-purple-500/30 rounded-xl flex items-center min-h-[44px]">
                      <span className="text-purple-300 mr-2">Absolute Locktime:</span>
                      <span className={tag.type === 'Disable' ? 'text-red-400 font-bold' : 'text-green-400 font-bold'}>
                        [{tag.text}]
                      </span>
                    </div>
                  );
                })()}
              </div>
            </div>

            {(() => {
              const b = txData.step6TxBase || {};
              const segments = [];
              if (b.version) segments.push({ text: b.version, color: 'text-blue-400', label: 'Version' });
              if (expectedData.hasSegwit) {
                if (b.marker) segments.push({ text: b.marker, color: 'text-pink-400', label: 'Marker' });
                if (b.flag) segments.push({ text: b.flag, color: 'text-pink-500', label: 'Flag' });
              }
              if (b.vinSize) segments.push({ text: b.vinSize, color: 'text-purple-400', label: 'Vin Size' });
              (b.vins || []).forEach((v, i) => { if (v) segments.push({ text: v, color: 'text-indigo-400', label: `Vin ${i + 1}` }); });
              if (b.voutSize) segments.push({ text: b.voutSize, color: 'text-amber-400', label: 'Vout Size' });
              (b.vouts || []).forEach((v, i) => { if (v) segments.push({ text: v, color: 'text-yellow-400', label: `Vout ${i + 1}` }); });
              if (b.locktime) segments.push({ text: b.locktime, color: 'text-green-400', label: 'Locktime' });

              const fullConcat = segments.map(s => s.text).join('');

              if (fullConcat.length > 0) {
                return (
                  <div className="pt-6 border-t border-purple-500/10">
                    <div className="flex justify-between items-center mb-2">
                      <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Real-time Skeleton Hex</h5>
                      <button
                        onClick={() => navigator.clipboard.writeText(fullConcat)}
                        className="text-[10px] font-bold px-3 py-1 bg-purple-500/20 hover:bg-purple-500/40 text-purple-300 rounded transition-colors"
                      >
                        Copy Hex
                      </button>
                    </div>
                    <div className="p-4 bg-black/60 rounded-xl border border-gray-700 font-mono text-[11px] leading-relaxed break-all">
                      {segments.map((seg, idx) => (
                        <span key={idx} className={`${seg.color} cursor-pointer hover:bg-white/10 px-[1px]`} title={seg.label}>{seg.text}</span>
                      ))}
                    </div>
                  </div>
                );
              }
              return null;
            })()}
          </div>

          <div className="flex justify-center pt-4">
            <button disabled={!isStep6Valid} onClick={() => setStep(7)} className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest ${isStep6Valid ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-lg shadow-purple-500/30' : 'bg-gray-800 text-gray-600 cursor-not-allowed'}`}>Proceed</button>
          </div>
        </div>
      </StepCard>

      <StepCard number="07" title="Sighash Preimage Formation" isActive={step === 7} isLocked={step < 7} isCompleted={step > 7} hint="สำหรับ input ที่เป็น Legacy, Native Segwit และ Nested Segwit ให้นำ Preiimage ไป doubleSHA-256 เพื่อสร้าง Message แต่หากเป็น Taproot ให้เปลี่ยนเป็นการ TaggedHash ด้วยการใช้คำว่า 'TapSighash' เป็น Tag">
        <div className="space-y-6">
          <p className="text-gray-400 text-sm">เลือก Sighash Type สำหรับแต่ละ Input จากนั้นประกอบร่างข้อความ Preimage ให้ถูกต้องตามกฎ และคำนวณ Message (Hash ของ Preimage)</p>

          <div className="space-y-6">
            {txData.utxos.map((u, i) => (
              <div key={`sighash-${i}`} className="p-4 bg-black/40 border border-purple-500/20 rounded-2xl space-y-4">
                <div className="flex justify-between items-center border-b border-purple-500/10 pb-2 gap-2">
                  <span className="text-xs font-bold text-gray-400 uppercase shrink-0">Input #{i + 1}</span>
                  <div className="flex items-center gap-2 justify-end flex-wrap">
                    <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-1 rounded">{expectedData.inputTypes?.[i]?.toUpperCase()}</span>
                    <span className="text-[10px] font-mono text-purple-400 bg-purple-500/10 px-2 py-1 rounded break-all">{u.addr}</span>
                  </div>
                </div>

                <div>
                  <label className="text-[10px] font-bold text-gray-500 tracking-widest block mb-2">Sighash Type (4 Bytes LE / 1 Byte for Taproot)</label>
                  <div className="flex flex-col md:flex-row items-stretch md:items-center gap-4">
                    <select
                      className="w-full md:w-1/2 bg-black/40 border-2 border-purple-500/20 rounded-xl p-3 text-sm font-mono text-purple-200 outline-none"
                      value={txData.step7Sighash?.[i]?.hashName || (expectedData.inputTypes?.[i] === 'taproot' ? 'SIGHASH_DEFAULT' : 'SIGHASH_ALL')}
                      onChange={(e) => {
                        const newArr = [...(txData.step7Sighash || [])];
                        newArr[i] = { ...newArr[i], hashName: e.target.value };
                        setTxData({ ...txData, step7Sighash: newArr });
                      }}
                    >
                      {(expectedData.inputTypes?.[i] === 'taproot' ? SIGHASH_TYPES.taproot : SIGHASH_TYPES.legacy).map(opt => (
                        <option key={opt.name} value={opt.name}>{opt.name}</option>
                      ))}
                    </select>

                    <input type="text"
                      className={`w-full md:w-1/2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step7Sighash?.[i]?.type === expectedData.step7?.[i]?.type ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`}
                      placeholder="4 byte hex LE"
                      value={txData.step7Sighash?.[i]?.type || ''}
                      onChange={(e) => {
                        const newArr = [...(txData.step7Sighash || [])];
                        if (checkCheatCode(e, expectedData.step7[i].type, (v) => { newArr[i] = { ...newArr[i], type: v }; setTxData({ ...txData, step7Sighash: newArr }); })) return;
                        newArr[i] = { ...newArr[i], type: e.target.value.toLowerCase().replace(/\s/g, '') };
                        setTxData({ ...txData, step7Sighash: newArr });
                      }}
                    />
                  </div>
                </div>

                <div>
                  <label className="text-[10px] font-bold text-gray-500 tracking-widest">Expected Preimage (Hex)</label>
                  <textarea className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all resize-none h-36 ${txData.step7Sighash?.[i]?.preimage === expectedData.step7?.[i]?.preimage ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="Hex" value={txData.step7Sighash?.[i]?.preimage || ''} onChange={(e) => {
                    const newArr = [...(txData.step7Sighash || [])];
                    if (checkCheatCode(e, expectedData.step7[i].preimage, (v) => { newArr[i] = { ...newArr[i], preimage: v }; setTxData({ ...txData, step7Sighash: newArr }); })) return;
                    newArr[i] = { ...newArr[i], preimage: e.target.value.toLowerCase().replace(/\s/g, '') };
                    setTxData({ ...txData, step7Sighash: newArr });
                  }} />
                </div>

                <div>
                  <label className="text-[10px] font-bold text-gray-500 tracking-widest">Message to Sign (32-byte Hex Hash)</label>
                  <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step7Sighash?.[i]?.message === expectedData.step7?.[i]?.message ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="32 byte hex" value={txData.step7Sighash?.[i]?.message || ''} onChange={(e) => {
                    const newArr = [...(txData.step7Sighash || [])];
                    if (checkCheatCode(e, expectedData.step7[i].message, (v) => { newArr[i] = { ...newArr[i], message: v }; setTxData({ ...txData, step7Sighash: newArr }); })) return;
                    newArr[i] = { ...newArr[i], message: e.target.value.toLowerCase().replace(/\s/g, '') };
                    setTxData({ ...txData, step7Sighash: newArr });
                  }} />
                </div>

                <div className="pt-2 border-t border-purple-500/10">
                  <button
                    onClick={() => setTxData({ ...txData, showPreimageHints: { ...txData.showPreimageHints, [i]: !txData.showPreimageHints?.[i] } })}
                    className="text-xs font-bold uppercase tracking-widest text-amber-500 hover:text-amber-400 transition-colors flex items-center gap-2"
                  >
                    <span>{txData.showPreimageHints?.[i] ? '▼ HIDE CHEAT SHEET' : '▶ SHOW CHEAT SHEET'}</span>
                  </button>

                  {txData.showPreimageHints?.[i] && expectedData.expectedPreimageParts?.[i] && (
                    <div className="mt-4 p-4 bg-amber-900/10 border border-amber-500/20 rounded-xl space-y-2 animate-in slide-in-from-top-2 duration-300">
                      <p className="text-[10px] text-amber-400/80 uppercase font-bold tracking-widest mb-3 pb-2 border-b border-amber-500/10">Preimage Components (Concatenate in order)</p>
                      {expectedData.expectedPreimageParts[i].map((part, idx) => (
                        <div key={idx} className="flex flex-col sm:flex-row gap-1 sm:gap-4 font-mono text-[10px]">
                          <span className="text-amber-500 w-36 shrink-0 pt-0.5">{part.label}</span>
                          <div className="flex flex-col flex-1">
                            <span className="text-amber-200/90 break-all select-all font-bold tracking-wider">{part.value}</span>
                            <span className="text-[9px] font-sans text-amber-500/50 italic mt-0.5">{part.desc}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-center pt-4">
            <button disabled={!isStep7Valid} onClick={() => setStep(8)} className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest ${isStep7Valid ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-lg shadow-purple-500/30' : 'bg-gray-800 text-gray-600 cursor-not-allowed'}`}>Proceed to Signing</button>
          </div>
        </div>
      </StepCard>

      <StepCard number="08" title="Digital Signatures" isActive={step === 8} isLocked={step < 8} isCompleted={step > 8} hint="นำ Message จากด่านที่แล้วมาเซ็นด้วย Private Key --- สำหรับ input ที่เป็น Legacy, Native Segwit และ Nested Segwit ให้ sign ด้วยเครื่องมือ ECDSA แต่หากเป็น Taproot ให้ sign ด้วย Schnorr --- และอย่าลืมเติม sighash bytes (1 byte) ต่อท้ายด้วย">
        <div className="space-y-6">
          <p className="text-gray-400 text-sm">การเซ็นลายเซ็นยืนยันการทำธุรกรรม หากเป็น Legacy/SegWit จะใช้ ECDSA (เพิ่ม 01 ต่อท้ายถ้าเป็น SIGHASH_ALL) แต่ถ้าเป็น Taproot จะใช้ Schnorr Signature</p>

          <div className="space-y-6">
            {txData.utxos.map((u, i) => {
              const step8Expected = expectedData.step8?.[i] || {};
              const inputType = expectedData.inputTypes?.[i];
              const isTaproot = inputType === 'taproot';
              return (
                <div key={`sig-${i}`} className="p-4 bg-black/40 border border-purple-500/20 rounded-2xl space-y-4">
                  <div className="flex justify-between items-center border-b border-purple-500/10 pb-2">
                    <span className="text-xs font-bold text-gray-400 uppercase">Input #{i + 1} ({expectedData.inputTypes?.[i]?.toUpperCase()})</span>
                    <span className="text-[10px] font-mono text-pink-400">{isTaproot ? 'Schnorr' : 'ECDSA (DER+Sighash Byte)'}</span>
                  </div>
                  <div>
                    <label className="text-[10px] font-bold text-gray-500 tracking-widest">Private Key (Hex)</label>
                    <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step8Sigs?.[i]?.priv === step8Expected.priv ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="32 byte hex" value={txData.step8Sigs?.[i]?.priv || ''} onChange={(e) => {
                      const newArr = [...(txData.step8Sigs || [])];
                      if (checkCheatCode(e, step8Expected.priv, (v) => { newArr[i] = { ...newArr[i], priv: v }; setTxData({ ...txData, step8Sigs: newArr }); })) return;
                      newArr[i] = { ...newArr[i], priv: e.target.value.toLowerCase().replace(/\s/g, '') };
                      setTxData({ ...txData, step8Sigs: newArr });
                    }} />
                  </div>
                  {isTaproot && (
                    <div>
                      <label className="text-[10px] font-bold text-gray-500 tracking-widest">Tweaked Private Key (Hex)</label>
                      <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step8Sigs?.[i]?.tweakedPriv === step8Expected.tweakedPriv ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="32 byte hex" value={txData.step8Sigs?.[i]?.tweakedPriv || ''} onChange={(e) => {
                        const newArr = [...(txData.step8Sigs || [])];
                        if (checkCheatCode(e, step8Expected.tweakedPriv, (v) => { newArr[i] = { ...newArr[i], tweakedPriv: v }; setTxData({ ...txData, step8Sigs: newArr }); })) return;
                        newArr[i] = { ...newArr[i], tweakedPriv: e.target.value.toLowerCase().replace(/\s/g, '') };
                        setTxData({ ...txData, step8Sigs: newArr });
                      }} />
                    </div>
                  )}
                  <div>
                    <label className="text-[10px] font-bold text-gray-500 tracking-widest">Signature Hex</label>
                    <textarea className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all resize-none h-24 break-all ${txData.step8Sigs?.[i]?.signature === step8Expected.signature ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="Hex" value={txData.step8Sigs?.[i]?.signature || ''} onChange={(e) => {
                      const newArr = [...(txData.step8Sigs || [])];
                      if (checkCheatCode(e, step8Expected.signature, (v) => { newArr[i] = { ...newArr[i], signature: v }; setTxData({ ...txData, step8Sigs: newArr }); })) return;
                      newArr[i] = { ...newArr[i], signature: e.target.value.toLowerCase().replace(/\s/g, '') };
                      setTxData({ ...txData, step8Sigs: newArr });
                    }} />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex justify-center pt-4">
            <button disabled={!isStep8Valid} onClick={() => setStep(9)} className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest ${isStep8Valid ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-lg shadow-purple-500/30' : 'bg-gray-800 text-gray-600 cursor-not-allowed'}`}>Assemble Full Tx</button>
          </div>
        </div>
      </StepCard>
      <StepCard number="09" title="Final Assembly" isActive={step === 9} isLocked={step < 9} isCompleted={step > 9} hint="นำโครงสร้างธุรกรรม (Skeleton) จากด่านที่ 6 มาแทรกลายเซ็น หรือต่อท้ายด้วย Witness">
        <div className="space-y-6">
          <p className="text-gray-400 text-sm">รวมทุกชิ้นส่วนเข้าด้วยกัน: Version + Marker/Flag (SegWit) + Vin Size + Inputs (พร้อม ScriptSig ถ้ามี) + Vout Size + Outputs + Witness Data (SegWit) + Locktime</p>

          <textarea className={`w-full bg-black/40 border-2 rounded-2xl p-4 text-sm font-mono h-48 resize-none outline-none transition-all shadow-inner ${txData.finalTx && txData.finalTx === expectedData.finalTx ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="Hex" value={txData.finalTx || ''} onChange={(e) => {
            if (checkCheatCode(e, expectedData.finalTx, (v) => setTxData({ ...txData, finalTx: v }))) return;
            setTxData({ ...txData, finalTx: e.target.value.toLowerCase().replace(/\s/g, '') });
          }} />

          <div className="pt-2 border-t border-purple-500/10">
            <button
              onClick={() => setTxData({ ...txData, showFinalTxHint: !txData.showFinalTxHint })}
              className="text-xs font-bold uppercase tracking-widest text-amber-500 hover:text-amber-400 transition-colors flex items-center gap-2"
            >
              <span>{txData.showFinalTxHint ? '▼ HIDE CHEAT SHEET' : '▶ SHOW CHEAT SHEET'}</span>
            </button>

            {txData.showFinalTxHint && expectedData.finalTxSegments && (
              <div className="mt-4 p-4 bg-amber-900/10 border border-amber-500/20 rounded-xl space-y-2 animate-in slide-in-from-top-2 duration-300">
                <p className="text-[10px] text-amber-400/80 uppercase font-bold tracking-widest mb-3 pb-2 border-b border-amber-500/10">Final Transaction Components (Concatenate in order)</p>
                {expectedData.finalTxSegments.map((seg, idx) => (
                  <div key={idx} className="flex flex-col sm:flex-row gap-1 sm:gap-4 font-mono text-[10px]">
                    <span className={`w-48 shrink-0 pt-0.5 font-bold ${seg.color}`}>{seg.label}</span>
                    <div className="flex flex-col flex-1">
                      <span className="text-amber-200/90 break-all select-all font-bold tracking-wider">{seg.text}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-center pt-4">
            <button disabled={!isStep9Valid} onClick={() => setStep(10)} className={`px-10 py-5 rounded-2xl font-black uppercase tracking-widest transition-all ${isStep9Valid ? 'bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:scale-105 shadow-2xl shadow-purple-500/40' : 'bg-gray-800 text-gray-600 cursor-not-allowed'}`}>Proceed to TxID</button>
          </div>
        </div>
      </StepCard>

      <StepCard number="10" title="TxID Calculation" isActive={step === 10} isLocked={step < 10} isCompleted={step > 10} hint="สกัด Marker, Flag และส่วน Witness ออก จากนั้นนำไปผ่าน Double-SHA256 แล้วกลับด้านเป็น Little Endian เพื่อสร้าง TxID">
        <div className="space-y-6">
          <p className="text-gray-400 text-sm">การหา TxID จะต้องใช้ Transaction Hex ที่ไม่มีส่วนผสมของ SegWit (Marker, Flag, และ Witness) จากนั้นนำไปผ่าน Double SHA-256 และสลับไบต์เป็น Little Endian</p>

          <div className="space-y-4">
            <div>
              <label className="text-[10px] font-bold text-gray-500 tracking-widest">TxID Calculation Base (No Witness Data)</label>
              <textarea className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all resize-none h-32 break-all ${txData.step10Txid?.base === expectedData.txidBase ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="Hex" value={txData.step10Txid?.base || ''} onChange={(e) => {
                if (checkCheatCode(e, expectedData.txidBase, (v) => setTxData({ ...txData, step10Txid: { ...txData.step10Txid, base: v } }))) return;
                setTxData({ ...txData, step10Txid: { ...txData.step10Txid, base: e.target.value.toLowerCase().replace(/\s/g, '') } });
              }} />
            </div>
            <div>
              <label className="text-[10px] font-bold text-gray-500 tracking-widest">Final TxID (Double SHA-256 + Reversed)</label>
              <input type="text" className={`w-full mt-2 bg-black/40 border-2 rounded-xl p-3 text-sm font-mono outline-none transition-all ${txData.step10Txid?.hash === expectedData.txid ? 'border-green-500 text-green-400' : 'border-purple-500/20 text-purple-200 focus:border-purple-500'}`} placeholder="32 byte hex LE" value={txData.step10Txid?.hash || ''} onChange={(e) => {
                if (checkCheatCode(e, expectedData.txid, (v) => setTxData({ ...txData, step10Txid: { ...txData.step10Txid, hash: v } }))) return;
                setTxData({ ...txData, step10Txid: { ...txData.step10Txid, hash: e.target.value.toLowerCase().replace(/\s/g, '') } });
              }} />
            </div>
          </div>

          <div className="flex justify-center pt-4">
            <button disabled={!isStep10Valid} onClick={() => setStep(11)} className={`px-10 py-5 rounded-2xl font-black uppercase tracking-widest transition-all ${isStep10Valid ? 'bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:scale-105 shadow-2xl shadow-purple-500/40' : 'bg-gray-800 text-gray-600 cursor-not-allowed'}`}>Verify Transaction</button>
          </div>
        </div>
      </StepCard>

      <StepCard number="11" title="Mission Accomplished" isActive={step === 11} isLocked={step < 11} isCompleted={false} hint="ยินดีด้วย! ธุรกรรมของคุณพร้อมส่งเข้าเครือข่ายแล้ว">
        <div className="space-y-8 text-center animate-in fade-in duration-500">
          <div className="inline-flex items-center justify-center w-24 h-24 bg-green-500/20 rounded-full border-4 border-green-500 animate-bounce">
            <span className="text-4xl">₿</span>
          </div>

          <div className="space-y-2">
            <h2 className="text-3xl md:text-4xl font-black text-white uppercase tracking-tighter">Transaction Crafted!</h2>
            <p className="text-purple-300 font-bold uppercase tracking-widest text-xs">Mission Accomplished</p>
          </div>

          <p className="text-gray-400 leading-relaxed text-sm">
            คุณได้สร้าง Bitcoin Transaction ระดับลึกที่สุดด้วยมือเปล่าสำเร็จแล้ว! คุณสามารถเลื่อนกลับขึ้นไปดูเส้นทางการสร้างธุรกรรมของคุณได้ทั้งหมด
          </p>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-left">
            <div className="p-3 bg-black/60 rounded-2xl border border-purple-500/30">
              <p className="text-[10px] text-gray-500 font-bold mb-1">Total Input</p>
              <p className="text-sm font-mono text-purple-400 font-bold">{(txData.utxos.reduce((a, b) => a + (b.value || 0), 0) / 100000000).toFixed(8)} BTC</p>
            </div>
            <div className="p-3 bg-black/60 rounded-2xl border border-purple-500/30">
              <p className="text-[10px] text-gray-500 font-bold mb-1">Total Output</p>
              <p className="text-sm font-mono text-purple-400 font-bold">{(txData.outputs.reduce((a, b) => a + (b.value || 0), 0) / 100000000).toFixed(8)} BTC</p>
            </div>
            <div className="p-3 bg-black/60 rounded-2xl border border-pink-500/30">
              <p className="text-[10px] text-gray-500 font-bold mb-1">Fee</p>
              <p className="text-sm font-mono text-pink-400 font-bold">{txData.utxos.reduce((a, b) => a + (b.value || 0), 0) - txData.outputs.reduce((a, b) => a + (b.value || 0), 0)} sats</p>
            </div>
            <div className="p-3 bg-black/60 rounded-2xl border border-amber-500/30">
              <p className="text-[10px] text-gray-500 font-bold mb-1">Fee Rate</p>
              <p className="text-sm font-mono text-amber-400 font-bold">{expectedData.metrics?.vsize ? ((txData.utxos.reduce((a, b) => a + (b.value || 0), 0) - txData.outputs.reduce((a, b) => a + (b.value || 0), 0)) / expectedData.metrics.vsize).toFixed(1) : 0} sat/vB</p>
            </div>
          </div>

          <div className="p-4 bg-black/60 rounded-2xl border border-green-500/30 text-left">
            <p className="text-[10px] text-green-500/80 font-bold mb-2">Final TxID (Double SHA-256 + Reversed)</p>
            <p className="text-[10px] font-mono text-green-400 break-all font-bold">{expectedData.txid}</p>
          </div>

          <div className="grid grid-cols-3 gap-4 text-center">
            <div className="p-3 bg-black/60 rounded-xl border border-blue-500/30">
              <p className="text-[10px] text-gray-500 font-bold mb-1">Total Size</p>
              <p className="text-sm font-mono text-blue-400 font-bold">{expectedData.metrics?.size} B</p>
            </div>
            <div className="p-3 bg-black/60 rounded-xl border border-amber-500/30">
              <p className="text-[10px] text-gray-500 font-bold mb-1">Weight</p>
              <p className="text-sm font-mono text-amber-400 font-bold">{expectedData.metrics?.weight} WU</p>
            </div>
            <div className="p-3 bg-black/60 rounded-xl border border-pink-500/30">
              <p className="text-[10px] text-gray-500 font-bold mb-1">Virtual Size (vB)</p>
              <p className="text-sm font-mono text-pink-400 font-bold">{expectedData.metrics?.vsize} vB</p>
            </div>
          </div>

          <div className="p-4 bg-black/60 rounded-2xl border border-purple-500/30 text-left">
            <p className="text-[10px] text-gray-500 font-bold mb-2">Your Signed Tx (Ready for mempool)</p>
            <div className="text-[11px] font-mono leading-relaxed break-all">
              {expectedData.finalTxSegments && expectedData.finalTxSegments.map(s => s.text).join('') === txData.finalTx ? (
                expectedData.finalTxSegments.map((seg, idx) => (
                  <span key={idx} className={`${seg.color} cursor-pointer hover:bg-white/10 px-[1px]`} title={seg.label}>{seg.text}</span>
                ))
              ) : (
                <span className="text-purple-400">{txData.finalTx}</span>
              )}
            </div>
          </div>

          <div className="flex justify-center pt-4">
            <button onClick={() => copyToClipboard(txData.finalTx)} className="w-full max-w-md py-4 bg-purple-600/20 hover:bg-purple-600/40 text-purple-300 rounded-2xl font-bold uppercase tracking-widest transition-all border border-purple-500/30">
              Copy Full TxHex
            </button>
          </div>
        </div>
      </StepCard>
    </div>
  );
}

export default TransactionJourney;
