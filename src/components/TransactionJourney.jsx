import { useState, useMemo, useEffect } from 'react';
import { cryptoUtils, hexToBytes, bytesToHex } from '../utils/crypto';
import StepCard from './StepCard';

function TransactionJourney() {
  const [step, setStep] = useState(1);
  const [keys, setKeys] = useState([{ id: Date.now(), priv: '', pub: '', addr: '' }]);
  const [txData, setTxData] = useState({
    utxos: [],
    outputs: [],
    fee: 1000, 
  });
  const [satoshiTx, setSatoshiTx] = useState(null);

  const generateSatoshiTx = () => {
    const myAddrs = keys.filter(k => k.addr).map(k => k.addr);
    const numOutputs = Math.max(myAddrs.length, Math.floor(Math.random() * (11 - myAddrs.length)) + myAddrs.length); 
    const outputs = [];
    const totalOutputBTC = 49; 
    
    // Distribute 49 BTC
    let remainingBTC = totalOutputBTC;
    
    // Helper for random address of different types
    const getRandomAddr = () => {
      const type = Math.floor(Math.random() * 4);
      const randPriv = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
      const randPub = cryptoUtils.ecMultiply(randPriv);
      if (type === 0) return cryptoUtils.p2pkh(randPub); // Legacy
      if (type === 1) return cryptoUtils.p2sh_p2wpkh(randPub); // Nested SegWit
      if (type === 2) return cryptoUtils.p2tr(randPub); // Taproot
      return cryptoUtils.bech32("bc", hexToBytes(cryptoUtils.hash160(hexToBytes(randPub))), 0); // Native SegWit
    };

    // Prepare structure
    const outputStructs = [];
    myAddrs.forEach(addr => outputStructs.push({ addr, isMine: true }));
    while (outputStructs.length < numOutputs) {
      outputStructs.push({ addr: getRandomAddr(), isMine: false });
    }

    // Shuffle structure
    for (let i = outputStructs.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [outputStructs[i], outputStructs[j]] = [outputStructs[j], outputStructs[i]];
    }

    // Assign values (at least 1 BTC each, except maybe the last one gets the rest)
    outputStructs.forEach((out, idx) => {
      if (idx === outputStructs.length - 1) {
        out.value = remainingBTC * 100000000;
      } else {
        const val = Math.floor(Math.random() * Math.min(5, remainingBTC - (outputStructs.length - 1 - idx))) + 1;
        out.value = val * 100000000;
        remainingBTC -= val;
      }
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

  const randomKey = (id) => {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    const priv = bytesToHex(arr);
    const pub = cryptoUtils.ecMultiply(priv);
    const addr = cryptoUtils.bech32("bc", hexToBytes(cryptoUtils.hash160(hexToBytes(pub))), 0);
    
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
      const expectedAddr = cryptoUtils.bech32("bc", hexToBytes(cryptoUtils.hash160(hexToBytes(expectedPub))), 0);
      return expectedAddr === key.addr;
    } catch (e) {
      return false;
    }
  };

  const allKeysValid = useMemo(() => {
    return keys.every(isKeyValid);
  }, [keys]);

  return (
    <div className="max-w-4xl mx-auto space-y-12 pb-32">
      <StepCard 
        number="01" 
        title="Setup Your Keys" 
        isActive={step === 1} 
        isLocked={false}
        isCompleted={step > 1}
        hint="กำหนดชุดคีย์ของคุณอย่างน้อย 1 แถว (สูงสุด 5 แถว) คีย์ต้องเป็น P2WPKH (Native SegWit) ที่ถูกต้องทุกฟิลด์"
      >
        <div className="space-y-6">
          <p className="text-gray-400 leading-relaxed text-sm">
            เริ่มต้นการสร้าง Transaction ด้วยการเตรียมกุญแจที่คุณจะใช้เป็นเจ้าของ UTXO (Unspent Transaction Output)
          </p>
          
          <div className="space-y-4">
            {keys.map((key, index) => (
              <div key={key.id} className="p-6 bg-purple-900/10 rounded-3xl border border-purple-500/20 flex flex-col gap-4 relative group transition-all hover:border-purple-500/40">
                <div className="flex justify-between items-center">
                  <span className="text-[10px] font-black text-purple-400 uppercase tracking-widest bg-purple-500/10 px-3 py-1 rounded-full">Key #{index + 1}</span>
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => randomKey(key.id)}
                      className="text-[10px] font-bold text-purple-400 hover:text-purple-300 flex items-center gap-1 transition-all"
                    >
                      🎲 RANDOM
                    </button>
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
                        <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider">Private Key (Hex)</label>
                        <button onClick={() => copyToClipboard(key.priv)} className="text-[9px] text-purple-500 hover:underline">📋 Copy</button>
                      </div>
                      <input 
                        type="text"
                        value={key.priv}
                        onChange={(e) => updateKey(key.id, 'priv', e.target.value.trim())}
                        className={`w-full bg-black/40 border-2 rounded-xl p-3 text-xs font-mono text-purple-200 outline-none transition-all ${
                          key.priv ? (isKeyValid(key) ? 'border-green-500/30' : 'border-purple-500/30') : 'border-gray-800'
                        } focus:border-purple-500/50`}
                        placeholder="32-byte hex..."
                      />
                    </div>
                    
                    <div className="space-y-1">
                      <div className="flex justify-between items-center px-1">
                        <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider">Public Key</label>
                        <button onClick={() => copyToClipboard(key.pub)} className="text-[9px] text-purple-500 hover:underline">📋 Copy</button>
                      </div>
                      <input 
                        type="text"
                        value={key.pub}
                        onChange={(e) => updateKey(key.id, 'pub', e.target.value.trim())}
                        className={`w-full bg-black/40 border-2 rounded-xl p-3 text-xs font-mono text-purple-200 outline-none transition-all ${
                          key.pub ? (isKeyValid(key) ? 'border-green-500/30' : 'border-purple-500/30') : 'border-gray-800'
                        } focus:border-purple-500/50`}
                      />
                    </div>
                    
                    <div className="space-y-1">
                      <div className="flex justify-between items-center px-1">
                        <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider">Address (bc1q...)</label>
                        <button onClick={() => copyToClipboard(key.addr)} className="text-[9px] text-purple-500 hover:underline">📋 Copy</button>
                      </div>
                      <input 
                        type="text"
                        value={key.addr}
                        onChange={(e) => updateKey(key.id, 'addr', e.target.value.trim())}
                        className={`w-full bg-black/40 border-2 rounded-xl p-3 text-xs font-mono text-purple-200 outline-none transition-all ${
                          key.addr ? (isKeyValid(key) ? 'border-green-500/30' : 'border-purple-500/30') : 'border-gray-800'
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
              className={`px-12 py-4 rounded-2xl font-black uppercase tracking-widest transition-all shadow-xl ${
                allKeysValid 
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
            ซาโตชิกลับมาแล้ว! และเขานำรางวัลที่ได้จากการขุด <a href="https://mempool.space/th/block/00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048" target="_blank" rel="noreferrer" className="underline hover:text-amber-500">บล็อก #1</a> มาส่งให้กับเราและคนอื่นๆ
          </span>
        }
      >
        <div className="space-y-6">
          <div className="text-center space-y-2">
            <h3 className="text-2xl font-black text-purple-400 uppercase tracking-tighter">ซาโตชิกลับมาแล้ว!!!</h3>
            <p className="text-sm text-gray-400 font-bold uppercase tracking-widest">และเขาสุ่มโอนเงินให้คุณ (และคนอื่นๆ ในรายการนี้) เพื่อฉลองการกลับมา</p>
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
                      <div key={idx} className={`p-3 rounded-xl border flex justify-between items-center group transition-all ${
                        out.isMine 
                          ? 'bg-green-500/10 border-green-500/30' 
                          : 'bg-black/40 border-purple-500/10'
                      }`}>
                        <div className="flex gap-3 items-center overflow-hidden">
                           <span className={`text-[9px] font-bold font-mono ${out.isMine ? 'text-green-500' : 'text-purple-500/50'}`}>#{idx}</span>
                           <div className="space-y-0.5 overflow-hidden">
                              <p className={`text-[9px] font-mono truncate ${out.isMine ? 'text-green-400' : 'text-gray-400'}`}>{out.addr}</p>
                              {out.isMine && <span className="text-[8px] font-black bg-green-500 text-white px-1 rounded">YOU</span>}
                           </div>
                        </div>
                        <div className={`text-xs font-mono font-bold shrink-0 ${out.isMine ? 'text-green-400' : 'text-purple-300'}`}>
                          {(out.value / 100000000).toFixed(0)}.00 BTC
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

      <StepCard 
        number="03" 
        title="Selecting Your UTXO" 
        isActive={step === 3} 
        isLocked={step < 3}
        isCompleted={step > 3}
        hint="เลือกว่าต้องการนำเหรียญจาก Address ไหนที่คุณสร้างไว้ในขั้นตอนแรก มาใช้ในการทำ Transaction นี้"
      >
        <div className="space-y-6">
          <p className="text-gray-400 text-sm leading-relaxed">
            นี่คือเหรียญ (UTXO) ที่ซาโตชิส่งให้คุณเมื่อครู่ เลือกเหรียญที่คุณต้องการนำมาเป็น Input ในรายการโอนครั้งนี้
          </p>

          <div className="grid grid-cols-1 gap-4">
            {satoshiTx?.outputs.filter(out => out.isMine).map((out, i) => (
              <button 
                key={i}
                onClick={() => {
                  setTxData({ ...txData, utxos: [{ 
                    txid: satoshiTx.txid, 
                    vout: satoshiTx.outputs.indexOf(out), 
                    value: out.value, 
                    addr: out.addr,
                    priv: keys.find(k => k.addr === out.addr)?.priv 
                  }] });
                  setStep(4);
                }}
                className="p-6 bg-black/40 border border-purple-500/20 rounded-3xl text-left hover:border-purple-500 transition-all group flex justify-between items-center"
              >
                <div>
                  <div className="text-[10px] font-bold text-gray-500 uppercase mb-1">UTXO from Satoshi</div>
                  <div className="text-xs font-mono text-purple-200">{out.addr}</div>
                </div>
                <div className="text-right">
                  <div className="text-xs font-mono text-green-400">{(out.value / 100000000).toFixed(0)}.00 BTC</div>
                  <div className="text-[9px] text-gray-600 uppercase">Unspent</div>
                </div>
              </button>
            ))}
          </div>
        </div>
      </StepCard>
      <StepCard 
        number="04" 
        title="Transaction Details" 
        isActive={step === 4} 
        isLocked={step < 4}
        isCompleted={step > 4}
        hint="ระบุ Address ผู้รับและจำนวนเงินที่ต้องการส่ง (หน่วย BTC) อย่าลืมเผื่อค่าธรรมเนียม (Fee) ให้กับ Miner ด้วย"
      >
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">Recipient Address</label>
              <input 
                type="text"
                placeholder="bc1q..."
                className="w-full bg-black/40 border-2 border-purple-500/20 rounded-2xl p-4 text-sm font-mono text-purple-200 outline-none focus:border-purple-500 transition-all"
                value={txData.outputs[0]?.addr || ''}
                onChange={(e) => {
                  const newOutputs = [...txData.outputs];
                  newOutputs[0] = { ...newOutputs[0], addr: e.target.value.trim() };
                  setTxData({ ...txData, outputs: newOutputs });
                }}
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">Amount (BTC)</label>
              <input 
                type="number"
                step="0.00000001"
                placeholder="0.00000000"
                className="w-full bg-black/40 border-2 border-purple-500/20 rounded-2xl p-4 text-sm font-mono text-purple-200 outline-none focus:border-purple-500 transition-all"
                value={txData.outputs[0]?.value ? (txData.outputs[0].value / 100000000) : ''}
                onChange={(e) => {
                  const val = Math.floor(parseFloat(e.target.value || 0) * 100000000);
                  const newOutputs = [...txData.outputs];
                  newOutputs[0] = { ...newOutputs[0], value: val };
                  setTxData({ ...txData, outputs: newOutputs });
                }}
              />
            </div>
          </div>

          <div className="p-4 bg-black/20 rounded-2xl border border-purple-500/10 space-y-3">
            <div className="flex justify-between text-xs">
              <span className="text-gray-500">Available Balance (Selected UTXO)</span>
              <span className="text-purple-300 font-mono">{(txData.utxos[0]?.value / 100000000).toFixed(8)} BTC</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-gray-500">Transaction Fee (Fixed for Tutorial)</span>
              <span className="text-red-400 font-mono">0.00001000 BTC</span>
            </div>
            <div className="border-t border-purple-500/10 pt-3 flex justify-between text-sm font-bold">
              <span className="text-gray-400 uppercase tracking-widest text-[10px]">Estimated Change</span>
              <span className="text-green-400 font-mono">
                {((txData.utxos[0]?.value - (txData.outputs[0]?.value || 0) - 1000) / 100000000).toFixed(8)} BTC
              </span>
            </div>
          </div>

          <div className="flex justify-center">
            <button 
              disabled={!txData.outputs[0]?.addr || !txData.outputs[0]?.value || (txData.outputs[0].value + 1000 > txData.utxos[0].value)}
              onClick={() => setStep(5)}
              className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest transition-all ${
                txData.outputs[0]?.addr && txData.outputs[0]?.value && (txData.outputs[0].value + 1000 <= txData.utxos[0].value)
                  ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-xl shadow-purple-500/20'
                  : 'bg-gray-800 text-gray-600 cursor-not-allowed'
              }`}
            >
              Prepare Serialization
            </button>
          </div>
        </div>
      </StepCard>
      <StepCard 
        number="05" 
        title="Serialization: The Preamble" 
        isActive={step === 5} 
        isLocked={step < 5}
        isCompleted={step > 5}
        hint="กรอกข้อมูล Version (LE), จำนวน Input, TXID (Reversed), VOUT (LE), และ Sequence ลงในรูปแบบ Raw Hex"
      >
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-4">
             <div className="p-4 bg-purple-900/10 rounded-2xl border border-purple-500/20 space-y-4">
                <div className="flex justify-between items-center border-b border-purple-500/10 pb-2">
                   <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Serialization Guide</h5>
                   <span className="text-[9px] text-purple-400 font-mono italic">Input Part (Non-Witness)</span>
                </div>
                <div className="space-y-2 text-xs font-mono">
                   <div className="flex justify-between">
                      <span className="text-gray-500">Version (4b LE)</span>
                      <span className="text-purple-300">02000000</span>
                   </div>
                   <div className="flex justify-between">
                      <span className="text-gray-500">Inputs Count (VarInt)</span>
                      <span className="text-purple-300">01</span>
                   </div>
                   <div className="flex justify-between">
                      <span className="text-gray-500">TXID (32b Reversed)</span>
                      <span className="text-purple-300 truncate ml-4">{txData.utxos[0]?.txid || '...'}</span>
                   </div>
                   <div className="flex justify-between">
                      <span className="text-gray-500">VOUT (4b LE)</span>
                      <span className="text-purple-300">00000000</span>
                   </div>
                   <div className="flex justify-between">
                      <span className="text-gray-500">ScriptSig Length</span>
                      <span className="text-purple-300">00 (SegWit)</span>
                   </div>
                   <div className="flex justify-between">
                      <span className="text-gray-500">Sequence</span>
                      <span className="text-purple-300">ffffffff</span>
                   </div>
                </div>
             </div>

             <div className="space-y-2">
                <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">Raw Input Hex</label>
                <textarea 
                  className="w-full bg-black/40 border-2 border-purple-500/20 rounded-2xl p-4 text-sm font-mono text-purple-200 outline-none focus:border-purple-500 h-32 resize-none"
                  placeholder="Paste your concatenated hex here..."
                  onChange={(e) => {
                     const val = e.target.value.toLowerCase().replace(/\s/g, '');
                     // Basic validation for the step - in a real lab we would check exactly
                     if (val.length >= 80) { // version(8) + count(2) + txid(64) + vout(8) + sig(2) + seq(8) = 92
                        setTxData({ ...txData, preambleHex: val });
                     }
                  }}
                />
             </div>
          </div>

          <div className="flex justify-center">
            <button 
              disabled={!txData.preambleHex}
              onClick={() => setStep(6)}
              className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest transition-all ${
                txData.preambleHex 
                  ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-xl shadow-purple-500/20'
                  : 'bg-gray-800 text-gray-600 cursor-not-allowed'
              }`}
            >
              Next: Outputs
            </button>
          </div>
        </div>
      </StepCard>
      <StepCard 
        number="06" 
        title="Serialization: The Outputs" 
        isActive={step === 6} 
        isLocked={step < 6}
        isCompleted={step > 6}
        hint="แปลงจำนวน BTC เป็น Satoshi (Little Endian) และสร้าง scriptPubKey สำหรับ P2WPKH (0014 + Hash160)"
      >
        <div className="space-y-6 text-sm text-gray-400">
          <p>
            คราวนี้มาสร้างส่วน Output รายการนี้จะมี 2 Output คือ (1) ผู้รับ และ (2) เงินทอน
          </p>
          
          <div className="space-y-4">
             {/* Guide for Output 1 */}
             <div className="p-4 bg-purple-900/10 rounded-2xl border border-purple-500/20 space-y-2">
                <div className="flex justify-between font-bold text-[10px] uppercase text-purple-400">
                   <span>Output #1 (Recipient)</span>
                   <span className="font-mono text-purple-300">{(txData.outputs[0]?.value / 100000000).toFixed(8)} BTC</span>
                </div>
                <div className="grid grid-cols-2 gap-4 font-mono text-[10px]">
                   <div>
                      <span className="block text-gray-500 mb-1 uppercase">8-byte LE Value</span>
                      <span className="text-gray-300 break-all">{cryptoUtils.toLittleEndian(txData.outputs[0]?.value || 0, 8)}</span>
                   </div>
                   <div>
                      <span className="block text-gray-500 mb-1 uppercase">scriptPubKey</span>
                      <span className="text-gray-300 break-all">0014 + Hash160(...)</span>
                   </div>
                </div>
             </div>

             <div className="space-y-2">
                <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">Raw Outputs Hex</label>
                <textarea 
                  className="w-full bg-black/40 border-2 border-purple-500/20 rounded-2xl p-4 text-sm font-mono text-purple-200 outline-none focus:border-purple-500 h-32 resize-none"
                  placeholder="Paste your concatenated outputs hex here..."
                  onChange={(e) => {
                     const val = e.target.value.toLowerCase().replace(/\s/g, '');
                     if (val.length >= 60) { 
                        setTxData({ ...txData, outputsHex: val });
                     }
                  }}
                />
             </div>
          </div>

          <div className="flex justify-center">
            <button 
              disabled={!txData.outputsHex}
              onClick={() => setStep(7)}
              className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest transition-all ${
                txData.outputsHex 
                  ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-xl shadow-purple-500/20'
                  : 'bg-gray-800 text-gray-600 cursor-not-allowed'
              }`}
            >
              Next: BIP143 Sighash
            </button>
          </div>
        </div>
      </StepCard>

      <StepCard 
        number="07" 
        title="BIP143 Sighash Construction" 
        isActive={step === 7} 
        isLocked={step < 7}
        isCompleted={step > 7}
        hint="Sighash คือหัวใจของการเซ็น เราต้องนำส่วนประกอบต่างๆ มา Hash ตามกฎ SegWit เพื่อสร้างเลข 'สารตั้งต้น' ก่อนเซ็น"
      >
        <div className="space-y-6 text-sm">
          <p className="text-gray-400">
            สำหรับ Native SegWit (v0), การสร้าง Sighash ต้องทำตาม BIP143 ซึ่งประกอบด้วย 10 ส่วน:
          </p>
          
          <div className="p-4 bg-black/40 rounded-2xl border border-purple-500/20 text-[10px] font-mono space-y-1">
             <div className="flex justify-between"><span className="text-gray-500">1. nVersion</span><span className="text-purple-300">02000000</span></div>
             <div className="flex justify-between"><span className="text-gray-500">2. hashPrevouts</span><span className="text-purple-300">DoubleSHA256(Inputs TXIDs + VOUTs)</span></div>
             <div className="flex justify-between"><span className="text-gray-500">3. hashSequence</span><span className="text-purple-300">DoubleSHA256(Sequences)</span></div>
             <div className="flex justify-between"><span className="text-gray-500">4. outpoint</span><span className="text-purple-300">TXID + VOUT</span></div>
             <div className="flex justify-between"><span className="text-gray-500">5. scriptCode</span><span className="text-purple-300">1976a914 + keyHash + 88ac</span></div>
             <div className="flex justify-between"><span className="text-gray-500">6. value</span><span className="text-purple-300">8b LE Satoshi</span></div>
             <div className="flex justify-between"><span className="text-gray-500">7. nSequence</span><span className="text-purple-300">ffffffff</span></div>
             <div className="flex justify-between"><span className="text-gray-500">8. hashOutputs</span><span className="text-purple-300">DoubleSHA256(Outputs)</span></div>
             <div className="flex justify-between"><span className="text-gray-500">9. nLockTime</span><span className="text-purple-300">00000000</span></div>
             <div className="flex justify-between"><span className="text-gray-500">10. sighashType</span><span className="text-purple-300">01000000</span></div>
          </div>

          <div className="space-y-2">
             <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">Final Sighash (Double SHA-256)</label>
             <input 
               type="text"
               className="w-full bg-black/40 border-2 border-purple-500/20 rounded-2xl p-4 text-sm font-mono text-purple-200 outline-none focus:border-purple-500"
               placeholder="Paste the 32-byte hex result here..."
               onChange={(e) => {
                  const val = e.target.value.toLowerCase().replace(/\s/g, '');
                  if (val.length === 64) {
                     setTxData({ ...txData, sighash: val });
                  }
               }}
             />
          </div>

          <div className="flex justify-center">
            <button 
              disabled={!txData.sighash}
              onClick={() => setStep(8)}
              className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest transition-all ${
                txData.sighash 
                  ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-xl shadow-purple-500/20'
                  : 'bg-gray-800 text-gray-600 cursor-not-allowed'
              }`}
            >
              Sign Transaction
            </button>
          </div>
        </div>
      </StepCard>
      <StepCard 
        number="08" 
        title="Signing: ECDSA Signature" 
        isActive={step === 8} 
        isLocked={step < 8}
        isCompleted={step > 8}
        hint="ใช้ Private Key ของคุณเซ็น Sighash ที่ได้จากขั้นตอนที่แล้ว โดยต้องเติม SIGHASH_ALL (01) ต่อท้ายลายเซ็นด้วย"
      >
        <div className="space-y-6">
          <div className="p-4 bg-purple-900/10 rounded-2xl border border-purple-500/20 space-y-4">
             <div className="flex justify-between items-center text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                <span>Signing Data</span>
                <span className="text-purple-400 font-mono">ECDSA (secp256k1)</span>
             </div>
             <div className="space-y-2 text-[10px] font-mono">
                <div className="bg-black/40 p-3 rounded-lg border border-purple-500/10">
                   <span className="text-gray-500 block mb-1">Message (Sighash)</span>
                   <span className="text-purple-300 break-all">{txData.sighash}</span>
                </div>
             </div>
          </div>

          <div className="space-y-2">
             <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">DER Signature + 01 (SIGHASH_ALL)</label>
             <input 
               type="text"
               className="w-full bg-black/40 border-2 border-purple-500/20 rounded-2xl p-4 text-sm font-mono text-purple-200 outline-none focus:border-purple-500"
               placeholder="Paste your DER hex here (e.g. 3045...01)"
               onChange={(e) => {
                  const val = e.target.value.toLowerCase().replace(/\s/g, '');
                  if (val.length >= 140) { // DER is usually 70-72 bytes (140-144 hex)
                     setTxData({ ...txData, signature: val });
                  }
               }}
             />
          </div>

          <div className="flex justify-center">
            <button 
              disabled={!txData.signature}
              onClick={() => setStep(9)}
              className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest transition-all ${
                txData.signature 
                  ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-xl shadow-purple-500/20'
                  : 'bg-gray-800 text-gray-600 cursor-not-allowed'
              }`}
            >
              Build Witness
            </button>
          </div>
        </div>
      </StepCard>

      <StepCard 
        number="09" 
        title="Constructing the Witness" 
        isActive={step === 9} 
        isLocked={step < 9}
        isCompleted={step > 9}
        hint="Witness Stack สำหรับ P2WPKH ประกอบด้วย: จำนวนรายการ (02), ความยาว Signature, Signature, ความยาว PubKey, PubKey"
      >
        <div className="space-y-6">
           <div className="p-4 bg-purple-900/10 rounded-2xl border border-purple-500/20 space-y-4">
              <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Witness Components</h5>
              <div className="space-y-2 text-[10px] font-mono">
                 <div className="flex justify-between"><span className="text-gray-500">Items Count</span><span className="text-purple-300">02</span></div>
                 <div className="flex justify-between"><span className="text-gray-500">Sig Length</span><span className="text-purple-300">{(txData.signature?.length / 2).toString(16).padStart(2, '0')}</span></div>
                 <div className="flex justify-between"><span className="text-gray-500">Signature</span><span className="text-purple-200 truncate ml-4">{txData.signature}</span></div>
                 <div className="flex justify-between"><span className="text-gray-500">PubKey Length</span><span className="text-purple-300">21 (33 bytes)</span></div>
                 <div className="flex justify-between"><span className="text-gray-500">Public Key</span><span className="text-purple-200 truncate ml-4">{txData.utxos[0]?.pub}</span></div>
              </div>
           </div>

           <div className="space-y-4">
              <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">Raw Witness Hex</label>
              <textarea 
                className="w-full bg-black/40 border-2 border-purple-500/20 rounded-2xl p-4 text-sm font-mono text-purple-200 outline-none focus:border-purple-500 h-32 resize-none"
                placeholder="Concatenate items: count + len1 + item1 + len2 + item2"
                onChange={(e) => {
                   const val = e.target.value.toLowerCase().replace(/\s/g, '');
                   if (val.length > 200) {
                      setTxData({ ...txData, witnessHex: val });
                   }
                }}
              />
           </div>

          <div className="flex justify-center">
            <button 
              disabled={!txData.witnessHex}
              onClick={() => setStep(10)}
              className={`px-10 py-4 rounded-2xl font-black uppercase tracking-widest transition-all ${
                txData.witnessHex 
                  ? 'bg-purple-600 text-white hover:bg-purple-700 shadow-xl shadow-purple-500/20'
                  : 'bg-gray-800 text-gray-600 cursor-not-allowed'
              }`}
            >
              Final Assembly
            </button>
          </div>
        </div>
      </StepCard>

      <StepCard 
        number="10" 
        title="The Final Assembly" 
        isActive={step === 10} 
        isLocked={step < 10}
        isCompleted={step > 10}
        hint="นำส่วนประกอบทั้งหมดมาต่อกัน: Version + Marker(00) + Flag(01) + Inputs + Outputs + Witness + Locktime(00000000)"
      >
        <div className="space-y-6">
           <div className="grid grid-cols-1 gap-4">
              <div className="p-4 bg-purple-900/10 rounded-2xl border border-purple-500/20">
                 <h5 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-4">Recipe for Success</h5>
                 <div className="text-[9px] font-mono space-y-2 opacity-80">
                    <p><span className="text-purple-400">02000000</span> (Version)</p>
                    <p><span className="text-yellow-400">0001</span> (SegWit Marker & Flag)</p>
                    <p><span className="text-blue-400 truncate block">01 + {txData.utxos[0]?.txid.slice(0, 16)}... (Inputs)</span></p>
                    <p><span className="text-green-400 truncate block">02 + {txData.outputsHex?.slice(0, 16)}... (Outputs)</span></p>
                    <p><span className="text-pink-400 truncate block">{txData.witnessHex?.slice(0, 16)}... (Witness)</span></p>
                    <p><span className="text-purple-400">00000000</span> (Locktime)</p>
                 </div>
              </div>

              <div className="space-y-4">
                 <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">Signed Raw Transaction</label>
                 <textarea 
                   className="w-full bg-black/40 border-2 border-purple-500/20 rounded-2xl p-6 text-xs font-mono text-purple-200 outline-none focus:border-purple-500 h-48 resize-none shadow-inner"
                   placeholder="02000000000101..."
                   onChange={(e) => {
                      const val = e.target.value.toLowerCase().replace(/\s/g, '');
                      if (val.length > 300) {
                         setTxData({ ...txData, finalTx: val });
                      }
                   }}
                 />
              </div>
           </div>

           <div className="flex justify-center">
            <button 
              disabled={!txData.finalTx}
              onClick={() => setStep(11)}
              className={`px-10 py-5 rounded-2xl font-black uppercase tracking-widest transition-all ${
                txData.finalTx 
                  ? 'bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:scale-105 shadow-2xl shadow-purple-500/40'
                  : 'bg-gray-800 text-gray-600 cursor-not-allowed'
              }`}
            >
              Verify & Broadcast
            </button>
          </div>
        </div>
      </StepCard>

      {step === 11 && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-500">
           <div className="max-w-2xl w-full bg-[#0f0a1a] border-2 border-purple-500/50 rounded-[40px] p-12 text-center shadow-2xl shadow-purple-500/20 relative overflow-hidden group">
              <div className="absolute inset-0 bg-gradient-to-br from-purple-600/10 via-transparent to-pink-600/10"></div>
              
              <div className="relative z-10 space-y-8">
                 <div className="inline-flex items-center justify-center w-24 h-24 bg-green-500/20 rounded-full border-4 border-green-500 animate-bounce">
                    <span className="text-4xl">₿</span>
                 </div>
                 
                 <div className="space-y-2">
                    <h2 className="text-4xl font-black text-white uppercase tracking-tighter">Transaction Crafted!</h2>
                    <p className="text-purple-300 font-bold uppercase tracking-widest text-xs">Mission Accomplished - Bitcoin Level Up</p>
                 </div>

                 <p className="text-gray-400 leading-relaxed text-sm">
                    คุณได้สร้าง Bitcoin Transaction ด้วยมือเปล่าสำเร็จแล้ว! นี่คือพื้นฐานที่กระเป๋าเงินทุกใบทำอยู่เบื้องหลังความสะดวกสบาย แต่ตอนนี้คุณคือผู้ที่ก้าวข้ามความสะดวกสบายมาสู่ความเข้าใจที่แท้จริง
                 </p>

                 <div className="p-4 bg-black/60 rounded-2xl border border-purple-500/30">
                    <p className="text-[10px] text-gray-500 font-bold uppercase mb-2">Your Signed Tx (Ready to Broadcast)</p>
                    <p className="text-[10px] font-mono text-purple-400 break-all line-clamp-3">{txData.finalTx}</p>
                 </div>

                 <div className="flex flex-col sm:flex-row gap-4">
                    <button 
                       onClick={() => copyToClipboard(txData.finalTx)}
                       className="flex-1 py-4 bg-purple-600/20 hover:bg-purple-600/40 text-purple-300 rounded-2xl font-bold uppercase tracking-widest transition-all border border-purple-500/30"
                    >
                       Copy TxHex
                    </button>
                    <button 
                       onClick={() => window.location.reload()}
                       className="flex-1 py-4 bg-white text-black hover:bg-gray-200 rounded-2xl font-bold uppercase tracking-widest transition-all"
                    >
                       Start Over
                    </button>
                 </div>
              </div>
           </div>
        </div>
      )}
    </div>
  );
}

export default TransactionJourney;
