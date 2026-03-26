import { useState, useMemo, useEffect } from 'react';
import { cryptoUtils, hexToBytes, bytesToHex } from './utils/crypto';
import { wordlist } from './utils/wordlist';
import Toolbox from './components/Toolbox';
import StepCard from './components/StepCard';

function App() {
  const [isDark, setIsDark] = useState(true);
  const [entropy, setEntropy] = useState('');
  const [mnemonicInput, setMnemonicInput] = useState('');
  const [seedInput, setSeedInput] = useState('');
  const [step, setStep] = useState(1);
  const [guessedWords, setGuessedWords] = useState(Array(12).fill(''));
  const [isXpubMode, setIsXpubMode] = useState(false);
  const [xpubInputs, setXpubInputs] = useState(Array(5).fill(null).map(() => ({ pub: '', xpub: '', ypub: '', zpub: '' })));

  const toggleTheme = () => setIsDark(!isDark);

  const generateEntropy = () => {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    setEntropy(bytesToHex(arr));
    setStep(1);
    setGuessedWords(Array(12).fill(''));
  };

  const entropyBinary = useMemo(() => {
    if (!entropy) return "";
    return hexToBytes(entropy).reduce((acc, byte) => acc + byte.toString(2).padStart(8, '0'), "");
  }, [entropy]);

  // Calculated BIP39 details
  const bip39Details = useMemo(() => {
    if (!entropy) return null;
    const entropyBytes = hexToBytes(entropy);
    const checksumHex = cryptoUtils.sha256(entropyBytes);
    const checksumBits = parseInt(checksumHex.slice(0, 2), 16).toString(2).padStart(8, '0').slice(0, 4);
    const fullBits = entropyBinary + checksumBits;
    
    const groups = [];
    for (let i = 0; i < 12; i++) {
      const bits = fullBits.slice(i * 11, (i + 1) * 11);
      const index = parseInt(bits, 2);
      groups.push({ bits, index, word: wordlist[index] });
    }

    const mnemonic = groups.map(g => g.word).join(' ');
    
    return { checksumBits, fullBits, groups, mnemonic };
  }, [entropy, entropyBinary]);

  const isMnemonicComplete = useMemo(() => {
    if (!bip39Details) return false;
    return guessedWords.every((w, i) => w.toLowerCase().trim() === bip39Details.groups[i].word);
  }, [guessedWords, bip39Details]);

  useEffect(() => {
    if (isMnemonicComplete && step === 3) {
      setStep(4);
    }
  }, [isMnemonicComplete, step]);

  const [seed, setSeed] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [rootPriv, setRootPriv] = useState('');
  const [rootChainCode, setRootChainCode] = useState('');
  const [rootPrivInput, setRootPrivInput] = useState('');
  const [rootCCInput, setRootCCInput] = useState('');
  const [derivationPath, setDerivationPath] = useState("m/84'/0'/0'/0/0");
  const [childKeys, setChildKeys] = useState([]); // Array of { priv, cc } for each step
  const [childInputs, setChildInputs] = useState(Array(5).fill(null).map(() => ({ priv: '', cc: '' })));
  const [pubKeyInput, setPubKeyInput] = useState('');
  const [payloadInput, setPayloadInput] = useState('');
  const [bip84Address, setBip84Address] = useState('');
  const [addrInput, setAddrInput] = useState('');
  const [bit132Input, setBit132Input] = useState('');
  const [tapXOnlyInput, setTapXOnlyInput] = useState('');
  const [tapTweakHashInput, setTapTweakHashInput] = useState('');
  const [tapTweakPointInput, setTapTweakPointInput] = useState('');
  const [tapSubStep, setTapSubStep] = useState(1);

  const addressType = useMemo(() => {
    if (derivationPath.startsWith("m/44'")) return 'legacy';
    if (derivationPath.startsWith("m/49'")) return 'nested';
    if (derivationPath.startsWith("m/84'")) return 'native';
    if (derivationPath.startsWith("m/86'")) return 'taproot';
    return 'native';
  }, [derivationPath]);

  const pathDetails = useMemo(() => {
    try {
      const parts = derivationPath.split('/').slice(1);
      return parts.map(part => {
        const hardened = part.endsWith("'");
        const indexVal = parseInt(part.replace("'", ""));
        const hex = (hardened ? indexVal + 0x80000000 : indexVal).toString(16).padStart(8, '0');
        return { label: part, hex, indexVal, hardened };
      });
    } catch (e) {
      return [];
    }
  }, [derivationPath]);

  const taprootDeconstruction = useMemo(() => {
    if (addressType !== 'taproot' || childKeys.length === 0) return null;
    try {
      const internalPub = cryptoUtils.ecMultiply(childKeys[childKeys.length - 1].priv);
      const xOnly = internalPub.slice(2);
      const tweakHash = cryptoUtils.taggedHash("TapTweak", hexToBytes(xOnly));
      const tweakPoint = cryptoUtils.ecMultiply(tweakHash);
      const evenPub = '02' + xOnly; // BIP341: Taproot tweak must be added to a point with an even Y coordinate
      const outputKey = cryptoUtils.ecAdd(evenPub, tweakPoint);
      return { internalPub, xOnly, tweakHash, tweakPoint, outputKey };
    } catch (e) {
      return null;
    }
  }, [addressType, childKeys]);

  const isValidPath = (path) => {
    const pathRegex = /^m(\/\d+'?){5}$/;
    if (!pathRegex.test(path)) return false;
    const parts = path.split('/').slice(1);
    const purpose = parts[0];
    const coinType = parts[1];
    const change = parts[3];
    return ["44'", "49'", "84'", "86'"].includes(purpose) && 
           coinType === "0'" && 
           ["0", "1"].includes(change);
  };

  const isXpubComplete = useMemo(() => {
    if (!isXpubMode) return false;
    const targets = [2, 3]; // Step 9 and 10
    return targets.every(i => {
      const key = childKeys[i];
      if (!key) return false;
      const fingerprint = cryptoUtils.getFingerprint(key.parentPub);
      const expectedXpub = cryptoUtils.serializeXpub(key.depth, fingerprint, key.index, key.cc, key.pub);
      const ok = xpubInputs[i]?.pub === key.pub && xpubInputs[i]?.xpub === expectedXpub;
      if (!ok) return false;
      if (addressType === 'nested') {
        const expectedYpub = cryptoUtils.serializeXpub(key.depth, fingerprint, key.index, key.cc, key.pub, "049d7cb2");
        return xpubInputs[i]?.ypub === expectedYpub;
      }
      if (addressType === 'native') {
        const expectedZpub = cryptoUtils.serializeXpub(key.depth, fingerprint, key.index, key.cc, key.pub, "04b24746");
        return xpubInputs[i]?.zpub === expectedZpub;
      }
      return true;
    });
  }, [isXpubMode, xpubInputs, childKeys, addressType]);

  const randomizePath = () => {
    const purposes = ["44'", "49'", "84'", "86'"];
    const purpose = purposes[Math.floor(Math.random() * purposes.length)];
    const x1 = Math.floor(Math.random() * 100);
    const x2 = Math.floor(Math.random() * 2); // Only 0 or 1
    const x3 = Math.floor(Math.random() * 1000);
    setDerivationPath(`m/${purpose}/0'/${x1}'/${x2}/${x3}`);
    setTapSubStep(1);
    if (step > 6) setStep(6);
  };

  // Handle derived data asynchronously
  useEffect(() => {
    async function deriveAll() {
      if (!bip39Details) return;
      const fullSalt = "mnemonic" + passphrase;
      const s = await cryptoUtils.pbkdf2Sha512(bip39Details.mnemonic, fullSalt, 2048, 64);
      setSeed(s);

      // Root Key Derivation
      const fullKey = cryptoUtils.hmacSha512(hexToBytes("426974636f696e2073656564"), hexToBytes(s));
      const rPriv = fullKey.slice(0, 64);
      const rCC = fullKey.slice(64, 128);
      setRootPriv(rPriv);
      setRootChainCode(rCC);

      // Parse path and derive intermediate keys
      try {
        const parts = derivationPath.split('/').slice(1);
        let currPriv = rPriv;
        let currCC = rCC;
        let currParentPub = cryptoUtils.ecMultiply(rPriv);
        const intermediate = [];

        for (let i = 0; i < parts.length; i++) {
          const part = parts[i];
          const hardened = part.endsWith("'");
          const idx = parseInt(part.replace("'", ""));
          const result = cryptoUtils.deriveChild(currPriv, currCC, idx, hardened);
          
          const prevPub = currParentPub;
          currPriv = result.privKey;
          currCC = result.chainCode;
          currParentPub = cryptoUtils.ecMultiply(currPriv);

          intermediate.push({ 
            priv: currPriv, 
            cc: currCC, 
            pub: currParentPub,
            parentPub: prevPub,
            label: part,
            depth: i + 1,
            index: hardened ? idx + 0x80000000 : idx
          });
        }
        setChildKeys(intermediate);

        // Final address calculation based on detected type
        if (intermediate.length > 0) {
          const finalPriv = intermediate[intermediate.length - 1].priv;
          const pubKeyHex = cryptoUtils.ecMultiply(finalPriv);
          
          let addr = '';
          if (addressType === 'legacy') {
            addr = cryptoUtils.p2pkh(pubKeyHex);
          } else if (addressType === 'nested') {
            addr = cryptoUtils.p2sh_p2wpkh(pubKeyHex);
          } else if (addressType === 'native') {
            addr = cryptoUtils.bech32("bc", hexToBytes(cryptoUtils.hash160(hexToBytes(pubKeyHex))), 0);
          } else if (addressType === 'taproot') {
            addr = cryptoUtils.p2tr(pubKeyHex);
          }
          setBip84Address(addr);
        }
      } catch (e) {
        console.error("Path derivation error:", e);
      }
    }
    deriveAll();
  }, [bip39Details, passphrase, derivationPath]);

  return (
    <div className={`min-h-screen ${isDark ? 'dark' : ''} transition-colors duration-300 bg-white dark:bg-[#0a0a0c] text-black dark:text-gray-100 flex flex-col md:flex-row h-screen font-sans`}>
      {/* Journey Pane (70%) */}
      <div className="flex-1 md:basis-[70%] p-8 border-r border-gray-200 dark:border-gray-800 overflow-y-auto no-scrollbar">
        <header className="mb-12 flex justify-between items-center bg-white/50 dark:bg-[#0a0a0c]/50 backdrop-blur-md sticky top-0 py-4 z-10">
          <div>
            <h1 className="text-4xl font-extrabold tracking-tighter mb-1 bg-gradient-to-br from-blue-400 via-indigo-500 to-purple-600 bg-clip-text text-transparent uppercase">
              HD Wallet Lab
            </h1>
            <p className="text-[10px] uppercase tracking-[0.4em] font-bold text-gray-400 dark:text-gray-600">
              Interactive Cryptography Journey
            </p>
          </div>
        </header>

        <div className="max-w-4xl mx-auto space-y-12 pb-32">
          {/* Step 1: Entropy */}
          <StepCard 
            number="01" 
            title="Entropy (Raw Bits)" 
            isActive={step === 1} 
            isLocked={false}
            isCompleted={step > 1}
            hint="ใช้ปุ่ม GENERATE ENTROPY เพื่อสร้างชุดข้อมูลความสุ่มขนาด 128 บิต"
          >
            <div className="flex flex-col gap-6">
              <p className="text-gray-500 dark:text-gray-400 leading-relaxed text-lg">
                คอมพิวเตอร์มองความสุ่มเป็น <span className="text-blue-500 font-bold">Bits</span> (0 หรือ 1) สำหรับ Mnemonic 12 คำ เราต้องการความสุ่มขนาด 128 บิต
              </p>
              
              <div className="space-y-4">
                <div className="flex flex-col gap-2">
                  <label className="text-[10px] font-black tracking-[0.2em] text-gray-400 px-1">Raw Binary (128 Bits)</label>
                  <textarea 
                    value={entropyBinary}
                    onChange={(e) => {
                      const val = e.target.value.replace(/[^01]/g, '');
                      setEntropyBinary(val);
                      if (val.length >= 128) setStep(2);
                    }}
                    placeholder="Click Generate Entropy below or type 128 bits of 0s and 1s here..."
                    className={`font-mono text-[10px] md:text-xs p-6 bg-gray-50 dark:bg-gray-900/80 rounded-3xl break-all border-2 leading-relaxed shadow-inner min-h-[80px] w-full outline-none transition-all resize-none ${
                        entropyBinary && (entropyBinary.length === 128 || entropyBinary.length === 256) 
                          ? 'border-green-500/50 text-black dark:text-white' 
                          : 'border-gray-200 dark:border-gray-800 text-gray-500 focus:border-blue-500/30'
                    }`}
                  />
                </div>

                <div className="flex flex-col sm:flex-row items-center justify-end mt-4">
                  <button 
                    onClick={generateEntropy}
                    className="px-10 py-5 bg-blue-600 text-white rounded-3xl font-black shadow-xl shadow-blue-500/20 hover:bg-blue-700 active:scale-95 transition-all text-sm uppercase tracking-widest"
                  >
                    Generate Random
                  </button>
                </div>
              </div>
            </div>
          </StepCard>

          {/* Step 2: SHA256 Checksum */}
          <StepCard 
            number="02" 
            title="SHA-256 Checksum" 
            isActive={step === 2} 
            isLocked={step < 1}
            isCompleted={step > 2}
            hint="นำ Entropy (Binary) ในด่าน 1 ไปแปลงเป็น Hex ด้วยเครื่องมือ Base converter (From: 2, To: 16) ก่อนจะนำ Hex นั้นไปใส่ในช่อง Data ของ SHA-256 แล้วนำผลลัพธ์แบบเต็มมาวาง"
          >
            <div className="space-y-6">
              <p className="text-gray-500 dark:text-gray-400 leading-relaxed">
                สร้างชุดข้อมูลตรวจสอบความถูกต้อง (Verification) เพื่อใช้ยืนยันความสมบูรณ์ของความสุ่มที่ได้มา
              </p>
              <div className="flex flex-col gap-3">
                <label className="text-[10px] font-black tracking-[0.2em] text-gray-400 px-1">Full SHA-256 Output</label>
                <div className="relative">
                  <textarea 
                    autoComplete="off"
                    onChange={(e) => {
                      const val = e.target.value.trim().toLowerCase();
                      const expected = cryptoUtils.sha256(hexToBytes(entropy));
                      if (val === '///') {
                        e.target.value = expected;
                        setStep(3);
                        return;
                      }
                      if (val === expected) {
                        setStep(3);
                      }
                    }}
                    className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                      step > 2 ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                    }`}
                    placeholder="Paste 64-char hex here..."
                  />
                  {step > 2 && (
                    <div className="absolute right-4 top-4 text-green-500">
                      ✓
                    </div>
                  )}
                </div>
              </div>
            </div>
          </StepCard>

          {/* Step 3: Mnemonic Mapping */}
          <StepCard 
            number="03" 
            title="Mnemonic Word Mapping" 
            isActive={step === 3} 
            isLocked={step < 3}
            isCompleted={step > 3}
            hint="นำ Raw Binary (128 บิต) จากด่าน 1 มาต่อกับ 4 บิตแรกของ Checksum จากด่าน 2 ให้ได้ 132 บิต แล้วกรอกลงในช่องเพื่อปลดล็อกรายชื่อคำ"
          >
            <div className="space-y-8">
              <div className="bg-blue-50/10 dark:bg-blue-900/5 p-6 rounded-3xl border border-blue-100 dark:border-blue-900/20">
                <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                  แปลงชุดข้อมูล Binary ทั้งหมดให้กลายเป็นคำที่มนุษย์อ่านออก 12 คำตามมาตรฐาน BIP39
                </p>
                <div className="flex flex-col gap-4">
                  <textarea 
                    value={bit132Input}
                    onChange={(e) => {
                      const val = e.target.value.trim();
                      const expected = entropyBinary + (bip39Details?.checksumBits || '');
                      setBit132Input(val === '///' ? expected : val);
                    }}
                    placeholder="Paste 132-bit combined string here..."
                    className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-20 resize-none break-all ${
                      bit132Input === (entropyBinary + (bip39Details?.checksumBits || '')) 
                        ? 'border-green-500/50' 
                        : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                    }`}
                  />
                  {entropy && bit132Input === (entropyBinary + bip39Details.checksumBits) && (
                    <p className="text-[10px] text-green-500 font-bold uppercase tracking-widest px-1 animate-pulse">
                      ✓ 132-bit String Verified. Words Unlocked.
                    </p>
                  )}
                </div>
              </div>

              <div className={`grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 transition-all duration-700 ${
                entropy && bit132Input === (entropyBinary + bip39Details.checksumBits)
                  ? 'opacity-100 scale-100 translate-y-0' 
                  : 'opacity-0 h-0 overflow-hidden pointer-events-none'
              }`}>
                {bip39Details?.groups.map((item, i) => (
                  <div key={i} className="flex flex-col gap-2 p-4 bg-gray-50 dark:bg-gray-900 border border-gray-100 dark:border-gray-800 rounded-2xl transition-all hover:border-blue-500/30">
                    <div className="flex justify-between items-center px-1">
                      <span className="text-[10px] font-black text-gray-400 tracking-widest">Word #{i+1}</span>
                      <span className="text-[10px] font-mono text-blue-500/50">{item.bits}</span>
                    </div>
                    <div className="relative">
                      <input 
                        type="text" 
                        value={guessedWords[i]}
                        onChange={(e) => {
                          const val = e.target.value;
                          if (val === '///') {
                            setGuessedWords(bip39Details.groups.map(g => g.word));
                            return;
                          }
                          if (val.includes(' ')) {
                            const words = val.trim().split(/\s+/);
                            if (words.length > 1) {
                              const newGuesses = [...guessedWords];
                              for (let j = 0; j < words.length && (i + j) < 12; j++) {
                                newGuesses[i + j] = words[j];
                              }
                              setGuessedWords(newGuesses);
                              return;
                            }
                          }
                          const newGuesses = [...guessedWords];
                          newGuesses[i] = val;
                          setGuessedWords(newGuesses);
                        }}
                        className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-3 font-bold text-sm outline-none transition-all shadow-inner ${
                          guessedWords[i].toLowerCase().trim() === item.word 
                            ? 'border-green-500/50 text-green-500' 
                            : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                        }`}
                        placeholder={`Index ${item.index}...`}
                      />
                    </div>
                  </div>
                ))}
              </div>
              
              <div className="flex flex-col items-center gap-4">
                {!isMnemonicComplete ? (
                  <p className="text-center text-xs text-gray-400 italic">
                    {bip39Details 
                      ? `Tip: ใช้ Toolbox หาคำจาก Index หรือลองเดากันดู! (ตัวอย่างคำแรกของ Mnemonic คือ "${bip39Details.groups[0].word}")`
                      : "กรุณากลับไปสร้าง Entropy ในด่านที่ 1 ก่อนครับ"}
                  </p>
                ) : (
                  <button 
                    onClick={() => {
                      navigator.clipboard.writeText(bip39Details.mnemonic);
                    }}
                    className="px-6 py-2 bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 rounded-xl font-bold text-[10px] tracking-widest transition-all hover:bg-gray-200 dark:hover:bg-gray-700 active:scale-95 border border-gray-200 dark:border-gray-700"
                  >
                    📋 Copy Mnemonic Phrase
                  </button>
                )}
              </div>
            </div>
          </StepCard>

          {/* Step 4: Mnemonic to Seed */}
          <StepCard 
            number="04" 
            title="Mnemonic to Seed (PBKDF2)" 
            isActive={step === 4} 
            isLocked={step < 4}
            isCompleted={step > 4}
            hint="ใช้ Mnemonic เป็น Password และ 'mnemonic' + passphrase เป็น Salt สำหรับเครื่องมือ PBKDF2 (2048 iterations, ความยาว 64 ไบต์)"
          >
            <div className="space-y-6">
              <p className="text-gray-500 dark:text-gray-400 leading-relaxed">
                แปลงรายชื่อคำบอกรหัสผ่านให้กลายเป็นรหัสดิจิทัล (Binary Seed) ที่มีความปลอดภัยสูง
              </p>
              
              <div className="flex flex-col gap-4">
                <div className="flex flex-col gap-2">
                  <label className="text-[10px] font-black tracking-[0.2em] text-gray-400 px-1">Passphrase (Optional)</label>
                  <input 
                    type="text"
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    className="w-full bg-white dark:bg-black border-2 border-gray-200 dark:border-gray-800 focus:border-blue-500/30 rounded-2xl p-4 font-mono text-sm outline-none transition-all shadow-inner text-black dark:text-white"
                    placeholder="Enter passphrase if any..."
                  />
                </div>
                
                <div className="flex flex-col gap-2">
                  <label className="text-[10px] font-black tracking-[0.2em] text-gray-400 px-1">Derived 512-bit Seed (Hex)</label>
                  <div className="relative">
                    <textarea 
                      onChange={async (e) => {
                        const val = e.target.value.trim().toLowerCase();
                        const mnemonic = guessedWords.join(' ');
                        const salt = "mnemonic" + passphrase;
                        const expectedSeed = await cryptoUtils.pbkdf2Sha512(mnemonic, salt, 2048, 64);
                        if (val === '///') {
                          e.target.value = expectedSeed;
                          setStep(5);
                          return;
                        }
                        if (val === expectedSeed) setStep(5);
                      }}
                      className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-24 resize-none break-all ${
                        step > 4 ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                      }`}
                      placeholder="Paste 128-char hex seed here..."
                    />
                    {step > 4 && <div className="absolute right-4 top-4 text-green-500">✓</div>}
                  </div>
                </div>
              </div>
            </div>
          </StepCard>

          {/* Step 5: Root Key Derivation */}
          <StepCard 
            number="05" 
            title="Master Root Key" 
            isActive={step === 5} 
            isLocked={step < 5}
            isCompleted={step > 5}
            hint="ใช้เครื่องมือ HMAC-SHA512 โดยตั้งค่า Key เป็น 'Bitcoin seed' (แบบ Text) และ Data เป็น Seed (Hex) จากนั้นแบ่งผลลัพธ์เป็น 2 ครึ่ง: ครึ่งแรก (0-63) คือ Master Private Key และ ครึ่งหลัง (64-127) คือ Master Chain Code"
          >
            <div className="space-y-6">
              <p className="text-gray-500 dark:text-gray-400 leading-relaxed">
                สร้างกุญแจแม่บท (Master Root Key) ซึ่งเป็นจุดเริ่มต้นของกิ่งก้านสาขากระเป๋าเงินทั้งหมดของคุณ
              </p>
              
              <div className="flex flex-col gap-6">
                <div className="flex flex-col gap-2">
                  <label className="text-[10px] font-black tracking-[0.2em] text-gray-500 px-1">Master Private Key (m)</label>
                  <div className="relative">
                    <textarea 
                      value={rootPrivInput}
                      onChange={(e) => {
                        const val = e.target.value.trim().toLowerCase();
                        const valueToSet = val === '///' ? rootPriv : val;
                        setRootPrivInput(valueToSet);
                        if (valueToSet === rootPriv && (rootCCInput === rootChainCode || val === '///')) {
                          if (val === '///' && rootCCInput !== rootChainCode) setRootCCInput(rootChainCode);
                          setStep(6);
                        }
                      }}
                      className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                        rootPrivInput === rootPriv ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                      }`}
                      placeholder="Enter 32-byte private key hex..."
                    />
                    {rootPrivInput === rootPriv && <div className="absolute right-4 top-4 text-green-500 text-xl">✓</div>}
                  </div>
                </div>
                <div className="flex flex-col gap-2">
                  <label className="text-[10px] font-black tracking-[0.2em] text-gray-500 px-1">Master Chain Code</label>
                  <div className="relative">
                    <textarea 
                      value={rootCCInput}
                      onChange={(e) => {
                        const val = e.target.value.trim().toLowerCase();
                        const valueToSet = val === '///' ? rootChainCode : val;
                        setRootCCInput(valueToSet);
                        if (valueToSet === rootChainCode && (rootPrivInput === rootPriv || val === '///')) {
                          if (val === '///' && rootPrivInput !== rootPriv) setRootPrivInput(rootPriv);
                          setStep(6);
                        }
                      }}
                      className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                        rootCCInput === rootChainCode && rootPrivInput === rootPriv ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                      }`}
                      placeholder="Enter 32-byte chain code hex..."
                    />
                    {rootCCInput === rootChainCode && <div className="absolute right-4 top-4 text-green-500 text-xl">✓</div>}
                  </div>
                </div>
              </div>
            </div>
          </StepCard>

          {/* Step 6: Path Selection */}
          <StepCard 
            number="06" 
            title="Derivation Path (BIP84)" 
            isActive={step === 6} 
            isLocked={step < 6}
            isCompleted={step > 6}
            hint="สุ่มเส้นทาง (BIP44, 49, 84, 86) หรือกำหนดเองตามรูปแบบ m/purpose'/coin'/account'/change/index"
          >
            <div className="space-y-6">
              <p className="text-gray-500 dark:text-gray-400 leading-relaxed text-sm">
                เลือกประเภทกระเป๋าที่ต้องการสร้าง: 
                <span className="block mt-2 font-mono text-xs">
                  • <span className="text-blue-500">m/44'</span> (Legacy), 
                  • <span className="text-blue-500">m/49'</span> (Nested SegWit), 
                  • <span className="text-blue-500">m/84'</span> (Native SegWit), 
                  • <span className="text-blue-500">m/86'</span> (Taproot)
                </span>
              </p>
              
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="flex-1 relative">
                  <input 
                    type="text" 
                    value={derivationPath}
                    onChange={(e) => {
                      const val = e.target.value.trim();
                      setDerivationPath(val);
                      setTapSubStep(1);
                      setStep(6);
                  
                      if (isValidPath(val)) {
                        setStep(7);
                      }
                    }}
                    className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-sm outline-none transition-all shadow-inner text-black dark:text-white ${
                      isValidPath(derivationPath) ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-red-500/30'
                    }`}
                  />
                  <button 
                    onClick={randomizePath}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-2 bg-blue-500/10 hover:bg-blue-500/20 text-blue-500 rounded-xl transition-all text-xs font-bold"
                  >
                    RANDOM
                  </button>
                </div>
                <button 
                  onClick={() => isValidPath(derivationPath) && setStep(7)}
                  disabled={!isValidPath(derivationPath)}
                  className={`px-8 py-4 rounded-2xl font-bold text-sm uppercase tracking-widest transition-all shadow-lg ${
                    isValidPath(derivationPath)
                      ? 'bg-indigo-600 text-white hover:scale-105 active:scale-95 shadow-indigo-500/20'
                      : 'bg-gray-200 dark:bg-gray-800 text-gray-400 cursor-not-allowed opacity-50'
                  }`}
                >
                  Confirm & Derive
                </button>
              </div>
            </div>
          </StepCard>

          {/* Steps 7-11: Granular Child Derivation */}
          {childKeys.map((key, i) => (
            <StepCard 
              key={i}
              number={(7 + i).toString().padStart(2, '0')} 
              title={`Derive Child: ${key.label}`} 
              isActive={step === (7 + i)} 
              isLocked={step < (7 + i)}
              isCompleted={step > (7 + i)}
              hint={
                i === 0 ? `Hardened Derivation (${key.label}): 1. ใช้ HMAC-SHA512 (Key=Root CC, Data=0x00 + Root Priv + ${pathDetails[0]?.hex || '...'}) 2. แบ่งครึ่งผลลัพธ์: ครึ่งแรก=IL, ครึ่งหลัง=CC ใหม่ 3. นำ IL + Root Priv ใน BigInt Add เพื่อหา Private Key` :
                i === 1 ? `Hardened Derivation (${key.label}): 1. ใช้ HMAC-SHA512 (Key=CC ด่าน 7, Data=0x00 + Priv ด่าน 7 + ${pathDetails[1]?.hex || '...'}) 2. แบ่งครึ่งผลลัพธ์: ครึ่งแรก=IL, ครึ่งหลัง=CC ใหม่ 3. นำ IL + Priv ด่าน 7 ใน BigInt Add เพื่อหา Private Key` :
                i === 2 ? `Hardened Derivation (${key.label}): 1. ใช้ HMAC-SHA512 (Key=CC ด่าน 8, Data=0x00 + Priv ด่าน 8 + ${pathDetails[2]?.hex || '...'}) 2. หา IL/CC ใหม่ 3. IL + Priv ด่าน 8 = Priv ใหม่${isXpubMode ? ` [xpub: 1.Version(${addressType === 'nested' ? '0488b21e(xpub) และ 049d7cb2(ypub)' : addressType === 'native' ? '0488b21e(xpub) และ 04b24746(zpub)' : '0488b21e(xpub)'}) 2.Depth(03) 3.Fingerprint(8 ตัวแรกของ HASH-160(PubKey ด่าน 8)) 4.Index(${pathDetails[2]?.hex || '...'}) 5.ChainCode 6.PubKey 7.รวม 1-6 เข้า Base58Check]` : ""}` :
                i === 3 ? `Normal Derivation (${key.label}): 1. หา PubKey ด่าน 9 2. HMAC-SHA512 (Key=CC ด่าน 9, Data=PubKey ด่าน 9 + ${pathDetails[3]?.hex || '...'}) 3. IL + Priv ด่าน 9 = Priv ใหม่${isXpubMode ? ` [xpub mode CKDpub: 1.Version(${addressType === 'nested' ? '0488b21e(xpub) และ 049d7cb2(ypub)' : addressType === 'native' ? '0488b21e(xpub) และ 04b24746(zpub)' : '0488b21e(xpub)'}) 2.HMAC(Key=CC ด่าน 9, Data=PubKey ด่าน 9 + ${pathDetails[3]?.hex || '...'})->IL/CC 2.Tweak=EC-Multiply(IL) 3.PubKey ใหม่=EC-Point-Add(PubKey ด่าน 9, Tweak)]` : ""}` :
                `Normal Derivation (${key.label}): 1. หา Public Key ของด่าน 10 (EC-Multiply) 2. ใช้ HMAC-SHA512 (Key=CC ด่าน 10, Data=PubKey ด่าน 10 + ${pathDetails[4]?.hex || '...'}) 3. แบ่งครึ่งหา IL/CC 4. นำ IL + Priv ด่าน 10 ใน BigInt Add`
              }
            >
              <div className="space-y-6">
                <p className="text-gray-500 dark:text-gray-400 leading-relaxed text-sm">
                  {i === 0 ? `คำนวณกุญแจสำหรับระดับแรก (Purpose) เพื่อระบุกระเป๋ารูปแบบ ${addressType.toUpperCase()}` :
                   i === 1 ? "คำนวณกุญแจระดับที่สอง (Coin Type) เพื่อระบุว่าเป็นเหรียญ Bitcoin" :
                   i === 2 ? "คำนวณกุญแจระดับที่สาม (Account) เพื่อแยกจัดการบัญชีภายในกระเป๋า" :
                   i === 3 ? "แยกแยะระหว่างกุญแจสำหรับรับเงิน (External) หรือกุญแจสำหรับเงินทอน (Internal)" :
                   "คำนวณกุญแจสำหรับลำดับสุดท้าย (Index) ที่จะนำไปใช้สร้างที่อยู่เป็นลำดับสุดท้าย"}
                </p>
                <div className="grid grid-cols-1 gap-6">
                  <div className="flex flex-col gap-2">
                    <label className="text-[10px] font-black tracking-[0.2em] text-gray-500 px-1">Private Key</label>
                    <textarea 
                      value={childInputs[i]?.priv || ''}
                      onChange={(e) => {
                        const val = e.target.value.trim().toLowerCase();
                        const finalVal = val === '///' ? key.priv : val;
                        const newInputs = [...childInputs];
                        newInputs[i] = { ...newInputs[i], priv: finalVal };
                        setChildInputs(newInputs);
                        if (finalVal === key.priv && (newInputs[i].cc === key.cc || val === '///')) {
                          if (val === '///' && newInputs[i].cc !== key.cc) {
                             newInputs[i].cc = key.cc;
                             setChildInputs([...newInputs]);
                          }
                          setStep(7 + i + 1);
                        }
                      }}
                      className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                        childInputs[i]?.priv === key.priv ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                      }`}
                      placeholder={`Enter Private Key for ${key.label}...`}
                    />
                  </div>
                  <div className="flex flex-col gap-2">
                    <label className="text-[10px] font-black tracking-[0.2em] text-gray-500 px-1">Chain Code</label>
                    <textarea 
                      value={childInputs[i]?.cc || ''}
                      onChange={(e) => {
                        const val = e.target.value.trim().toLowerCase();
                        const finalVal = val === '///' ? key.cc : val;
                        const newInputs = [...childInputs];
                        newInputs[i] = { ...newInputs[i], cc: finalVal };
                        setChildInputs(newInputs);
                        if (finalVal === key.cc && (newInputs[i].priv === key.priv || val === '///')) {
                          if (val === '///' && newInputs[i].priv !== key.priv) {
                             newInputs[i].priv = key.priv;
                             setChildInputs([...newInputs]);
                          }
                          setStep(7 + i + 1);
                        }
                      }}
                      className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                        childInputs[i]?.cc === key.cc ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                      }`}
                      placeholder={`Enter Chain Code for ${key.label}...`}
                    />
                  </div>
                  {step > (7 + i) && <p className="text-[10px] text-green-500 font-bold uppercase tracking-widest px-1">✓ Child Derived & Verified</p>}
                </div>

                {i === 2 && (
                  <div className="flex justify-start mt-4">
                    <button 
                      onClick={() => setIsXpubMode(!isXpubMode)}
                      className={`px-4 py-2 rounded-xl text-[10px] font-bold uppercase tracking-widest transition-all border ${
                        isXpubMode 
                          ? 'bg-blue-500/10 border-blue-500 text-blue-500' 
                          : 'bg-gray-100 dark:bg-gray-800 border-gray-200 dark:border-gray-700 text-gray-400'
                      }`}
                    >
                      {isXpubMode ? 'Disable xpub Mode' : 'Enable xpub Mode'}
                    </button>
                  </div>
                )}

                {isXpubMode && (i === 2 || i === 3) && (
                  <div className="mt-6 p-6 bg-blue-50/10 dark:bg-blue-900/5 rounded-3xl border border-blue-200/20 space-y-4 animate-in fade-in slide-in-from-top-4 duration-500">
                    <div className="flex flex-col gap-2">
                       <label className="text-[10px] font-black tracking-[0.2em] text-blue-500/70 px-1">{i === 2 ? 'Account' : 'Change'} Public Key (Hex)</label>
                       <textarea 
                         value={xpubInputs[i]?.pub || ''}
                         onChange={(e) => {
                           const val = e.target.value.trim().toLowerCase();
                           const expected = key.pub;
                           const finalVal = val === '///' ? expected : val;
                           const newInputs = [...xpubInputs];
                           newInputs[i] = { ...newInputs[i], pub: finalVal };
                           setXpubInputs(newInputs);
                         }}
                         className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                           xpubInputs[i]?.pub === key.pub ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                         }`}
                         placeholder="Paste compressed public key..."
                       />
                    </div>
                    <div className="flex flex-col gap-2">
                       <label className="text-[10px] font-black tracking-[0.2em] text-blue-500/70 px-1">{i === 2 ? 'Account' : 'Change'} xpub</label>
                       <textarea 
                         value={xpubInputs[i]?.xpub || ''}
                         onChange={(e) => {
                           const val = e.target.value.trim();
                           const finger = cryptoUtils.getFingerprint(key.parentPub);
                           const expected = cryptoUtils.serializeXpub(key.depth, finger, key.index, key.cc, key.pub);
                           const finalVal = val === '///' ? expected : val;
                           const newInputs = [...xpubInputs];
                           newInputs[i] = { ...newInputs[i], xpub: finalVal };
                           setXpubInputs(newInputs);
                         }}
                         className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                           (() => {
                             const finger = cryptoUtils.getFingerprint(key.parentPub);
                             const expected = cryptoUtils.serializeXpub(key.depth, finger, key.index, key.cc, key.pub);
                             return xpubInputs[i]?.xpub === expected;
                           })() ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                         }`}
                         placeholder="Enter standard xpub..."
                       />
                    </div>
                    {addressType === 'nested' && (
                      <div className="flex flex-col gap-2">
                         <label className="text-[10px] font-black tracking-[0.2em] text-blue-500/70 px-1">{i === 2 ? 'Account' : 'Change'} ypub</label>
                         <textarea 
                           value={xpubInputs[i]?.ypub || ''}
                           onChange={(e) => {
                             const val = e.target.value.trim();
                             const finger = cryptoUtils.getFingerprint(key.parentPub);
                             const expected = cryptoUtils.serializeXpub(key.depth, finger, key.index, key.cc, key.pub, "049d7cb2");
                             const finalVal = val === '///' ? expected : val;
                             const newInputs = [...xpubInputs];
                             newInputs[i] = { ...newInputs[i], ypub: finalVal };
                             setXpubInputs(newInputs);
                           }}
                           className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                             (() => {
                               const finger = cryptoUtils.getFingerprint(key.parentPub);
                               const expected = cryptoUtils.serializeXpub(key.depth, finger, key.index, key.cc, key.pub, "049d7cb2");
                               return xpubInputs[i]?.ypub === expected;
                             })() ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                           }`}
                           placeholder="Enter ypub (BIP49)..."
                         />
                      </div>
                    )}
                    {addressType === 'native' && (
                      <div className="flex flex-col gap-2">
                         <label className="text-[10px] font-black tracking-[0.2em] text-blue-500/70 px-1">{i === 2 ? 'Account' : 'Change'} zpub</label>
                         <textarea 
                           value={xpubInputs[i]?.zpub || ''}
                           onChange={(e) => {
                             const val = e.target.value.trim();
                             const finger = cryptoUtils.getFingerprint(key.parentPub);
                             const expected = cryptoUtils.serializeXpub(key.depth, finger, key.index, key.cc, key.pub, "04b24746");
                             const finalVal = val === '///' ? expected : val;
                             const newInputs = [...xpubInputs];
                             newInputs[i] = { ...newInputs[i], zpub: finalVal };
                             setXpubInputs(newInputs);
                           }}
                           className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                             (() => {
                               const finger = cryptoUtils.getFingerprint(key.parentPub);
                               const expected = cryptoUtils.serializeXpub(key.depth, finger, key.index, key.cc, key.pub, "04b24746");
                               return xpubInputs[i]?.zpub === expected;
                             })() ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                           }`}
                           placeholder="Enter zpub (BIP84)..."
                         />
                      </div>
                    )}
                  </div>
                )}
              </div>
            </StepCard>
          ))}

          {/* Step 12: Final Private Key to Public Key */}
          <StepCard 
            number="12" 
            title="Final Priv to Pub" 
            isActive={step === 12} 
            isLocked={step < 12}
            isCompleted={step > 12}
            hint={`ใช้เครื่องมือ EC-Multiply โดยใส่ Private Key จากด่านที่แล้วลงในช่อง Data เพื่อให้ได้ Compressed Public Key${isXpubMode ? " หรือใช้ xpub จากด่านที่ 10 มาคำนวณหาได้เช่นกัน" : ""}`}
          >
            <div className="space-y-6">
              <p className="text-gray-500 dark:text-gray-400 leading-relaxed text-sm">
                แปลงความลับ (Private Key) ให้กลายเป็นกุญแจสาธารณะ (Public Key) เพื่อใช้ติดต่อกับเครือข่าย
              </p>
              <div className="relative">
                <textarea 
                  value={pubKeyInput}
                  onChange={(e) => {
                    const val = e.target.value.trim().toLowerCase();
                    const finalKey = childKeys[childKeys.length - 1];
                    const expectedPub = finalKey ? cryptoUtils.ecMultiply(finalKey.priv) : "";
                    const finalVal = val === '///' ? expectedPub : val;
                    setPubKeyInput(finalVal);
                    if (finalVal === expectedPub && expectedPub !== "") setStep(13);
                  }}
                  className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                    pubKeyInput ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                  }`}
                  placeholder="Enter Compressed Public Key Hex..."
                />
                {step > 12 && <div className="absolute right-4 top-4 text-green-500">✓</div>}
              </div>
            </div>
          </StepCard>

          {addressType === 'taproot' ? (
            <>
              {/* Step 13.1: Tagged Hash */}
              <StepCard 
                number="13.1" 
                title="Tweak Hash (Tagged)" 
                isActive={step === 13 && tapSubStep === 1} 
                isLocked={step < 13}
                isCompleted={step > 13 || (step === 13 && tapSubStep > 1)}
                hint="ใช้เครื่องมือ Tagged Hash ใน Toolbox: 1. Tag = TapTweak, 2. Data = นำ Internal Public Key (ด่าน 12) ตัด 2 ตัวหน้า (02/03) ทิ้งเหลือแค่ X-Only (พิกัด X ความยาว 64 ตัวอักษร)"
              >
                <div className="space-y-4">
                  <p className="text-sm text-gray-500">คำนวณค่า Scalar สำหรับปรับแต่งกุญแจตามมาตรฐาน BIP340</p>
                  <div className="relative">
                    <textarea 
                      value={tapTweakHashInput}
                      onChange={(e) => {
                        const val = e.target.value.trim().toLowerCase();
                        const expected = taprootDeconstruction?.tweakHash;
                        const finalVal = val === '///' ? expected : val;
                        setTapTweakHashInput(finalVal);
                        if (finalVal === expected) setTapSubStep(2);
                      }}
                      className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all ${
                        tapTweakHashInput === taprootDeconstruction?.tweakHash ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800'
                      }`}
                      placeholder="Enter Tweak Hash Hex..."
                    />
                  </div>
                </div>
              </StepCard>

              {/* Step 13.2: Tweak Point */}
              <StepCard 
                number="13.2" 
                title="Tweak Point (EC-Mul)" 
                isActive={step === 13 && tapSubStep === 2} 
                isLocked={step < 13 || (step === 13 && tapSubStep < 2)}
                isCompleted={step > 13 || (step === 13 && tapSubStep > 2)}
                hint="ใช้เครื่องมือ EC-Multiply: นำ Tweak Hash (ด่านก่อนหน้า) มาหา Public Key ที่สัมพันธ์กัน"
              >
                <div className="space-y-4">
                  <p className="text-sm text-gray-500">แปลงค่า Scalar ให้กลายเป็นพิกัดบนเส้นโค้ง (Point) เพื่อนำไปบวก</p>
                  <div className="relative">
                    <textarea 
                      value={tapTweakPointInput}
                      onChange={(e) => {
                        const val = e.target.value.trim().toLowerCase();
                        const expected = taprootDeconstruction?.tweakPoint;
                        const finalVal = val === '///' ? expected : val;
                        setTapTweakPointInput(finalVal);
                        if (finalVal === expected) setTapSubStep(3);
                      }}
                      className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all ${
                        tapTweakPointInput === taprootDeconstruction?.tweakPoint ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800'
                      }`}
                      placeholder="Enter Tweak Point Hex..."
                    />
                  </div>
                </div>
              </StepCard>

              {/* Step 13.3: Final Tweak (Point Add) */}
              <StepCard 
                number="13.3" 
                title="Output Key (Point-Add)" 
                isActive={step === 13 && tapSubStep === 3} 
                isLocked={step < 13 || (step === 13 && tapSubStep < 3)}
                isCompleted={step > 13}
                hint="ใช้เครื่องมือ EC-Point-Add: บวกกุญแจใบที่ 1 (Internal PubKey ด่าน 12 โดยเปลี่ยน 2 ตัวแรกให้เป็น '02' เสมอ) เข้ากับกุญแจใบที่ 2 (Tweak Point ด่าน 13.2)"
              >
                <div className="space-y-4">
                  <p className="text-sm text-gray-500">รวมกุญแจเดิมเข้ากับค่าปรับแต่งเพื่อให้ได้ Output Key (ต้องมั่นใจว่ากุญแจเดิมมีค่า Y เป็นคู่ หรือขึ้นต้นด้วย 02)</p>
                  <div className="relative">
                    <textarea 
                      value={payloadInput}
                      onChange={(e) => {
                        const val = e.target.value.trim().toLowerCase();
                        const expected = taprootDeconstruction?.outputKey;
                        const finalVal = val === '///' ? expected : val;
                        setPayloadInput(finalVal);
                        if (finalVal === expected) setStep(14);
                      }}
                      className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all ${
                        payloadInput === taprootDeconstruction?.outputKey ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800'
                      }`}
                      placeholder="Enter Final Output Key Hex..."
                    />
                  </div>
                </div>
              </StepCard>
            </>
          ) : (
            /* Step 13: Payload Calculation (Legacy/SegWit) */
            <StepCard 
              number="13" 
              title={
                addressType === 'legacy' ? "Public Key to Payload (HASH160)" :
                addressType === 'nested' ? "Public Key to P2SH Payload" :
                "Public Key to Payload (HASH160)"
              }
              isActive={step === 13} 
              isLocked={step < 13}
              isCompleted={step > 13}
              hint={
                addressType === 'legacy' ? "ใช้เครื่องมือ HASH-160 โดยใส่ Public Key (Hex) จากด่านที่แล้วลงในช่อง Data" :
                addressType === 'nested' ? "1. นำ HASH160 ของ PubKey มาสร้าง Witness Script (0014...) 2. นำ Hex นั้นไปเข้า HASH160 อีกรอบเพื่อให้ได้ Payload" :
                "ใช้เครื่องมือ HASH-160 โดยใส่ Public Key (Hex) จากด่านที่แล้วลงในช่อง Data"
              }
            >
              <div className="space-y-6">
                <p className="text-gray-500 dark:text-gray-400 leading-relaxed text-sm">
                  ลดขนาดกุญแจสาธารณะให้อยู่ในรูปแบบที่พร้อมสำหรับสร้างเป็นที่อยู่กระเป๋าเงิน (Payload)
                </p>
                {(() => {
                  let expected = "";
                  try {
                    const finalKey = childKeys[childKeys.length - 1];
                    if (finalKey) {
                      const pub = cryptoUtils.ecMultiply(finalKey.priv);
                      if (addressType === 'legacy' || addressType === 'native') {
                        expected = cryptoUtils.hash160(hexToBytes(pub));
                      } else if (addressType === 'nested') {
                        const pubHash = cryptoUtils.hash160(hexToBytes(pub));
                        const witnessProgram = "0014" + pubHash;
                        expected = cryptoUtils.hash160(hexToBytes(witnessProgram));
                      }
                    }
                  } catch (e) {}

                  return (
                    <div className="relative">
                      <textarea 
                        value={payloadInput}
                        onChange={(e) => {
                          const val = e.target.value.trim().toLowerCase();
                          const finalVal = val === '///' ? expected : val;
                          setPayloadInput(finalVal);
                          if (finalVal === expected && expected !== "") {
                            setStep(14);
                          }
                        }}
                        className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs outline-none transition-all shadow-inner text-black dark:text-white h-16 resize-none break-all ${
                          payloadInput === expected && expected !== "" ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                        }`}
                        placeholder="Enter 20-byte Payload Hex..."
                      />
                      {(step > 13 || (payloadInput === expected && expected !== "")) && <div className="absolute right-4 top-4 text-green-500">✓</div>}
                    </div>
                  );
                })()}
              </div>
            </StepCard>
          )}

          {/* Step 14: Final Encoding */}
          <StepCard 
            number="14" 
            title={`${addressType.charAt(0).toUpperCase() + addressType.slice(1)} Address`} 
            isActive={step === 14} 
            isLocked={step < 14}
            isCompleted={step > 14}
            hint={
              addressType === 'legacy' ? "ใช้ Base58Check Encode ข้อมูล: Prefix '00' + Payload (ด่าน 13)" :
              addressType === 'nested' ? "ใช้ Base58Check Encode ข้อมูล: Prefix '05' + Payload (ด่าน 13)" :
              addressType === 'native' ? "ใช้ Bech32 Encode (Version 0) ข้อมูล: HRP 'bc' + Payload (ด่าน 13)" :
              "ใช้ Bech32m Encode (Version 1) ข้อมูล: HRP 'bc' + Output Key (นำด่าน 13.3 ตัด 2 ไตว์แรก 02/03 ทิ้งให้เหลือแต่พิกัด X-only 64 อักษร)"
            }
          >
            <div className="space-y-8">
              <p className="text-gray-500 dark:text-gray-400 leading-relaxed text-sm">
                แปลงข้อมูลทางเทคนิคทั้งหมดให้กลายเป็นที่อยู่กระเป๋าเงิน (Address) ที่มนุษย์สามารถใช้งานได้จริง
              </p>
              <div className="relative group overflow-hidden">
                <div className={`absolute -inset-1 bg-gradient-to-r from-blue-500 via-purple-600 to-pink-500 rounded-[2.5rem] blur opacity-25 group-hover:opacity-100 transition duration-1000 ${step > 14 ? 'opacity-100' : ''}`}></div>
                <div className="relative p-10 bg-white dark:bg-[#0d0d0f] rounded-[2.5rem] border border-gray-100 dark:border-gray-800 flex flex-col items-center gap-6">
                  <div className="text-5xl">{step > 14 ? '🏆' : '🗝️'}</div>
                  <div className="text-center space-y-4 w-full">
                    <p className="text-[10px] font-black uppercase tracking-[0.3em] text-gray-400">Final Bitcoin Address</p>
                    <div className="relative">
                      <textarea 
                        value={addrInput}
                        onChange={(e) => {
                          const val = e.target.value.trim();
                          const finalVal = val === '///' ? bip84Address : val;
                          setAddrInput(finalVal);
                        }}
                        className={`w-full bg-white dark:bg-black border-2 rounded-2xl p-4 font-mono text-xs md:text-sm outline-none transition-all shadow-inner text-black dark:text-white h-20 resize-none break-all ${
                          addrInput === bip84Address ? 'border-green-500/50' : 'border-gray-200 dark:border-gray-800 focus:border-blue-500/30'
                        }`}
                        placeholder={
                          addressType === 'legacy' || addressType === 'nested' 
                            ? "Manually assemble: prefix + payload + checksum..." 
                            : "Manually assemble: hrp + separator + encoded_data..."
                        }
                      />
                      {addrInput === bip84Address && <div className="absolute right-4 top-4 text-green-500 text-xl">✓</div>}
                    </div>
                  </div>
                </div>
              </div>
              
              <button 
                onClick={() => setStep(15)}
                disabled={addrInput !== bip84Address}
                className={`w-full py-4 bg-green-500 text-white rounded-2xl font-bold uppercase tracking-widest transition-all hover:scale-[1.02] active:scale-[0.98] ${step > 14 || addrInput !== bip84Address ? 'opacity-50 cursor-not-allowed' : ''} ${step > 14 ? 'hidden' : 'block'}`}
              >
                Complete Journey 🚀
              </button>

              <p className="text-center text-gray-400 text-xs italic leading-relaxed">
                {isXpubComplete ? (
                  <span className="text-green-500 font-bold block scale-110 transition-all duration-1000">
                    🏆 มหาเทพแห่งคริปโต! คุณสำเร็จการเดินทางใน xpub Mode อย่างสมบูรณ์แบบ 🚀
                  </span>
                ) : (
                  <>
                    Congratulations! You've manually derived a Bitcoin address through the entire HD Wallet stack. 🚀
                    {isXpubMode ? (
                      <span className="block mt-2 text-amber-500">
                        ⚠️ เกือบได้ความสำเร็จพิเศษแล้ว! กรอกข้อมูลใน xpub mode ให้ครบและถูกต้องเพื่อปลดล็อค
                      </span>
                    ) : (
                      <span className="block mt-2 opacity-50">
                        (ปลดล็อคความสำเร็จพิเศษด้วยการเล่น xpub mode ในด่าน 9-10)
                      </span>
                    )}
                  </>
                )}
              </p>
            </div>
          </StepCard>
        </div>
      </div>

      {/* Toolbox Pane (30%) */}
      <aside className="md:basis-[30%] h-screen overflow-hidden flex flex-col bg-gray-50/30 dark:bg-black/40 backdrop-blur-3xl p-6 border-l border-gray-200 dark:border-gray-800">
        <Toolbox />
      </aside>
    </div>
  );
}

export default App;
