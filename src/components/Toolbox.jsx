import { useState, useEffect } from 'react';
import { cryptoUtils, hexToBytes, bytesToHex } from '../utils/crypto';
import { bech32 } from 'bech32';

export default function Toolbox() {
  const [algo, setAlgo] = useState('SHA-256');
  const [inputs, setInputs] = useState({ primary: '', secondary: '', extra: '' });
  const [output, setOutput] = useState('-');
  const [error, setError] = useState('');

  const hasSecondary = algo === 'PBKDF2' || algo === 'HMAC-SHA512' || algo === 'BigInt Add (Mod N)' || algo === 'Base Converter' || algo === 'Bech32 Encode';
  const isBIP32Math = algo === 'BigInt Add (Mod N)';
  const isBaseConv = algo === 'Base Converter';
  const isBech32 = algo === 'Bech32 Encode';

  const getAlgoDetails = (name) => {
    switch (name) {
      case 'PBKDF2': return "Mnemonic -> Seed: Password = Mnemonic String, Salt = 'mnemonic' + passphrase. Iterations = 2048, Length = 64 bytes.";
      case 'HMAC-SHA512': return "BIP32 Derivation: Key = Parent Chain Code. Data (Hardened) = 0x00 + Parent Private Key + (Index + 0x80000000). Data (Normal) = Parent Public Key + Index. Output IL (Left 32B) + IR (Right 32B).";
      case 'BigInt Add (Mod N)': return "BIP32 Key Addition: Output = (A + B) % N. Default N is Secp256k1 order.";
      case 'Base Converter': return "Convert numbers between bases. E.g. Dec (10) to Hex (16).";
      case 'Bech32 Encode': return "Manual Bech32: 1) Prepend Witness Version (00) to Payload Hex. 2) Enter HRP (bc) for checksum. 3) Output is 'data + checksum'. 4) Manually add 'bc1' prefix to get final address.";
      case 'SHA-256': return "Hashing entropy or checksum verification.";
      case 'HASH-160': return "Public Key to Address: SHA-256 then RIPEMD-160.";
      case 'EC-Multiply': return "Private Key to Public Key (Compressed).";
      default: return "";
    }
  };

  useEffect(() => {
    if (!inputs.primary) {
      setOutput('-');
      setError('');
      return;
    }

    async function calculate() {
      try {
        let result = '';
        const primaryClean = inputs.primary.replace(/\s/g, '');
        const secondaryClean = inputs.secondary.replace(/\s/g, '');

        const data = primaryClean.startsWith('0x') || (/^[0-9a-fA-F]+$/.test(primaryClean) && primaryClean.length % 2 === 0)
          ? hexToBytes(primaryClean) 
          : new TextEncoder().encode(inputs.primary);

        const secondaryData = secondaryClean.startsWith('0x') || (/^[0-9a-fA-F]+$/.test(secondaryClean) && secondaryClean.length % 2 === 0)
          ? hexToBytes(secondaryClean)
          : new TextEncoder().encode(inputs.secondary);

        switch (algo) {
          case 'SHA-256':
            result = cryptoUtils.sha256(data);
            break;
          case 'RIPEMD-160':
            result = cryptoUtils.ripemd160(data);
            break;
          case 'HASH-160':
            result = cryptoUtils.hash160(data);
            break;
          case 'EC-Multiply':
            result = cryptoUtils.ecMultiply(inputs.primary);
            break;
          case 'Base58Check':
            result = cryptoUtils.base58check(data);
            break;
          case 'PBKDF2': {
            const iterations = parseInt(inputs.extra) || 2048;
            const keyLength = parseInt(inputs.secondary_extra) || 64;
            result = await cryptoUtils.pbkdf2Sha512(inputs.primary, inputs.secondary || "", iterations, keyLength);
            break;
          }
          case 'HMAC-SHA512':
            result = cryptoUtils.hmacSha512(secondaryData, data);
            break;
          case 'BigInt Add (Mod N)': {
            const aStr = inputs.primary.replace(/\s/g, '');
            const bStr = inputs.secondary.replace(/\s/g, '');
            const nStr = inputs.extra.replace(/\s/g, '');
            const a = BigInt(aStr.startsWith('0x') ? aStr : '0x' + aStr);
            const b = BigInt(bStr.startsWith('0x') ? bStr : '0x' + bStr);
            const n = BigInt(nStr.startsWith('0x') ? nStr : '0x' + nStr);
            result = ((a + b) % n).toString(16).padStart(64, '0');
            break;
          }
          case 'Base Converter': {
            const fromBase = parseInt(inputs.secondary) || 10;
            const toBase = parseInt(inputs.extra) || 16;
            const primaryClean = inputs.primary.replace(/\s/g, '');
            
            let numStr = primaryClean;
            if (fromBase === 2) numStr = '0b' + primaryClean;
            else if (fromBase === 16 && !primaryClean.startsWith('0x')) numStr = '0x' + primaryClean;
            
            const num = BigInt(numStr);
            result = num.toString(toBase).toLowerCase();
            break;
          }
          case 'Bech32 Encode': {
            const hrp = inputs.extra || 'bc';
            const dataBytes = hexToBytes(inputs.primary.replace(/\s/g, ''));
            if (dataBytes.length < 1) throw new Error("Empty data");
            
            // Treat the FIRST BYTE as the first 5-bit word (Witness Version)
            // Perform toWords on the REST of the bytes (Payload)
            const firstByteWord = dataBytes[0];
            const payloadWords = bech32.toWords(dataBytes.slice(1));
            const words = [firstByteWord, ...payloadWords];
            
            const fullEncoding = bech32.encode(hrp, words);
            // Return only the part after the separator '1'
            result = fullEncoding.split('1').pop();
            break;
          }
          default:
            result = '-';
        }
        setOutput(result);
        setError('');
      } catch (e) {
        setOutput('Invalid Input');
        setError(e.message);
      }
    }
    calculate();
  }, [algo, inputs]);

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm border border-gray-200 dark:border-gray-700 h-full flex flex-col">
      <h3 className="text-lg font-bold mb-4 flex items-center gap-2 text-black dark:text-white">
        <span className="text-blue-500">⚡</span> Live Calculator
      </h3>
      
      <div className="space-y-4 flex-1 overflow-y-auto">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Algorithm</label>
          <select 
            value={algo}
            onChange={(e) => {
              const newAlgo = e.target.value;
              setAlgo(newAlgo);
              if (newAlgo === 'BigInt Add (Mod N)') {
                setInputs({ primary: '', secondary: '', extra: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', secondary_extra: '' });
              } else if (newAlgo === 'Base Converter') {
                setInputs({ primary: '', secondary: '10', extra: '16', secondary_extra: '' });
              } else if (newAlgo === 'PBKDF2') {
                setInputs({ primary: '', secondary: '', extra: '2048', secondary_extra: '64' });
              } else {
                setInputs({ primary: '', secondary: '', extra: '', secondary_extra: '' });
              }
            }}
            className="w-full bg-white dark:bg-black border-2 border-gray-200 dark:border-gray-700 rounded-2xl p-3 outline-none focus:ring-2 ring-blue-500/20 transition-all font-medium text-black dark:text-white"
          >
            <option>Base Converter</option>
            <option>Base58Check</option>
            <option>Bech32 Encode</option>
            <option>BigInt Add (Mod N)</option>
            <option>EC-Multiply</option>
            <option>HASH-160</option>
            <option>HMAC-SHA512</option>
            <option>PBKDF2</option>
            <option>RIPEMD-160</option>
            <option>SHA-256</option>
          </select>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
              {algo === 'PBKDF2' ? 'Password' : isBIP32Math ? 'Value A' : isBaseConv ? 'Number' : isBech32 ? 'Data (Hex)' : 'Data'}
            </label>
            <textarea 
              value={inputs.primary}
              onChange={(e) => setInputs({ ...inputs, primary: e.target.value })}
              placeholder="Enter value..."
              className="w-full bg-white dark:bg-black border-2 border-gray-200 dark:border-gray-700 rounded-2xl p-3 font-mono text-sm h-24 resize-none outline-none focus:ring-2 ring-blue-500/20 transition-all shadow-inner placeholder:text-gray-400 text-black dark:text-white"
            />
          </div>

          {hasSecondary && !isBech32 && !isBaseConv && (
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
                {algo === 'PBKDF2' ? 'Salt' : isBIP32Math ? 'Value B' : 'Key'}
              </label>
              <textarea 
                value={inputs.secondary}
                onChange={(e) => setInputs({ ...inputs, secondary: e.target.value })}
                placeholder="Enter value..."
                className="w-full bg-white dark:bg-black border-2 border-gray-200 dark:border-gray-700 rounded-2xl p-3 font-mono text-sm h-24 resize-none outline-none focus:ring-2 ring-blue-500/20 transition-all shadow-inner placeholder:text-gray-400 text-black dark:text-white"
              />
            </div>
          )}

          {(isBIP32Math || isBaseConv || isBech32 || algo === 'PBKDF2') && (
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
                {isBIP32Math ? 'Modulo N (Hex)' : isBaseConv ? 'From Base' : isBech32 ? 'HRP for Checksum' : algo === 'PBKDF2' ? 'Iterations' : 'Extra'}
              </label>
              {isBaseConv ? (
                <select 
                  value={inputs.secondary}
                  onChange={(e) => setInputs({ ...inputs, secondary: e.target.value })}
                  className="w-full bg-white dark:bg-black border-2 border-gray-200 dark:border-gray-700 rounded-2xl p-3 outline-none focus:ring-2 ring-blue-500/20 transition-all font-medium text-black dark:text-white"
                >
                  <option value="2">2 (Binary)</option>
                  <option value="10">10 (Decimal)</option>
                  <option value="16">16 (Hex)</option>
                </select>
              ) : (
                <textarea 
                  value={inputs.extra || ''}
                  onChange={(e) => setInputs({ ...inputs, extra: e.target.value })}
                  placeholder={isBech32 ? "e.g. bc" : algo === 'PBKDF2' ? "2048" : "Enter value..."}
                  className="w-full bg-white dark:bg-black border-2 border-gray-200 dark:border-gray-700 rounded-2xl p-3 font-mono text-sm h-16 resize-none outline-none focus:ring-2 ring-blue-500/20 transition-all shadow-inner placeholder:text-gray-400 text-black dark:text-white"
                />
              )}
            </div>
          )}

          {(isBaseConv || algo === 'PBKDF2') && (
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
                {isBaseConv ? 'To Base' : 'Key Length (Bytes)'}
              </label>
              {isBaseConv ? (
                <select 
                  value={inputs.extra}
                  onChange={(e) => setInputs({ ...inputs, extra: e.target.value })}
                  className="w-full bg-white dark:bg-black border-2 border-gray-200 dark:border-gray-700 rounded-2xl p-3 outline-none focus:ring-2 ring-blue-500/20 transition-all font-medium text-black dark:text-white"
                >
                  <option value="2">2 (Binary)</option>
                  <option value="10">10 (Decimal)</option>
                  <option value="16">16 (Hex)</option>
                </select>
              ) : (
                <textarea 
                  value={inputs.secondary_extra || ''}
                  onChange={(e) => setInputs({ ...inputs, secondary_extra: e.target.value })}
                  placeholder="64"
                  className="w-full bg-white dark:bg-black border-2 border-gray-200 dark:border-gray-700 rounded-2xl p-3 font-mono text-sm h-16 resize-none outline-none focus:ring-2 ring-blue-500/20 transition-all shadow-inner placeholder:text-gray-400 text-black dark:text-white"
                />
              )}
            </div>
          )}
        </div>

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">Output</label>
          <div className="relative group">
            <div className={`w-full p-4 rounded-xl font-mono text-sm break-all border transition-all ${
              output === 'Invalid Input' 
                ? 'bg-red-50 dark:bg-red-900/10 border-red-200 dark:border-red-800 text-red-500' 
                : 'bg-green-50/50 dark:bg-green-900/5 border-gray-200 dark:border-gray-700 text-green-600 dark:text-green-400'
            }`}>
              {output}
            </div>
            {output !== '-' && output !== 'Invalid Input' && (
              <button 
                onClick={() => navigator.clipboard.writeText(output)}
                className="absolute right-2 top-2 p-1.5 bg-white dark:bg-gray-700 rounded-md shadow-sm opacity-0 group-hover:opacity-100 transition-opacity hover:bg-gray-50 text-xs font-bold"
              >
                COPY
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="mt-6 pt-6 border-t border-gray-100 dark:border-gray-700/50 flex flex-col items-center gap-4">
        <div className="text-[10px] text-gray-400 uppercase tracking-[0.2em]">
          Vibe coding by <a href="https://www.facebook.com/takrudcrypto21" target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:text-blue-400 font-bold transition-colors">ขิงว่านะ</a>
        </div>
        
        <a 
          href="https://github.com/Khing021/hdwalletlab" 
          target="_blank" 
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-900 hover:bg-gray-200 dark:hover:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-800 transition-all text-xs font-bold text-gray-600 dark:text-gray-300 shadow-sm"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.042-1.416-4.042-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
          </svg>
          GitHub Repository
        </a>
      </div>
    </div>
  );
}
