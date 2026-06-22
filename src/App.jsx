import { useState, useMemo } from 'react';
import { cryptoUtils } from './utils/crypto';
import Toolbox from './components/Toolbox';
import KeyDerivationJourney from './components/KeyDerivationJourney';
import TransactionJourney from './components/TransactionJourney';

function App() {
  const [journey, setJourney] = useState('derivation');
  const [isDark, setIsDark] = useState(true);

  const toggleTheme = () => setIsDark(!isDark);

  const themeVars = journey === 'derivation'
    ? {
      '--primary-color': '#3b82f6', // blue-500
      '--primary-bg': 'rgba(239, 246, 255, 0.05)',
      '--primary-glow': 'rgba(59, 130, 246, 0.1)',
      '--bg-color': '#0a0a0c',
      '--header-gradient': 'from-blue-400 via-indigo-500 to-purple-600'
    }
    : {
      '--primary-color': '#a855f7', // purple-500
      '--primary-bg': 'rgba(250, 245, 255, 0.05)',
      '--primary-glow': 'rgba(168, 85, 247, 0.1)',
      '--bg-color': '#0f0a1a', // Dark Purple
      '--header-gradient': 'from-purple-400 via-fuchsia-500 to-pink-600'
    };

  return (
    <div className={`min-h-screen ${isDark ? 'dark' : ''} transition-all duration-700`} style={themeVars}>
      <div className="bg-white dark:bg-[var(--bg-color)] text-black dark:text-gray-100 flex flex-col md:flex-row h-screen font-sans transition-colors duration-700">

        {/* Journey Pane (70%) */}
        <div className="flex-1 md:basis-[70%] p-8 border-r border-gray-200 dark:border-gray-800 overflow-y-auto no-scrollbar">
          <header className="mb-12 flex flex-col sm:flex-row justify-between items-start sm:items-center bg-white/50 dark:bg-transparent backdrop-blur-md sticky top-0 py-4 z-10 gap-6">
            <div>
              <h1 className={`text-4xl font-extrabold tracking-tighter mb-1 bg-gradient-to-br ${themeVars['--header-gradient']} bg-clip-text text-transparent uppercase`}>
                HD Wallet Lab
              </h1>
              <p className="text-[10px] uppercase tracking-[0.4em] font-bold text-gray-400 dark:text-gray-600">
                Interactive Cryptography Journey
              </p>
            </div>

            {/* ซ่อนปุ่มสลับหน้าโดยการเติม/ลบคำว่า hidden ใน classname */}
            <nav className="hidden flex bg-gray-100 dark:bg-gray-900/50 p-1 rounded-2xl border border-gray-200 dark:border-gray-800 shadow-inner">
              <button
                onClick={() => setJourney('derivation')}
                className={`px-6 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${journey === 'derivation'
                  ? 'bg-white dark:bg-gray-800 text-blue-500 shadow-sm'
                  : 'text-gray-400 hover:text-gray-600 dark:hover:text-gray-200'
                  }`}
              >
                Key Derivation
              </button>
              <button
                onClick={() => setJourney('transaction')}
                className={`px-6 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${journey === 'transaction'
                  ? 'bg-white dark:bg-gray-800 text-purple-500 shadow-sm'
                  : 'text-gray-400 hover:text-gray-600 dark:hover:text-gray-200'
                  }`}
              >
                Transaction Making
              </button>
            </nav>

            <button
              onClick={toggleTheme}
              className="p-3 bg-gray-100 dark:bg-gray-900 rounded-2xl hover:bg-gray-200 dark:hover:bg-gray-800 transition-all border border-gray-200 dark:border-gray-800 shadow-sm"
            >
              {isDark ? '☀️' : '🌙'}
            </button>
          </header>

          <main className="animate-in fade-in duration-1000">
            {journey === 'derivation' ? <KeyDerivationJourney /> : <TransactionJourney />}
          </main>
        </div>

        {/* Toolbox Pane (30%) */}
        <aside className="md:basis-[30%] bg-gray-50/50 dark:bg-black/20 p-8 overflow-y-auto no-scrollbar">
          <Toolbox />
        </aside>
      </div>
    </div>
  );
}

export default App;
