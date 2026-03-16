import { useState } from 'react';

export default function StepCard({ number, title, isActive, isLocked, isCompleted, children, hint }) {
  const [showHint, setShowHint] = useState(false);

  return (
    <section className={`relative transition-all duration-500 group ${
      isLocked ? 'opacity-40 grayscale pointer-events-none' : 'opacity-100'
    }`}>
      <div className={`p-8 rounded-3xl border-2 transition-all ${
        isActive 
          ? 'border-blue-500 bg-blue-50/5 shadow-2xl shadow-blue-500/10 scale-[1.02]' 
          : isCompleted
            ? 'border-green-500/30 bg-green-50/5'
            : 'border-gray-100 dark:border-gray-800 bg-white dark:bg-gray-900'
      }`}>
        <div className="flex justify-between items-start mb-6">
          <div className="flex items-center gap-4">
            <span className={`w-10 h-10 rounded-2xl flex items-center justify-center font-bold text-lg transition-colors ${
              isActive ? 'bg-blue-500 text-white' : isCompleted ? 'bg-green-500 text-white' : 'bg-gray-100 dark:bg-gray-800 text-gray-400'
            }`}>
              {isCompleted ? '✓' : number}
            </span>
            <h2 className="text-2xl font-bold tracking-tight">{title}</h2>
          </div>
          {hint && !isLocked && (
            <button 
              onClick={() => setShowHint(!showHint)}
              className="text-xs font-bold uppercase tracking-widest text-blue-500 hover:text-blue-600 transition-colors"
            >
              {showHint ? 'Hide Hint' : 'Get Hint'}
            </button>
          )}
        </div>

        {!isLocked && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-500">
            {children}
            
            {showHint && (
              <div className="p-4 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800 rounded-2xl text-amber-700 dark:text-amber-400 text-sm leading-relaxed italic">
                💡 {hint}
              </div>
            )}
          </div>
        )}
      </div>

      {isLocked && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="bg-white/80 dark:bg-gray-900/80 backdrop-blur-sm px-4 py-2 rounded-full border border-gray-200 dark:border-gray-800 shadow-sm text-xs font-bold text-gray-400 tracking-widest">
            Locked
          </div>
        </div>
      )}
    </section>
  );
}
