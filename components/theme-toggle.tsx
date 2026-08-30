'use client';

import React from 'react';
import { useTheme } from './theme-provider';
import { Sun, Moon } from 'lucide-react';

export function ThemeToggle({ className = '' }: { className?: string }) {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      onClick={toggleTheme}
      type="button"
      aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
      className={`relative inline-flex items-center justify-center p-2 rounded-full transition-all duration-150 border cursor-pointer ${
        isDark
          ? 'bg-[#1a1a1a] border-black text-neutral-300 hover:text-white hover:bg-[#252525]'
          : 'bg-white border-neutral-300 text-neutral-700 hover:text-neutral-900 hover:bg-neutral-100 shadow-xs'
      } ${className}`}
    >
      {isDark ? (
        <Sun className="w-4 h-4 text-amber-400" />
      ) : (
        <Moon className="w-4 h-4 text-neutral-700" />
      )}
    </button>
  );
}
