import React from 'react';
import { Shield, History, Layers, Sun, Moon } from 'lucide-react';

interface NavbarProps {
  theme: 'dark' | 'light';
  toggleTheme: () => void;
  openHistory: () => void;
  openProviders: () => void;
  providersCount?: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  theme,
  toggleTheme,
  openHistory,
  openProviders,
  providersCount = 15,
}) => {
  return (
    <header className="border-b border-theme bg-theme-surface/90 backdrop-blur sticky top-0 z-40 px-6 py-3.5 flex items-center justify-between transition-colors shadow-xs">
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center justify-center">
          <Shield className="w-6 h-6 text-red-500" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-black tracking-wider text-theme-primary">THREATLENS</h1>
            <span className="px-2 py-0.5 text-[10px] font-mono tracking-widest uppercase rounded bg-red-500/20 text-red-500 border border-red-500/30">
              v1.0 SOC
            </span>
          </div>
          <p className="text-xs text-theme-secondary font-medium">
            Threat Intelligence & Infrastructure Hunting Platform
          </p>
        </div>
      </div>

      <div className="flex items-center space-x-3">
        <button
          onClick={openProviders}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium text-theme-secondary hover:text-theme-primary bg-theme-card border border-theme hover:border-theme-hover transition shadow-2xs cursor-pointer"
        >
          <Layers className="w-4 h-4 text-cyan-500" />
          <span>{providersCount} Providers</span>
        </button>

        <button
          onClick={openHistory}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium text-theme-secondary hover:text-theme-primary bg-theme-card border border-theme hover:border-theme-hover transition shadow-2xs cursor-pointer"
        >
          <History className="w-4 h-4 text-amber-500" />
          <span>History</span>
        </button>

        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg text-theme-secondary hover:text-theme-primary bg-theme-card border border-theme hover:border-theme-hover transition shadow-2xs cursor-pointer"
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`}
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? (
            <Sun className="w-4.5 h-4.5 text-yellow-400 hover:text-yellow-300 transition" />
          ) : (
            <Moon className="w-4.5 h-4.5 text-blue-600 hover:text-blue-500 transition" />
          )}
        </button>
      </div>
    </header>
  );
};
