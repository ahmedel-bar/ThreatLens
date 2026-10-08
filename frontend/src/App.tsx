import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { IocSearch } from './components/IocSearch';
import { Layer1Reputation } from './components/layer1/Layer1Reputation';
import { Layer2Infrastructure } from './components/layer2/Layer2Infrastructure';
import { Layer3RelatedIocs } from './components/layer3/Layer3RelatedIocs';
import { InvestigationGraph } from './components/graph/InvestigationGraph';
import { InvestigationHistory } from './components/history/InvestigationHistory';
import { ProvidersModal } from './components/ProvidersModal';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import {
  InvestigationDetail,
  InvestigationSummary,
  ProviderCapability,
  IOCType,
} from './types';
import {
  startInvestigation,
  getInvestigation,
  listInvestigations,
  pivotInvestigation,
  getProviders,
} from './services/api';
import { AlertTriangle, Loader2, Shield } from 'lucide-react';

export const App: React.FC = () => {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('threatlens_theme');
    if (saved === 'light' || saved === 'dark') return saved;
    return 'dark';
  });
  const [investigation, setInvestigation] = useState<InvestigationDetail | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isPivoting, setIsPivoting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Modals state
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isProvidersOpen, setIsProvidersOpen] = useState(false);
  const [historyList, setHistoryList] = useState<InvestigationSummary[]>([]);
  const [providersList, setProvidersList] = useState<ProviderCapability[]>([]);

  // Sync theme with DOM and localStorage
  useEffect(() => {
    if (theme === 'light') {
      document.documentElement.classList.add('light');
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
      document.documentElement.classList.remove('light');
    }
    localStorage.setItem('threatlens_theme', theme);
  }, [theme]);

  // Toggle Theme
  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Initial load
  useEffect(() => {
    async function init() {
      try {
        const provs = await getProviders();
        setProvidersList(provs);
      } catch (err) {
        console.error('Failed to load providers', err);
      }

      try {
        const history = await listInvestigations();
        setHistoryList(history);
      } catch (err) {
        console.error('Failed to load history', err);
      }
    }
    init();
  }, []);

  const handleSearch = async (ioc: string, detectedType?: IOCType) => {
    setIsLoading(true);
    setError(null);
    setInvestigation(null);
    try {
      const res = await startInvestigation(ioc, detectedType);
      setInvestigation(res);
      // Refresh history
      const history = await listInvestigations();
      setHistoryList(history);
    } catch (err: any) {
      setError(err.message || 'Investigation failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePivot = async (targetIoc: string, targetType?: IOCType) => {
    if (!targetIoc || !targetIoc.trim()) return;
    const cleanIoc = targetIoc.trim();
    if (investigation && investigation.root_ioc_value.toLowerCase() === cleanIoc.toLowerCase()) {
      return;
    }
    setIsPivoting(true);
    setError(null);
    try {
      await handleSearch(cleanIoc, targetType);
    } catch (err: any) {
      setError(err.message || 'Pivot failed');
    } finally {
      setIsPivoting(false);
    }
  };

  const handleSelectPastInvestigation = async (id: string) => {
    setIsLoading(true);
    setError(null);
    setInvestigation(null);
    try {
      const inv = await getInvestigation(id);
      setInvestigation(inv);
    } catch (err: any) {
      setError(err.message || 'Failed to load past investigation');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-theme-page text-theme-primary flex flex-col font-sans selection:bg-red-500/30">
      {/* Navbar */}
      <Navbar
        theme={theme}
        toggleTheme={toggleTheme}
        openHistory={() => {
          listInvestigations().then(setHistoryList).catch(console.error);
          setIsHistoryOpen(true);
        }}
        openProviders={() => setIsProvidersOpen(true)}
        providersCount={providersList.length > 0 ? providersList.length : 15}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 md:px-6 py-6 space-y-8">
        {/* Search Header */}
        <IocSearch
          onSearch={handleSearch}
          isLoading={isLoading}
          currentStatus={investigation?.status}
          rootIoc={investigation?.root_ioc_value}
          rootType={investigation?.root_ioc_type}
        />

        {/* Error Banner */}
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-xl text-red-500 text-xs flex items-center space-x-2 font-mono">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-500" />
            <span>{error}</span>
          </div>
        )}

        {/* Pivoting Overlay notification */}
        {isPivoting && (
          <div className="bg-blue-500/10 border border-blue-500/30 p-3 rounded-xl text-blue-500 text-xs flex items-center justify-between font-mono animate-pulse">
            <div className="flex items-center space-x-2">
              <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
              <span>Expanding recursive pivot and updating threat relationship topology...</span>
            </div>
            <span className="text-[10px] text-blue-500 font-bold uppercase">Depth +1</span>
          </div>
        )}

        {/* Investigation Layers */}
        {investigation ? (
          <div className="space-y-10">
            {/* Layer 1: Reputation & Intelligence */}
            <ErrorBoundary name="Layer 1: Reputation & Intelligence">
              <Layer1Reputation layer1={investigation.layer1} />
            </ErrorBoundary>

            {/* Layer 2: Infrastructure Hunting */}
            <ErrorBoundary name="Layer 2: Infrastructure & Host Intelligence">
              <Layer2Infrastructure layer2={investigation.layer2} />
            </ErrorBoundary>

            {/* Layer 3: Related IOC Discovery (Tri-bucket) */}
            <ErrorBoundary name="Layer 3: Related IOC Discovery">
              <Layer3RelatedIocs
                layer3={investigation.layer3}
                onPivot={handlePivot}
                isPivoting={isPivoting}
              />
            </ErrorBoundary>

            {/* Interactive Threat Graph */}
            <ErrorBoundary name="Threat Relationship Graph">
              <InvestigationGraph
                key={investigation.id}
                graphData={investigation.graph}
                onPivot={handlePivot}
                isPivoting={isPivoting}
                theme={theme}
              />
            </ErrorBoundary>
          </div>
        ) : isLoading ? (
          <div className="py-24 flex flex-col items-center justify-center space-y-3 text-theme-muted">
            <Loader2 className="w-8 h-8 animate-spin text-red-500" />
            <span className="text-xs font-mono">Conducting multi-provider infrastructure reconnaissance...</span>
          </div>
        ) : (
          <div className="py-20 flex flex-col items-center justify-center text-center max-w-xl mx-auto space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-theme-surface border border-theme flex items-center justify-center text-theme-muted">
              <Shield className="w-8 h-8 text-red-500/80" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-theme-text font-mono">Ready for Investigation</h2>
              <p className="text-xs text-theme-muted mt-1">
                Enter any valid IPv4, IPv6, Domain, URL, MD5, SHA1, or SHA256 indicator above and click <span className="text-red-500 font-mono font-semibold">HUNT</span> to launch automated intelligence gathering, infrastructure discovery, and relationship graphing.
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
              <span className="px-2.5 py-1 rounded bg-theme-surface border border-theme text-[11px] font-mono text-theme-muted">IPv4 / IPv6</span>
              <span className="px-2.5 py-1 rounded bg-theme-surface border border-theme text-[11px] font-mono text-theme-muted">Domains & FQDNs</span>
              <span className="px-2.5 py-1 rounded bg-theme-surface border border-theme text-[11px] font-mono text-theme-muted">URLs</span>
              <span className="px-2.5 py-1 rounded bg-theme-surface border border-theme text-[11px] font-mono text-theme-muted">File Hashes</span>
            </div>
          </div>
        )}
      </main>

      {/* Modals */}
      <InvestigationHistory
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        investigations={historyList}
        onSelect={handleSelectPastInvestigation}
      />

      <ProvidersModal
        isOpen={isProvidersOpen}
        onClose={() => setIsProvidersOpen(false)}
        providers={providersList}
      />

      {/* Footer */}
      <footer className="border-t border-theme bg-theme-surface py-4 px-6 text-center text-xs text-theme-muted font-mono">
        ThreatLens Threat Intelligence &amp; Infrastructure Hunting Platform • {providersList.length || 15} Active Adapters • Automated Normalization &amp; Deduplication
      </footer>
    </div>
  );
};

export default App;
