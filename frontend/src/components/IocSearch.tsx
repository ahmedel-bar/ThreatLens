import React, { useState, useEffect } from 'react';
import { Search, Loader2, Crosshair, AlertCircle, CheckCircle2 } from 'lucide-react';
import { IOCType } from '../types';
import { detectIoc } from '../services/api';

interface IocSearchProps {
  onSearch: (ioc: string, detectedType?: IOCType) => void;
  isLoading: boolean;
  currentStatus?: string;
  rootIoc?: string;
  rootType?: string;
}

const EXAMPLES = [
  { label: '8.8.8.8 (Google DNS)', val: '8.8.8.8', type: 'ipv4' },
  { label: '1.1.1.1 (Cloudflare)', val: '1.1.1.1', type: 'ipv4' },
  { label: 'example.com', val: 'example.com', type: 'domain' },
  { label: 'EICAR Hash', val: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', type: 'sha256' },
];

export const IocSearch: React.FC<IocSearchProps> = ({
  onSearch,
  isLoading,
  currentStatus,
  rootIoc,
}) => {
  const [inputVal, setInputVal] = useState(rootIoc || '');
  const [detectedType, setDetectedType] = useState<IOCType | undefined>();
  const [isDetecting, setIsDetecting] = useState<boolean>(false);

  useEffect(() => {
    if (rootIoc) {
      setInputVal(rootIoc);
    }
  }, [rootIoc]);

  // Real-time automatic IOC detection
  useEffect(() => {
    const trimmed = inputVal.trim();
    if (!trimmed) {
      setDetectedType(undefined);
      return;
    }

    const timer = setTimeout(async () => {
      setIsDetecting(true);
      try {
        const res = await detectIoc(trimmed);
        setDetectedType(res.detected_type);
      } catch {
        setDetectedType(undefined);
      } finally {
        setIsDetecting(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [inputVal]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputVal.trim() && !isLoading) {
      onSearch(inputVal.trim(), detectedType);
    }
  };

  const getTypeBadgeColor = (type?: string) => {
    switch (type) {
      case 'ipv4':
      case 'ipv6':
        return 'bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30';
      case 'domain':
        return 'bg-purple-500/15 text-purple-600 dark:text-purple-400 border-purple-500/30';
      case 'url':
        return 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border-cyan-500/30';
      case 'md5':
      case 'sha1':
      case 'sha256':
        return 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30';
      default:
        return 'bg-gray-500/15 text-gray-600 dark:text-gray-400 border-gray-500/30';
    }
  };

  const getStatusBadge = (status?: string) => {
    if (!status) return null;
    switch (status) {
      case 'running':
        return (
          <span className="flex items-center space-x-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-500/30 animate-pulse">
            <Loader2 className="w-3 h-3 animate-spin" />
            <span>Hunting Providers...</span>
          </span>
        );
      case 'complete':
        return (
          <span className="flex items-center space-x-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-green-500/20 text-green-600 dark:text-green-400 border border-green-500/30">
            <CheckCircle2 className="w-3 h-3" />
            <span>Complete</span>
          </span>
        );
      case 'partial':
        return (
          <span className="flex items-center space-x-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-yellow-500/20 text-yellow-600 dark:text-yellow-400 border border-yellow-500/30">
            <AlertCircle className="w-3 h-3" />
            <span>Partial Results</span>
          </span>
        );
      case 'failed':
        return (
          <span className="flex items-center space-x-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-red-500/20 text-red-600 dark:text-red-400 border border-red-500/30">
            <AlertCircle className="w-3 h-3" />
            <span>Failed</span>
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="bg-theme-card border border-theme rounded-xl p-6 shadow-md transition-colors">
      <form onSubmit={handleSubmit} className="flex flex-col md:flex-row gap-3">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-theme-muted">
            <Search className="w-5 h-5" />
          </div>
          <input
            type="text"
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            placeholder="Enter ONE IOC (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256)..."
            className="w-full pl-11 pr-32 py-3.5 bg-theme-inset border border-theme focus:border-red-500 focus:ring-1 focus:ring-red-500 rounded-lg text-sm text-theme-primary placeholder:text-theme-muted outline-none transition font-mono"
            autoFocus
          />

          {/* Auto Detected IOC Type Pill */}
          <div className="absolute inset-y-0 right-3 flex items-center space-x-2 pointer-events-none">
            {isDetecting ? (
              <Loader2 className="w-4 h-4 text-theme-muted animate-spin" />
            ) : detectedType ? (
              <span
                className={`px-2.5 py-0.5 text-xs font-mono font-bold tracking-wider uppercase rounded border ${getTypeBadgeColor(
                  detectedType
                )}`}
              >
                {detectedType}
              </span>
            ) : inputVal.trim() ? (
              <span className="px-2 py-0.5 text-[11px] font-mono text-red-500 bg-red-500/10 border border-red-500/30 rounded">
                Unrecognized
              </span>
            ) : null}
          </div>
        </div>

        <button
          type="submit"
          disabled={isLoading || !inputVal.trim()}
          className="px-8 py-3.5 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 disabled:opacity-50 text-white text-sm font-bold tracking-wider uppercase rounded-lg shadow-md shadow-red-900/20 flex items-center justify-center space-x-2 transition cursor-pointer"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>HUNTING...</span>
            </>
          ) : (
            <>
              <Crosshair className="w-4 h-4" />
              <span>HUNT</span>
            </>
          )}
        </button>
      </form>

      {/* Examples & Status Row */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center space-x-2 flex-wrap gap-y-2">
          <span className="text-theme-secondary font-medium">Quick Pivots:</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex.val}
              type="button"
              onClick={() => {
                setInputVal(ex.val);
                onSearch(ex.val, ex.type as IOCType);
              }}
              className="px-2.5 py-1 rounded bg-theme-inset hover:bg-theme-card-hover border border-theme hover:border-theme-hover text-theme-primary font-mono transition cursor-pointer"
            >
              {ex.label}
            </button>
          ))}
        </div>

        <div>{getStatusBadge(currentStatus)}</div>
      </div>
    </div>
  );
};
