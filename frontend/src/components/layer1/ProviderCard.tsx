import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Clock,
  ChevronDown,
  ChevronUp,
  Skull,
  FileCode,
} from 'lucide-react';
import { ProviderResult, ProviderStatus } from '../../types';

interface ProviderCardProps {
  result: ProviderResult;
}

export const ProviderCard: React.FC<ProviderCardProps> = ({ result }) => {
  const [expanded, setExpanded] = useState(false);

  const isVT = result.provider_name.toLowerCase() === 'virustotal';
  const isCensys = result.provider_name.toLowerCase() === 'censys';
  const rawData = result.raw_data as any;
  const vtStats: Record<string, number> | undefined = result.vt_engine_counts
    || rawData?.data?.attributes?.last_analysis_stats
    || rawData?.attributes?.last_analysis_stats
    || rawData?.last_analysis_stats;

  const vtMalicious = vtStats?.malicious ?? result.malicious_count ?? 0;
  const vtSuspicious = vtStats?.suspicious ?? result.suspicious_count ?? 0;
  const vtUndetected = vtStats?.undetected ?? 0;
  const vtHarmless = vtStats?.harmless ?? (vtStats?.clean ?? result.harmless_count ?? 0);
  const vtTimeout = (vtStats?.timeout ?? 0) + (vtStats?.['confirmed-timeout'] ?? 0) + (vtStats?.confirmed_timeout ?? 0);
  const vtTypeUnsupported = (vtStats?.['type-unsupported'] ?? 0) + (vtStats?.type_unsupported ?? 0);
  const vtFailure = vtStats?.failure ?? 0;

  const calculatedSum = vtMalicious + vtSuspicious + vtUndetected + vtHarmless + vtTimeout + vtTypeUnsupported + vtFailure;
  const vtTotal = (vtStats?.total && vtStats.total >= calculatedSum) ? vtStats.total : calculatedSum;
  const hasVTDetection = vtTotal > 0 || vtMalicious > 0 || vtSuspicious > 0 || vtHarmless > 0 || vtUndetected > 0;

  const getStatusBadge = (status: ProviderStatus) => {
    switch (status) {
      case 'success':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-green-500/20 text-green-600 dark:text-green-400 border border-green-500/30">SUCCESS</span>;
      case 'not_found':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-500/20 text-slate-400 border border-slate-500/30">NO MATCH</span>;
      case 'unsupported':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-gray-500/20 text-gray-600 dark:text-gray-400 border border-gray-500/30">UNSUPPORTED</span>;
      case 'not_configured':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/30">NO API KEY</span>;
      case 'unauthorized':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-500/20 text-amber-500 border border-amber-500/30">AUTH FAILED</span>;
      case 'forbidden':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-500/20 text-amber-500 border border-amber-500/30">FORBIDDEN</span>;
      case 'plan_restricted':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">PLAN RESTRICTED</span>;
      case 'rate_limited':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-orange-500/20 text-orange-600 dark:text-orange-400 border border-orange-500/30">RATE LIMITED</span>;
      case 'timeout':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-red-500/20 text-red-600 dark:text-red-400 border border-red-500/30">TIMEOUT</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/30 uppercase">{status}</span>;
    }
  };

  const getVerdictBadge = (classification?: string) => {
    switch (classification) {
      case 'malicious':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 text-xs font-bold rounded bg-red-500/20 text-red-600 dark:text-red-400 border border-red-500/30">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>MALICIOUS</span>
          </span>
        );
      case 'suspicious':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 text-xs font-bold rounded bg-yellow-500/20 text-yellow-600 dark:text-yellow-400 border border-yellow-500/30">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>SUSPICIOUS</span>
          </span>
        );
      case 'benign':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 text-xs font-bold rounded bg-green-500/20 text-green-600 dark:text-green-400 border border-green-500/30">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>BENIGN</span>
          </span>
        );
      default:
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 text-xs font-bold rounded bg-gray-500/20 text-gray-600 dark:text-gray-400 border border-gray-500/30">
            <ShieldQuestion className="w-3.5 h-3.5" />
            <span>UNKNOWN</span>
          </span>
        );
    }
  };

  return (
    <div className="bg-theme-card border border-theme hover:border-theme-hover rounded-xl p-4 flex flex-col justify-between transition shadow-xs">
      <div>
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-theme">
          <div className="flex items-center space-x-2">
            <span className="font-bold text-sm text-theme-primary capitalize">{result.provider_name}</span>
            {result.execution_time_ms > 0 && (
              <span className="text-[10px] text-theme-muted flex items-center space-x-0.5 font-mono">
                <Clock className="w-2.5 h-2.5" />
                <span>{result.execution_time_ms}ms</span>
              </span>
            )}
          </div>
          <div>{getStatusBadge(result.status)}</div>
        </div>

        {/* Content Body */}
        {result.status === 'success' ? (
          <div className="py-3 space-y-3">
            {isCensys ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="flex items-center space-x-1.5 px-2.5 py-1 text-xs font-bold rounded bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30">
                    <span>INFRASTRUCTURE</span>
                  </span>
                </div>
                <div className="bg-theme-inset p-3 rounded-lg border border-theme text-xs font-mono space-y-1.5">
                  <p className="text-theme-secondary">
                    Infrastructure &amp; Host Intelligence data available in <span className="text-cyan-400 font-bold">Layer 2</span>.
                  </p>
                  {result.tags && result.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 pt-1">
                      {result.tags.slice(0, 4).map((t, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-0.5 text-[10px] font-mono rounded bg-theme-surface text-theme-secondary border border-theme"
                        >
                          #{t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : isVT ? (
              <div className="space-y-3">
                {/* Top: Verdict Badge */}
                <div className="flex items-center justify-between">
                  <div>{getVerdictBadge(result.classification)}</div>
                </div>

                {/* 1. Dedicated VirusTotal Detection Section */}
                {hasVTDetection && (
                  <div className="bg-theme-inset p-3 rounded-lg border border-theme text-xs font-mono space-y-2">
                    <div className="flex items-center justify-between text-[11px] font-bold text-theme-secondary uppercase border-b border-theme pb-1.5">
                      <span className="flex items-center space-x-1.5 text-theme-primary">
                        <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                        <span>VirusTotal Detection</span>
                      </span>
                      {vtTotal > 0 && (
                        <span className="text-theme-muted font-normal text-[10px]">
                          {vtTotal} Engines Evaluated
                        </span>
                      )}
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div className="flex items-center justify-between bg-theme-surface px-2.5 py-1 rounded border border-red-500/20">
                        <span className="text-red-500 font-semibold">Malicious:</span>
                        <span className="font-bold text-red-400">
                          {vtTotal > 0 ? `${vtMalicious} / ${vtTotal}` : vtMalicious}
                        </span>
                      </div>
                      <div className="flex items-center justify-between bg-theme-surface px-2.5 py-1 rounded border border-yellow-500/20">
                        <span className="text-yellow-500 font-semibold">Suspicious:</span>
                        <span className="font-bold text-yellow-400">
                          {vtTotal > 0 ? `${vtSuspicious} / ${vtTotal}` : vtSuspicious}
                        </span>
                      </div>
                      {(vtUndetected > 0 || (vtStats && 'undetected' in vtStats) || isVT) && (
                        <div className="flex items-center justify-between bg-theme-surface px-2.5 py-1 rounded border border-theme">
                          <span className="text-theme-muted font-semibold">Undetected:</span>
                          <span className="font-bold text-theme-secondary">
                            {vtTotal > 0 ? `${vtUndetected} / ${vtTotal}` : vtUndetected}
                          </span>
                        </div>
                      )}
                      {vtHarmless > 0 && (
                        <div className="flex items-center justify-between bg-theme-surface px-2.5 py-1 rounded border border-green-500/20">
                          <span className="text-green-500 font-semibold">Harmless:</span>
                          <span className="font-bold text-green-400">
                            {vtTotal > 0 ? `${vtHarmless} / ${vtTotal}` : vtHarmless}
                          </span>
                        </div>
                      )}
                      {vtTimeout > 0 && (
                        <div className="flex items-center justify-between bg-theme-surface px-2.5 py-1 rounded border border-theme">
                          <span className="text-theme-muted font-semibold">Timeout:</span>
                          <span className="font-bold text-theme-secondary">
                            {vtTotal > 0 ? `${vtTimeout} / ${vtTotal}` : vtTimeout}
                          </span>
                        </div>
                      )}
                      {vtTypeUnsupported > 0 && (
                        <div className="flex items-center justify-between bg-theme-surface px-2.5 py-1 rounded border border-theme">
                          <span className="text-theme-muted font-semibold">Type Unsupported:</span>
                          <span className="font-bold text-theme-secondary">
                            {vtTotal > 0 ? `${vtTypeUnsupported} / ${vtTotal}` : vtTypeUnsupported}
                          </span>
                        </div>
                      )}
                      {vtFailure > 0 && (
                        <div className="flex items-center justify-between bg-theme-surface px-2.5 py-1 rounded border border-theme">
                          <span className="text-theme-muted font-semibold">Failure:</span>
                          <span className="font-bold text-theme-secondary">
                            {vtTotal > 0 ? `${vtFailure} / ${vtTotal}` : vtFailure}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* 2. Dedicated VirusTotal Reputation Section */}
                {result.reputation_score !== undefined && (
                  <div className="bg-theme-inset p-2.5 rounded-lg border border-theme text-xs font-mono flex items-center justify-between">
                    <div>
                      <div className="text-[11px] font-bold text-theme-secondary uppercase">VirusTotal Reputation</div>
                      <div className="text-[10px] text-theme-muted">Community score (-100 to +100)</div>
                    </div>
                    <div className="text-right">
                      <span className={`text-sm font-bold px-2 py-0.5 rounded border ${
                        result.reputation_score < 0
                          ? 'bg-red-500/10 text-red-400 border-red-500/30'
                          : result.reputation_score > 0
                          ? 'bg-green-500/10 text-green-400 border-green-500/30'
                          : 'bg-gray-500/10 text-gray-400 border-gray-500/30'
                      }`}>
                        {result.reputation_score} / 100
                      </span>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <div>{getVerdictBadge(result.classification)}</div>
                  {result.reputation_score !== undefined && (
                    <div className="text-right">
                      <div className="text-[10px] text-theme-muted font-medium">Reputation</div>
                      <div className="text-sm font-mono font-bold text-theme-primary">{result.reputation_score}/100</div>
                    </div>
                  )}
                </div>

                {(result.malicious_count > 0 || result.suspicious_count > 0 || result.harmless_count > 0) ? (
                  <div className="flex items-center space-x-2 text-xs font-mono">
                    {result.malicious_count > 0 && (
                      <span className="text-red-600 dark:text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/30 font-semibold">
                        +{result.malicious_count} Malicious
                      </span>
                    )}
                    {result.suspicious_count > 0 && (
                      <span className="text-yellow-600 dark:text-yellow-400 bg-yellow-500/10 px-2 py-0.5 rounded border border-yellow-500/30 font-semibold">
                        +{result.suspicious_count} Suspicious
                      </span>
                    )}
                    {result.harmless_count > 0 && (
                      <span className="text-green-600 dark:text-green-400 bg-green-500/10 px-2 py-0.5 rounded border border-green-500/30 font-semibold">
                        +{result.harmless_count} Clean
                      </span>
                    )}
                  </div>
                ) : null}
              </>
            )}

            {/* Threat Actors */}
            {result.threat_actors && result.threat_actors.length > 0 && (
              <div className="flex items-center space-x-1.5 text-xs text-red-600 dark:text-red-400">
                <Skull className="w-3.5 h-3.5 shrink-0" />
                <span className="font-semibold">{result.threat_actors.slice(0, 2).join(', ')}</span>
              </div>
            )}

            {/* Malware Families */}
            {result.malware_families && result.malware_families.length > 0 && (
              <div className="flex items-center space-x-1.5 text-xs text-rose-600 dark:text-rose-400">
                <FileCode className="w-3.5 h-3.5 shrink-0" />
                <span className="font-semibold">{result.malware_families.slice(0, 3).join(', ')}</span>
              </div>
            )}

            {/* Tags */}
            {result.tags && result.tags.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {result.tags.slice(0, 4).map((t, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 text-[10px] font-mono rounded bg-theme-inset text-theme-secondary border border-theme"
                  >
                    #{t}
                  </span>
                ))}
              </div>
            )}
          </div>
        ) : result.status === 'not_found' ? (
          <div className="py-4 text-xs text-theme-muted font-mono flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-slate-400 shrink-0"></span>
            <span>{isCensys ? 'No host records found in Censys database.' : `No matching record in ${result.provider_name} database.`}</span>
          </div>
        ) : result.status === 'unauthorized' || result.status === 'forbidden' || result.status === 'plan_restricted' ? (
          <div className="py-4 text-xs text-amber-500/90 font-mono">
            {result.error_details || 'Access restricted. Please verify API key / plan permissions.'}
          </div>
        ) : result.status === 'rate_limited' ? (
          <div className="py-4 text-xs text-orange-400 font-mono">
            {result.error_details || 'Provider rate limit reached. Backoff applied.'}
          </div>
        ) : (
          <div className="py-4 text-xs text-theme-muted italic">
            {result.error_details || 'Provider reported no detections for this IOC type.'}
          </div>
        )}
      </div>

      {/* Footer Details Toggle */}
      {result.evidences && result.evidences.length > 0 && (
        <div className="pt-2 border-t border-theme mt-2">
          <button
            onClick={() => setExpanded(!expanded)}
            className="w-full flex items-center justify-between text-xs text-theme-secondary hover:text-theme-primary transition py-1 cursor-pointer"
          >
            <span>{expanded ? 'Hide Evidence' : 'View Evidence'}</span>
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {expanded && (
            <div className="mt-2 space-y-2 text-xs bg-theme-inset p-3 rounded-lg border border-theme font-mono">
              {result.evidences.map((ev, i) => (
                <div key={i} className="space-y-0.5">
                  <div className="text-theme-muted font-semibold uppercase text-[10px]">{ev.evidence_type}</div>
                  <div className="text-theme-primary">{ev.description}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
