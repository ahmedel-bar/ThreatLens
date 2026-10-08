import React from 'react';
import { Layer1Reputation as Layer1Type } from '../../types';
import { ProviderCard } from './ProviderCard';
import { ShieldAlert, Activity, CheckCircle, XCircle } from 'lucide-react';

interface Layer1Props {
  layer1: Layer1Type;
}

export const Layer1Reputation: React.FC<Layer1Props> = ({ layer1 }) => {
  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-500 bg-red-500/10 border-red-500/30';
    if (score >= 40) return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30';
    if (score >= 10) return 'text-green-500 bg-green-500/10 border-green-500/30';
    return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
  };

  // Evaluated providers (only providers supporting the IOC type that executed with success or not_found)
  const repProviders = (layer1?.provider_results || []).filter(
    (res) => !['shodan', 'censys'].includes((res.provider_name || '').toLowerCase())
  );
  const evaluatedProviders = repProviders.filter(
    (r) => r.status === 'success' || r.status === 'not_found'
  );
  const evalCount = layer1.applicable_providers_count ?? evaluatedProviders.length;
  const maliciousCount = layer1.verdict_counts?.malicious ?? evaluatedProviders.filter((r) => r.classification === 'malicious').length;
  const suspiciousCount = layer1.verdict_counts?.suspicious ?? evaluatedProviders.filter((r) => r.classification === 'suspicious').length;
  const cleanCount = layer1.verdict_counts?.clean ?? evaluatedProviders.filter((r) => ['benign', 'clean'].includes(r.classification || '') && r.status === 'success').length;
  const unknownCount = layer1.verdict_counts?.unknown ?? Math.max(0, evalCount - maliciousCount - suspiciousCount - cleanCount);
  const excludedCount = repProviders.filter((r) => r.status !== 'success' && r.status !== 'not_found').length;

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-4 border-b border-theme pb-3">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold tracking-widest text-red-500 uppercase">Layer 01</span>
            <span className="text-theme-muted">/</span>
            <h2 className="text-lg font-bold text-theme-primary tracking-wide">Threat Intelligence & Reputation</h2>
          </div>
          <p className="text-xs text-theme-secondary">
            Multi-source provider verdicts, reputation scoring, and actor attribution across evaluated intelligence feeds.
          </p>
        </div>

        {/* Global Risk & Classification Banner */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 bg-theme-surface border border-theme px-3.5 py-1.5 rounded-lg text-xs">
            <span className="text-theme-secondary">Classification:</span>
            <span className="font-bold uppercase tracking-wider text-theme-primary">
              {layer1.overall_classification}
            </span>
          </div>

          <div
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg border text-xs font-mono font-bold ${getRiskColor(
              layer1.risk_score
            )}`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Risk Score: {layer1.risk_score}/100</span>
          </div>

          {layer1.ttps && layer1.ttps.length > 0 && (
            <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono font-bold text-amber-400 bg-amber-500/10 border-amber-500/30">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
              <span>{layer1.ttps.length} MITRE TTPs</span>
            </div>
          )}
        </div>
      </div>

      {/* Global Provider-Based Reputation Stats Bar */}
      <div className="bg-theme-inset px-4 py-3 rounded-lg border border-theme font-mono space-y-2.5">
        <div className="flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center space-x-2">
            <span className="text-theme-secondary">Evaluated Providers (N):</span>
            <span className="text-theme-primary font-bold px-2 py-0.5 rounded bg-theme-surface border border-theme">
              {evalCount} of {repProviders.length} Providers
            </span>
          </div>
          {excludedCount > 0 && (
            <div className="text-[11px] text-theme-muted">
              ({excludedCount} excluded: unconfigured, unsupported, or error)
            </div>
          )}
        </div>

        <div className="flex items-center flex-wrap gap-2.5 text-xs">
          <span className="flex items-center space-x-1.5 text-red-500 font-bold bg-red-500/10 px-2.5 py-1 rounded border border-red-500/30">
            <span className="w-2 h-2 rounded-full bg-red-500"></span>
            <span>Malicious: {maliciousCount} / {evalCount} providers</span>
          </span>

          <span className="flex items-center space-x-1.5 text-yellow-500 font-bold bg-yellow-500/10 px-2.5 py-1 rounded border border-yellow-500/30">
            <span className="w-2 h-2 rounded-full bg-yellow-500"></span>
            <span>Suspicious: {suspiciousCount} / {evalCount} providers</span>
          </span>

          <span className="flex items-center space-x-1.5 text-green-500 font-bold bg-green-500/10 px-2.5 py-1 rounded border border-green-500/30">
            <span className="w-2 h-2 rounded-full bg-green-500"></span>
            <span>Clean: {cleanCount} / {evalCount} providers</span>
          </span>

          {unknownCount > 0 && (
            <span className="flex items-center space-x-1.5 text-slate-400 font-medium bg-slate-500/10 px-2.5 py-1 rounded border border-slate-500/30">
              <span className="w-2 h-2 rounded-full bg-slate-400"></span>
              <span>No Record / Unknown: {unknownCount} / {evalCount} providers</span>
            </span>
          )}
        </div>
      </div>

      {/* Provider Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {(layer1?.provider_results || [])
          .filter((res) => !['shodan'].includes((res.provider_name || '').toLowerCase()))
          .map((res) => (
            <ProviderCard key={res.provider_name} result={res} />
          ))}
      </div>
    </section>
  );
};
