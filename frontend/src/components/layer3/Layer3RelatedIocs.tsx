import React, { useState, useMemo } from 'react';
import {
  Layer3DiscoveredIOCs as Layer3Type,
  CanonicalIOC,
  IOCType,
} from '../../types';
import {
  Hash,
  Globe,
  Link2,
  GitFork,
  Search,
  Filter,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';

interface Layer3Props {
  layer3: Layer3Type;
  onPivot: (ioc: string, type: IOCType) => void;
  isPivoting?: boolean;
}

export const Layer3RelatedIocs: React.FC<Layer3Props> = ({
  layer3,
  onPivot,
  isPivoting,
}) => {
  const [activeTab, setActiveTab] = useState<'hashes' | 'ips' | 'urls_domains'>('hashes');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRel, setSelectedRel] = useState<string>('all');
  const [selectedProvider, setSelectedProvider] = useState<string>('all');

  const currentList = useMemo(() => {
    if (!layer3) return [];
    switch (activeTab) {
      case 'hashes':
        return layer3.hashes || [];
      case 'ips':
        return layer3.ips || [];
      case 'urls_domains':
        return layer3.urls_and_domains || [];
      default:
        return [];
    }
  }, [activeTab, layer3]);

  // Extract available filter options
  const relationships = useMemo(() => {
    const set = new Set<string>();
    (currentList || []).forEach((item) => {
      (item.relationships || []).forEach((r) => {
        if (typeof r === 'string') {
          r.split(',').forEach((part) => {
            const trimmed = part.trim();
            if (trimmed) set.add(trimmed);
          });
        }
      });
    });
    return Array.from(set).sort();
  }, [currentList]);

  const providers = useMemo(() => {
    const set = new Set<string>();
    (currentList || []).forEach((item) => {
      (item.providers || []).forEach((p) => set.add(p));
    });
    return Array.from(set);
  }, [currentList]);

  // Filter items
  const filteredList = useMemo(() => {
    return (currentList || []).filter((item) => {
      const matchesSearch =
        !searchQuery ||
        (item.canonical_value || '').toLowerCase().includes(searchQuery.toLowerCase());

      const itemRels = (item.relationships || []).flatMap((r) =>
        typeof r === 'string' ? r.split(',').map((part) => part.trim()).filter(Boolean) : []
      );
      const matchesRel =
        selectedRel === 'all' || itemRels.includes(selectedRel);

      const matchesProv =
        selectedProvider === 'all' || (item.providers || []).includes(selectedProvider);
      return matchesSearch && matchesRel && matchesProv;
    });
  }, [currentList, searchQuery, selectedRel, selectedProvider]);

  const getConfidenceBadge = (score: number) => {
    if (score >= 80) {
      return (
        <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-red-500/20 text-red-400 border border-red-500/30">
          {score}% Very High
        </span>
      );
    } else if (score >= 60) {
      return (
        <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
          {score}% High
        </span>
      );
    } else if (score >= 30) {
      return (
        <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
          {score}% Med
        </span>
      );
    } else {
      return (
        <span className="px-2 py-0.5 text-[11px] font-mono font-bold rounded bg-theme-inset text-theme-muted border border-theme">
          {score}% Low
        </span>
      );
    }
  };

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between border-b border-theme pb-3 flex-wrap gap-3">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold tracking-widest text-amber-500 uppercase">Layer 03</span>
            <span className="text-theme-muted">/</span>
            <h2 className="text-lg font-bold text-theme-primary tracking-wide">Related IOC Discovery</h2>
          </div>
          <p className="text-xs text-theme-secondary">
            Deduplicated pivots categorized into the three primary hunting buckets. Every IOC is pivotable.
          </p>
        </div>

        {/* 3 Primary Buckets Tabs */}
        <div className="flex rounded-lg bg-theme-inset p-1 border border-theme">
          <button
            onClick={() => setActiveTab('hashes')}
            className={`flex items-center space-x-2 px-4 py-1.5 rounded-md text-xs font-bold uppercase tracking-wider transition ${
              activeTab === 'hashes'
                ? 'bg-amber-500 text-gray-950 shadow-md font-extrabold'
                : 'text-theme-secondary hover:text-theme-primary'
            }`}
          >
            <Hash className="w-3.5 h-3.5" />
            <span>Hashes ({layer3.hashes.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('ips')}
            className={`flex items-center space-x-2 px-4 py-1.5 rounded-md text-xs font-bold uppercase tracking-wider transition ${
              activeTab === 'ips'
                ? 'bg-blue-500 text-white shadow-md font-extrabold'
                : 'text-theme-secondary hover:text-theme-primary'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>IPs ({layer3.ips.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('urls_domains')}
            className={`flex items-center space-x-2 px-4 py-1.5 rounded-md text-xs font-bold uppercase tracking-wider transition ${
              activeTab === 'urls_domains'
                ? 'bg-cyan-500 text-gray-950 shadow-md font-extrabold'
                : 'text-theme-secondary hover:text-theme-primary'
            }`}
          >
            <Link2 className="w-3.5 h-3.5" />
            <span>URLs & Domains ({layer3.urls_and_domains.length})</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-theme-card p-3 rounded-lg border border-theme">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-theme-muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search discovered IOCs..."
            className="w-full pl-9 pr-3 py-1.5 bg-theme-inset border border-theme rounded text-xs text-theme-primary placeholder-theme-muted focus:outline-none focus:border-amber-500 font-mono"
          />
        </div>

        <div className="flex items-center space-x-3 text-xs">
          {/* Relationship Filter */}
          <div className="flex items-center space-x-1.5">
            <span className="text-theme-secondary">Relationship:</span>
            <select
              value={selectedRel}
              onChange={(e) => setSelectedRel(e.target.value)}
              className="bg-theme-inset border border-theme rounded px-2 py-1 text-theme-primary text-xs focus:outline-none"
            >
              <option value="all">All</option>
              {relationships.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>

          {/* Provider Filter */}
          <div className="flex items-center space-x-1.5">
            <span className="text-theme-secondary">Provider:</span>
            <select
              value={selectedProvider}
              onChange={(e) => setSelectedProvider(e.target.value)}
              className="bg-theme-inset border border-theme rounded px-2 py-1 text-theme-primary text-xs focus:outline-none"
            >
              <option value="all">All</option>
              {providers.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-theme-card border border-theme rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-theme-table-header text-theme-secondary uppercase font-mono tracking-wider text-[11px] border-b border-theme">
              <tr>
                <th className="py-3 px-4">Canonical IOC</th>
                <th className="py-3 px-3">Type</th>
                <th className="py-3 px-3">Relationship</th>
                <th className="py-3 px-3">Contributing Providers</th>
                <th className="py-3 px-3">Confidence</th>
                <th className="py-3 px-3">Depth</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-theme font-mono">
              {filteredList.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-theme-muted italic">
                    No IOCs discovered in this bucket matching current filters.
                  </td>
                </tr>
              ) : (
                filteredList.map((item) => (
                  <tr key={item.id} className="hover:bg-theme-card-hover transition">
                    <td className="py-3 px-4 font-semibold text-theme-primary max-w-[320px]">
                      <div className="truncate" title={item.canonical_value}>
                        {item.canonical_value}
                      </div>
                      {item.metadata?.filename && (
                        <div
                          className="text-[10px] text-theme-muted font-normal font-sans truncate flex items-center space-x-1 mt-0.5"
                          title={item.metadata.filename}
                        >
                          <span className="text-amber-500/80 font-mono">file:</span>
                          <span className="truncate">{item.metadata.filename}</span>
                          {item.metadata?.detections && (
                            <span className="text-red-400 font-mono shrink-0">
                              ({item.metadata.detections})
                            </span>
                          )}
                        </div>
                      )}
                      {item.metadata?.vt_reported_count && (
                        <div
                          className="text-[10px] text-cyan-400 font-mono mt-0.5 flex items-center space-x-1"
                          title={`VirusTotal reported ${item.metadata.vt_reported_count} related objects in this collection`}
                        >
                          <span className="text-theme-muted">VT collection:</span>
                          <span className="font-bold">{item.metadata.vt_reported_count} reported</span>
                          {item.metadata.vt_materialized_count && item.metadata.vt_materialized_count < item.metadata.vt_reported_count && (
                            <span className="text-amber-400">({item.metadata.vt_materialized_count} materialized)</span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 text-theme-secondary uppercase">{item.ioc_type}</td>
                    <td className="py-3 px-3">
                      <div className="flex flex-wrap gap-1">
                        {(() => {
                          const rawList = item.relationships && item.relationships.length > 0 ? item.relationships : ['related_to'];
                          const relList = rawList.flatMap((r) =>
                            typeof r === 'string' ? r.split(',').map((part) => part.trim()).filter(Boolean) : []
                          );
                          const finalRels = relList.length > 0 ? Array.from(new Set(relList)) : ['related_to'];
                          return finalRels.map((r) => (
                            <span
                              key={r}
                              className="px-1.5 py-0.5 rounded bg-theme-inset text-theme-secondary border border-theme text-[10px]"
                            >
                              {r}
                            </span>
                          ));
                        })()}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex flex-wrap gap-1">
                        {(item.providers || []).map((p) => (
                          <span
                            key={p}
                            className="px-1.5 py-0.5 rounded bg-theme-inset text-theme-secondary border border-theme text-[10px]"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-3">{getConfidenceBadge(item.confidence)}</td>
                    <td className="py-3 px-3 text-theme-muted">d={item.depth}</td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onPivot(item.canonical_value, item.ioc_type)}
                        disabled={isPivoting}
                        className="inline-flex items-center space-x-1.5 px-3 py-1 rounded bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 hover:border-red-500/50 text-xs font-bold transition disabled:opacity-50 cursor-pointer"
                        title="Pivot and expand investigation from this IOC"
                      >
                        <GitFork className="w-3 h-3" />
                        <span>PIVOT</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
};
