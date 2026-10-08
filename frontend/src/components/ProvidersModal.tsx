import React from 'react';
import { ProviderCapability } from '../types';
import { X, Layers, ExternalLink, Key, Check, Shield } from 'lucide-react';

interface ProvidersModalProps {
  isOpen: boolean;
  onClose: () => void;
  providers: ProviderCapability[];
}

export const ProvidersModal: React.FC<ProvidersModalProps> = ({
  isOpen,
  onClose,
  providers,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-theme-surface border border-theme rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col justify-between shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-theme flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Layers className="w-5 h-5 text-cyan-500" />
            <h3 className="text-base font-bold text-theme-primary tracking-wide">
              All {providers.length || 15} Threat Intelligence & Infrastructure Providers
            </h3>
          </div>
          <button onClick={onClose} className="text-theme-muted hover:text-theme-primary p-1 cursor-pointer">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {providers.map((prov) => (
              <div
                key={prov.name}
                className="bg-theme-card border border-theme rounded-xl p-4 space-y-2.5 text-xs font-mono shadow-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-theme-primary font-sans">{prov.display_name}</span>
                  <a
                    href={prov.doc_url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-cyan-500 hover:text-cyan-400 flex items-center space-x-1 text-[11px] font-sans"
                  >
                    <span>Docs</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>

                <p className="text-theme-secondary text-[11px] font-sans">{prov.description}</p>

                <div className="flex flex-wrap gap-1">
                  <span className="text-theme-muted mr-1 text-[10px]">Supported:</span>
                  {prov.supported_iocs.map((ioc) => (
                    <span
                      key={ioc}
                      className="px-1.5 py-0.2 rounded bg-theme-inset text-theme-secondary border border-theme text-[10px] uppercase font-bold"
                    >
                      {ioc}
                    </span>
                  ))}
                </div>

                <div className="pt-2 border-t border-theme flex items-center justify-between text-[10px] text-theme-muted">
                  <span>{prov.rate_limit_desc}</span>
                  {prov.requires_auth ? (
                    <span className="text-amber-500 font-semibold flex items-center space-x-0.5">
                      <Key className="w-2.5 h-2.5" />
                      <span>API Key</span>
                    </span>
                  ) : (
                    <span className="text-green-500 font-semibold">Public / Free</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-theme bg-theme-inset text-right">
          <button
            onClick={onClose}
            className="px-5 py-2 bg-theme-card hover:bg-theme-card-hover border border-theme text-theme-primary text-xs font-bold rounded-lg transition cursor-pointer"
          >
            Close Matrix
          </button>
        </div>
      </div>
    </div>
  );
};
