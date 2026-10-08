import React from 'react';
import { InvestigationSummary } from '../../types';
import { formatTimestamp } from '../../utils/date';
import { X, Clock, ChevronRight, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface HistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  investigations: InvestigationSummary[];
  onSelect: (id: string) => void;
}

export const InvestigationHistory: React.FC<HistoryModalProps> = ({
  isOpen,
  onClose,
  investigations,
  onSelect,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex justify-end">
      <div className="w-full max-w-md bg-theme-surface border-l border-theme h-full p-6 flex flex-col justify-between shadow-2xl animate-in slide-in-from-right duration-200">
        <div>
          <div className="flex items-center justify-between pb-4 border-b border-theme">
            <div className="flex items-center space-x-2">
              <Clock className="w-5 h-5 text-amber-500" />
              <h3 className="text-base font-bold text-theme-primary tracking-wide">Investigation History</h3>
            </div>
            <button onClick={onClose} className="text-theme-muted hover:text-theme-primary p-1 cursor-pointer">
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="mt-4 space-y-2.5 max-h-[calc(100vh-140px)] overflow-y-auto pr-1">
            {investigations.length === 0 ? (
              <div className="py-12 text-center text-xs text-theme-muted italic">
                No past investigations found. Start hunting an IOC to generate history.
              </div>
            ) : (
              investigations.map((inv) => (
                <div
                  key={inv.id}
                  onClick={() => {
                    onSelect(inv.id);
                    onClose();
                  }}
                  className="bg-theme-card hover:bg-theme-card-hover border border-theme hover:border-theme-hover p-3.5 rounded-xl cursor-pointer transition flex items-center justify-between group shadow-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-theme-primary font-mono font-bold text-xs truncate max-w-[200px]">
                        {inv.root_ioc_value}
                      </span>
                      <span className="px-1.5 py-0.2 text-[9px] font-mono uppercase bg-theme-inset text-theme-secondary border border-theme rounded">
                        {inv.root_ioc_type}
                      </span>
                    </div>

                    <div className="flex items-center space-x-3 text-[10px] text-theme-muted font-mono">
                      <span>{formatTimestamp(inv.created_at)}</span>
                      <span>•</span>
                      <span>{inv.discovered_iocs_count} Pivots</span>
                      <span>•</span>
                      <span className="text-red-500 font-bold">Risk: {inv.risk_score}</span>
                    </div>
                  </div>

                  <ChevronRight className="w-4 h-4 text-theme-muted group-hover:text-theme-primary transition group-hover:translate-x-0.5" />
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
