import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  name?: string;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error(`ErrorBoundary caught error in [${this.props.name || 'Component'}]:`, error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="bg-theme-card border border-red-500/30 rounded-xl p-5 my-4 shadow-sm">
          <div className="flex items-start space-x-3">
            <div className="p-2 rounded-lg bg-red-500/10 text-red-500 shrink-0">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div className="space-y-2 flex-1">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-bold text-red-500 font-mono">
                  {this.props.name ? `${this.props.name} Display Warning` : 'Component Error'}
                </h4>
                <button
                  onClick={this.handleReset}
                  className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono rounded bg-theme-inset hover:bg-theme-card-hover border border-theme text-theme-primary transition cursor-pointer"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Retry</span>
                </button>
              </div>
              <p className="text-xs text-theme-muted">
                An unexpected format in provider data was handled safely. The remaining investigation intelligence remains fully operational.
              </p>
              {this.state.error && (
                <pre className="text-[11px] font-mono text-red-400/80 bg-theme-inset p-2 rounded overflow-x-auto max-h-24">
                  {this.state.error.message}
                </pre>
              )}
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
