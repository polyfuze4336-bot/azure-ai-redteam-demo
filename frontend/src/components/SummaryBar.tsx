/**
 * SummaryBar Component
 * 
 * Displays telemetry summary metrics at the top of the main page.
 * 
 * DESIGN:
 * - Uses the centralized telemetry store as single source of truth
 * - Never computes metrics independently
 * - Maintains stable values during loading (shows previous values)
 * - Auto-refreshes every 30 seconds
 */

import { ShieldCheck, ShieldAlert, AlertTriangle, Clock, Zap, Target, Bug } from 'lucide-react';
import { useTelemetrySummary } from '../stores';

export default function SummaryBar() {
  const { summary, isLoading, debugInfo } = useTelemetrySummary({
    refreshIntervalMs: 30000,
    autoRefresh: true,
  });

  // Format latency for display
  const formatLatency = (ms: number): string => {
    if (ms >= 1000) {
      return `${(ms / 1000).toFixed(1)}s`;
    }
    return `${Math.round(ms)}ms`;
  };

  return (
    <div className="border-b border-slate-800 bg-slate-900/30">
      <div className="max-w-[1800px] mx-auto px-6 py-3">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-6">
            {/* Session Context */}
            <div className="flex items-center gap-2 pr-6 border-r border-slate-700">
              <div className="w-8 h-8 rounded-lg bg-azure-500/10 flex items-center justify-center">
                <Target className="w-4 h-4 text-azure-400" />
              </div>
              <div>
                <p className="text-xs text-slate-500">Target</p>
                <p className="text-sm font-medium text-white">gpt-4o</p>
              </div>
            </div>

            {/* Total Attacks */}
            <div className="flex items-center gap-2">
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                isLoading ? 'bg-slate-800 animate-pulse' : 'bg-slate-800'
              }`}>
                <Zap className="w-4 h-4 text-azure-500" />
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Total Attacks</p>
                <p className="text-lg font-bold text-white">{summary.total_attacks}</p>
              </div>
            </div>

            {/* Divider */}
            <div className="h-10 w-px bg-slate-700" />

            {/* Blocked */}
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-success-500/20 flex items-center justify-center">
                <ShieldCheck className="w-4 h-4 text-success-500" />
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Blocked</p>
                <p className="text-lg font-bold text-success-500">{summary.blocked_count}</p>
              </div>
            </div>

            {/* Bypassed */}
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-danger-500/20 flex items-center justify-center">
                <ShieldAlert className="w-4 h-4 text-danger-500" />
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Bypassed</p>
                <p className="text-lg font-bold text-danger-500">{summary.bypassed_count}</p>
              </div>
            </div>

            {/* Flagged */}
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-warning-500/20 flex items-center justify-center">
                <AlertTriangle className="w-4 h-4 text-warning-500" />
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Flagged</p>
                <p className="text-lg font-bold text-warning-500">{summary.flagged_count}</p>
              </div>
            </div>

            {/* Divider */}
            <div className="h-10 w-px bg-slate-700" />

            {/* Avg Latency */}
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                <Clock className="w-4 h-4 text-slate-400" />
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Avg Latency</p>
                <p className="text-lg font-bold text-white">{formatLatency(summary.avg_latency_ms)}</p>
              </div>
            </div>
          </div>

          {/* Block Rate */}
          <div className="flex items-center gap-3 bg-slate-800/50 rounded-xl px-4 py-2">
            <div className="text-right">
              <p className="text-xs text-slate-500 uppercase tracking-wide">Defense Rate</p>
              <p className="text-2xl font-bold text-success-500">{summary.block_rate}%</p>
            </div>
            <div className="w-16 h-16">
              <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                <circle
                  cx="18"
                  cy="18"
                  r="15.5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="3"
                  className="text-slate-700"
                />
                <circle
                  cx="18"
                  cy="18"
                  r="15.5"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="3"
                  strokeDasharray={`${summary.block_rate} ${100 - summary.block_rate}`}
                  strokeLinecap="round"
                  className="text-success-500"
                />
              </svg>
            </div>
          </div>
        </div>

        {/* Debug Panel - Only visible in development */}
        {debugInfo && (
          <TelemetryDebugPanel debugInfo={debugInfo} />
        )}
      </div>
    </div>
  );
}

/**
 * Debug panel component - only rendered in development mode.
 */
function TelemetryDebugPanel({ debugInfo }: { debugInfo: NonNullable<ReturnType<typeof useTelemetrySummary>['debugInfo']> }) {
  return (
    <div className="mt-3 p-3 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono">
      <div className="flex items-center gap-2 mb-2 text-amber-400">
        <Bug className="w-3 h-3" />
        <span className="font-semibold">Telemetry Debug (DEV ONLY)</span>
      </div>
      <div className="grid grid-cols-4 gap-4 text-slate-400">
        <div>
          <span className="text-slate-500">Raw runs:</span>{' '}
          <span className="text-white">{debugInfo.raw_runs_loaded}</span>
        </div>
        <div>
          <span className="text-slate-500">After dedup:</span>{' '}
          <span className="text-white">{debugInfo.runs_after_dedup}</span>
        </div>
        <div>
          <span className="text-slate-500">Store version:</span>{' '}
          <span className="text-white">{debugInfo.store_version}</span>
        </div>
        <div>
          <span className="text-slate-500">Last update:</span>{' '}
          <span className="text-white">{new Date(debugInfo.last_aggregation_timestamp).toLocaleTimeString()}</span>
        </div>
      </div>
      <details className="mt-2">
        <summary className="cursor-pointer text-slate-500 hover:text-slate-300">
          Show computed summary JSON
        </summary>
        <pre className="mt-2 p-2 bg-slate-900 rounded text-[10px] overflow-auto max-h-32 text-green-400">
          {JSON.stringify(debugInfo.computed_summary, null, 2)}
        </pre>
      </details>
    </div>
  );
}
