import { useState, useEffect, useRef, useCallback } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Clock, Zap, Target } from 'lucide-react';
import { getStatistics } from '../services/api';

interface DashboardMetrics {
  totalAttacks: number;
  blockedCount: number;
  passedCount: number;
  flaggedCount: number;
  avgLatencyMs: number;
  blockRate: number;
  totalCampaigns: number;
}

const STORAGE_KEY = 'redteam_metrics';

// Load from localStorage on module init
function loadCachedMetrics(): DashboardMetrics {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      return JSON.parse(stored);
    }
  } catch (e) {
    console.error('Failed to load cached metrics:', e);
  }
  return {
    totalAttacks: 0,
    blockedCount: 0,
    passedCount: 0,
    flaggedCount: 0,
    avgLatencyMs: 0,
    blockRate: 0,
    totalCampaigns: 0,
  };
}

function saveCachedMetrics(metrics: DashboardMetrics): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(metrics));
  } catch (e) {
    console.error('Failed to save cached metrics:', e);
  }
}

export default function SummaryBar() {
  const [metrics, setMetrics] = useState<DashboardMetrics>(loadCachedMetrics);
  
  const isMounted = useRef(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchMetrics = useCallback(async () => {
    try {
      const stats = await getStatistics();
      if (!isMounted.current) return;
      
      const newMetrics = {
        totalAttacks: stats.total_attacks,
        blockedCount: stats.blocked_count,
        passedCount: stats.passed_count,
        flaggedCount: stats.flagged_count,
        avgLatencyMs: stats.avg_latency_ms,
        blockRate: stats.block_rate,
        totalCampaigns: stats.total_campaigns,
      };
      
      // Only update if we have real data (don't overwrite with zeros if we had data)
      setMetrics(current => {
        if (newMetrics.totalAttacks === 0 && current.totalAttacks > 0) {
          // API returned 0 but we have cached data - keep cache
          // (backend might have restarted)
          return current;
        }
        saveCachedMetrics(newMetrics);
        return newMetrics;
      });
    } catch (error) {
      // Keep existing metrics on error - don't reset to zero
      console.error('Failed to fetch statistics:', error);
    }
  }, []);

  useEffect(() => {
    isMounted.current = true;
    fetchMetrics();
    
    // Refresh every 10 seconds
    intervalRef.current = setInterval(fetchMetrics, 10000);
    
    return () => {
      isMounted.current = false;
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [fetchMetrics]);

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
              <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                <Zap className="w-4 h-4 text-azure-500" />
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Total Attacks</p>
                <p className="text-lg font-bold text-white">{metrics.totalAttacks}</p>
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
                <p className="text-lg font-bold text-success-500">{metrics.blockedCount}</p>
              </div>
            </div>

            {/* Passed */}
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-danger-500/20 flex items-center justify-center">
                <ShieldAlert className="w-4 h-4 text-danger-500" />
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Bypassed</p>
                <p className="text-lg font-bold text-danger-500">{metrics.passedCount}</p>
              </div>
            </div>

            {/* Flagged */}
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-warning-500/20 flex items-center justify-center">
                <AlertTriangle className="w-4 h-4 text-warning-500" />
              </div>
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Flagged</p>
                <p className="text-lg font-bold text-warning-500">{metrics.flaggedCount}</p>
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
                <p className="text-lg font-bold text-white">{metrics.avgLatencyMs}ms</p>
              </div>
            </div>
          </div>

          {/* Block Rate */}
          <div className="flex items-center gap-3 bg-slate-800/50 rounded-xl px-4 py-2">
            <div className="text-right">
              <p className="text-xs text-slate-500 uppercase tracking-wide">Defense Rate</p>
              <p className="text-2xl font-bold text-success-500">{metrics.blockRate}%</p>
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
                  strokeDasharray={`${metrics.blockRate} ${100 - metrics.blockRate}`}
                  strokeLinecap="round"
                  className="text-success-500"
                />
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
