/**
 * React hooks for telemetry store.
 * 
 * Use these hooks in components to subscribe to telemetry data.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { TelemetrySummary, TelemetryDebugInfo } from './telemetryTypes';
import {
  subscribeTelemetry,
  getTelemetrySummary,
  getTelemetryDebugInfo,
  initializeTelemetryStore,
  refreshFromHistory,
  isStoreReady,
  isStoreLoading,
} from './telemetryStore';

/**
 * Hook to subscribe to telemetry summary updates.
 * 
 * This is the primary hook for components that display telemetry data.
 * It handles:
 * - Automatic subscription/unsubscription
 * - Store initialization on first use
 * - Periodic refresh scheduling
 * - Stable values during loading
 */
export function useTelemetrySummary(options?: {
  refreshIntervalMs?: number;
  autoRefresh?: boolean;
}): {
  summary: TelemetrySummary;
  isLoading: boolean;
  isInitialized: boolean;
  refresh: () => Promise<void>;
  debugInfo: TelemetryDebugInfo | null;
} {
  const { refreshIntervalMs = 30000, autoRefresh = true } = options || {};
  
  // Use ref to track if we've initialized
  const didInitialize = useRef(false);
  
  // Local state that mirrors the store
  const [summary, setSummary] = useState<TelemetrySummary>(getTelemetrySummary);
  const [isLoading, setIsLoading] = useState(isStoreLoading);
  const [isInitialized, setIsInitialized] = useState(isStoreReady);
  
  // Debug info (only computed when needed)
  const [debugInfo, setDebugInfo] = useState<TelemetryDebugInfo | null>(null);

  // Initialize store on mount
  useEffect(() => {
    if (didInitialize.current) return;
    didInitialize.current = true;
    
    // Initialize the store (loads from localStorage + fetches fresh)
    initializeTelemetryStore(true).then(() => {
      setIsInitialized(true);
      setIsLoading(false);
    }).catch(err => {
      console.error('[useTelemetrySummary] Init error:', err);
      setIsLoading(false);
    });
  }, []);

  // Subscribe to store updates
  useEffect(() => {
    const unsubscribe = subscribeTelemetry((newSummary) => {
      setSummary(newSummary);
      setIsLoading(isStoreLoading());
      
      // Update debug info in dev mode
      if (import.meta.env.DEV) {
        setDebugInfo(getTelemetryDebugInfo());
      }
    });
    
    return unsubscribe;
  }, []);

  // Auto-refresh interval
  useEffect(() => {
    if (!autoRefresh || refreshIntervalMs <= 0) return;
    
    const interval = setInterval(() => {
      refreshFromHistory().catch(err => {
        console.error('[useTelemetrySummary] Refresh error:', err);
      });
    }, refreshIntervalMs);
    
    return () => clearInterval(interval);
  }, [autoRefresh, refreshIntervalMs]);

  // Manual refresh function
  const refresh = useCallback(async () => {
    setIsLoading(true);
    try {
      await refreshFromHistory();
    } finally {
      setIsLoading(false);
    }
  }, []);

  return {
    summary,
    isLoading,
    isInitialized,
    refresh,
    debugInfo: import.meta.env.DEV ? debugInfo : null,
  };
}

/**
 * Hook for accessing debug info only.
 * Returns null in production.
 */
export function useTelemetryDebug(): TelemetryDebugInfo | null {
  const [debugInfo, setDebugInfo] = useState<TelemetryDebugInfo | null>(null);
  
  useEffect(() => {
    if (!import.meta.env.DEV) return;
    
    // Update debug info when store changes
    const unsubscribe = subscribeTelemetry(() => {
      setDebugInfo(getTelemetryDebugInfo());
    });
    
    return unsubscribe;
  }, []);
  
  return import.meta.env.DEV ? debugInfo : null;
}
