/**
 * Central Telemetry Store
 * 
 * This is the SINGLE SOURCE OF TRUTH for all telemetry data in the application.
 * 
 * Design principles:
 * 1. All run data flows through this store
 * 2. Summary is computed by aggregateTelemetry() only
 * 3. UI components subscribe to the store, never compute independently
 * 4. Updates are explicit and controlled
 * 5. Data persists to localStorage for stability across refreshes
 */

import { 
  NormalizedRun, 
  TelemetrySummary, 
  TelemetryDebugInfo,
  TelemetryStoreState,
  createEmptySummary,
  TELEMETRY_STORAGE_KEY,
} from './telemetryTypes';
import { 
  normalizeApiResult, 
  mergeRuns, 
  aggregateTelemetry,

  summariesEqual,
} from './telemetryAggregator';
import { ApiAttackResult, getHistory, getStatistics } from '../services/api';

// ============================================================================
// Store State
// ============================================================================

let storeState: TelemetryStoreState = {
  runs: new Map(),
  summary: createEmptySummary(),
  isLoading: false,
  isInitialized: false,
  lastFetchError: null,
  storeVersion: 0,
  lastUpdatedAt: new Date().toISOString(),
};

// Subscribers for reactive updates
type Subscriber = (summary: TelemetrySummary) => void;
const subscribers: Set<Subscriber> = new Set();

// ============================================================================
// Persistence
// ============================================================================

interface PersistedState {
  runs: [string, NormalizedRun][];
  summary: TelemetrySummary;
  version: number;
  savedAt: string;
}

function loadFromStorage(): void {
  try {
    const stored = localStorage.getItem(TELEMETRY_STORAGE_KEY);
    if (!stored) return;
    
    const parsed: PersistedState = JSON.parse(stored);
    
    // Validate the data
    if (!parsed.runs || !Array.isArray(parsed.runs)) return;
    if (!parsed.summary) return;
    
    // Restore the runs map
    storeState.runs = new Map(parsed.runs);
    storeState.summary = parsed.summary;
    storeState.storeVersion = parsed.version || 0;
    storeState.isInitialized = true;
    
    console.log(`[TelemetryStore] Loaded ${storeState.runs.size} runs from storage`);
  } catch (e) {
    console.error('[TelemetryStore] Failed to load from storage:', e);
  }
}

function saveToStorage(): void {
  try {
    const toSave: PersistedState = {
      runs: Array.from(storeState.runs.entries()),
      summary: storeState.summary,
      version: storeState.storeVersion,
      savedAt: new Date().toISOString(),
    };
    localStorage.setItem(TELEMETRY_STORAGE_KEY, JSON.stringify(toSave));
  } catch (e) {
    console.error('[TelemetryStore] Failed to save to storage:', e);
  }
}

// ============================================================================
// Core Store Operations
// ============================================================================

/**
 * Recompute the summary from current runs and notify subscribers.
 * This is the ONLY place where aggregation happens.
 */
function recomputeSummary(): void {
  const oldSummary = storeState.summary;
  const newSummary = aggregateTelemetry(storeState.runs);
  
  // Only update and notify if there's a meaningful change
  if (!summariesEqual(oldSummary, newSummary)) {
    storeState.summary = newSummary;
    storeState.storeVersion++;
    storeState.lastUpdatedAt = new Date().toISOString();
    
    // Persist
    saveToStorage();
    
    // Notify subscribers
    notifySubscribers();
  }
}

function notifySubscribers(): void {
  const summary = storeState.summary;
  subscribers.forEach(sub => {
    try {
      sub(summary);
    } catch (e) {
      console.error('[TelemetryStore] Subscriber error:', e);
    }
  });
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize the store from persisted state and optionally fetch fresh data.
 * Call this once when the app starts.
 */
export async function initializeTelemetryStore(fetchFresh = true): Promise<void> {
  // Load persisted data first (instant)
  loadFromStorage();
  
  // Mark as initialized even if fetch fails
  storeState.isInitialized = true;
  
  // Notify subscribers with persisted data immediately
  notifySubscribers();
  
  // Optionally fetch fresh data
  if (fetchFresh) {
    await refreshFromHistory();
  }
}

/**
 * Subscribe to summary updates.
 * Returns unsubscribe function.
 */
export function subscribeTelemetry(callback: Subscriber): () => void {
  subscribers.add(callback);
  
  // Immediately call with current state
  callback(storeState.summary);
  
  return () => {
    subscribers.delete(callback);
  };
}

/**
 * Get the current summary (synchronous read).
 */
export function getTelemetrySummary(): TelemetrySummary {
  return storeState.summary;
}

/**
 * Get debug information for development mode.
 */
export function getTelemetryDebugInfo(): TelemetryDebugInfo {
  return {
    raw_runs_loaded: storeState.runs.size,
    runs_after_dedup: storeState.runs.size,
    last_aggregation_timestamp: storeState.lastUpdatedAt,
    computed_summary: storeState.summary,
    store_version: storeState.storeVersion,
  };
}

/**
 * Check if the store is initialized and has data.
 */
export function isStoreReady(): boolean {
  return storeState.isInitialized;
}

/**
 * Check if the store is currently loading.
 */
export function isStoreLoading(): boolean {
  return storeState.isLoading;
}

/**
 * Add a single run result (e.g., after running an attack).
 * This is the preferred way to add new runs.
 */
export function addRun(apiResult: ApiAttackResult): void {
  const normalized = normalizeApiResult(apiResult);
  storeState.runs.set(normalized.run_id, normalized);
  recomputeSummary();
  
  console.log(`[TelemetryStore] Added run ${normalized.run_id}, total: ${storeState.runs.size}`);
}

/**
 * Add multiple runs (e.g., from a campaign completion).
 */
export function addRuns(apiResults: ApiAttackResult[]): void {
  const normalized = apiResults.map(normalizeApiResult);
  storeState.runs = mergeRuns(storeState.runs, normalized);
  recomputeSummary();
  
  console.log(`[TelemetryStore] Added ${apiResults.length} runs, total: ${storeState.runs.size}`);
}

/**
 * Refresh the store from history API.
 * This merges with existing data, never overwrites valid data with empty.
 */
export async function refreshFromHistory(): Promise<void> {
  if (storeState.isLoading) {
    console.log('[TelemetryStore] Already loading, skipping refresh');
    return;
  }
  
  storeState.isLoading = true;
  storeState.lastFetchError = null;
  
  try {
    // Fetch all history (we want the complete picture)
    const response = await getHistory({ limit: 500 });
    const apiResults = response.results || [];
    
    if (apiResults.length === 0) {
      // API returned empty but we might have local data
      // Don't clear existing data - backend might have restarted
      console.log('[TelemetryStore] API returned 0 results, keeping existing data');
      storeState.isLoading = false;
      return;
    }
    
    // Normalize and merge
    const normalized = apiResults.map(normalizeApiResult);
    storeState.runs = mergeRuns(storeState.runs, normalized);
    
    // Recompute
    recomputeSummary();
    
    console.log(`[TelemetryStore] Refreshed from history: ${apiResults.length} runs from API, ${storeState.runs.size} total`);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    storeState.lastFetchError = errorMsg;
    console.error('[TelemetryStore] Failed to refresh from history:', error);
    // Keep existing data on error
  } finally {
    storeState.isLoading = false;
  }
}

/**
 * Refresh from the statistics endpoint (for standalone stats).
 * This is a fallback when history isn't available.
 * We still don't overwrite meaningful data with zeros.
 */
export async function refreshFromStatistics(): Promise<void> {
  if (storeState.isLoading) return;
  
  // If we have local run data, use that instead
  if (storeState.runs.size > 0) {
    console.log('[TelemetryStore] Using local run data instead of statistics endpoint');
    return;
  }
  
  storeState.isLoading = true;
  
  try {
    const stats = await getStatistics();
    
    // Only update if we don't have local data
    if (storeState.runs.size === 0 && stats.total_attacks > 0) {
      // Create a synthetic summary from stats (limited accuracy)
      storeState.summary = {
        total_attacks: stats.total_attacks,
        blocked_count: stats.blocked_count,
        bypassed_count: stats.passed_count, // API uses 'passed' for bypassed
        flagged_count: stats.flagged_count,
        safe_refusal_count: stats.blocked_count,
        suspicious_success_count: Math.floor(stats.flagged_count / 2),
        unsafe_success_count: stats.passed_count,
        error_count: 0,
        avg_latency_ms: Math.round(stats.avg_latency_ms),
        block_rate: stats.block_rate,
        last_updated_at: new Date().toISOString(),
        runs_included: stats.total_attacks,
      };
      storeState.storeVersion++;
      saveToStorage();
      notifySubscribers();
    }
  } catch (error) {
    console.error('[TelemetryStore] Failed to fetch statistics:', error);
  } finally {
    storeState.isLoading = false;
  }
}

/**
 * Clear all telemetry data.
 * Use with caution - this removes all persisted data.
 */
export function clearTelemetryStore(): void {
  storeState.runs.clear();
  storeState.summary = createEmptySummary();
  storeState.storeVersion++;
  storeState.lastUpdatedAt = new Date().toISOString();
  
  try {
    localStorage.removeItem(TELEMETRY_STORAGE_KEY);
  } catch (e) {
    console.error('[TelemetryStore] Failed to clear storage:', e);
  }
  
  notifySubscribers();
  console.log('[TelemetryStore] Store cleared');
}

// ============================================================================
// React Hook
// ============================================================================

/**
 * React hook for subscribing to telemetry summary.
 * Use this in components instead of direct state management.
 */
export function useTelemetrySummary(): {
  summary: TelemetrySummary;
  isLoading: boolean;
  isInitialized: boolean;
  refresh: () => Promise<void>;
} {
  // This is a placeholder - actual implementation uses useState/useEffect
  // Components should import the hook from telemetryHooks.ts
  throw new Error('Use useTelemetrySummary from telemetryHooks.ts');
}
