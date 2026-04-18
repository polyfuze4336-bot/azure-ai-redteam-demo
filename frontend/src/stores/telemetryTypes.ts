/**
 * Normalized telemetry types for the Red Team Demo.
 * These types define the single source of truth for all telemetry data.
 */

/**
 * Outcome classification for a single attack run.
 * Maps backend outcomes to frontend display categories.
 */
export type RunOutcome = 'blocked' | 'bypassed' | 'flagged' | 'error';

/**
 * Normalized representation of a single attack run.
 * This is the canonical format stored in the telemetry store.
 */
export interface NormalizedRun {
  run_id: string;
  timestamp: string;
  latency_ms: number;
  outcome: RunOutcome;
  attack_category: string;
  scenario_id: string;
  scenario_name: string;
  target_name: string;
  shield_enabled: boolean;
  campaign_id: string | null;
  // Verdicts for detailed analysis
  shield_verdict_result: 'blocked' | 'allowed' | 'flagged' | 'n/a';
  model_verdict_result: 'blocked' | 'allowed' | 'flagged' | 'n/a';
  evaluator_verdict_result: 'blocked' | 'allowed' | 'flagged' | 'n/a';
  // Detailed outcome flags (derived from verdicts)
  is_safe_refusal: boolean;
  is_unsafe_success: boolean;
  is_suspicious_success: boolean;
  is_error: boolean;
}

/**
 * Aggregated telemetry summary.
 * This is the normalized model that the UI reads from.
 */
export interface TelemetrySummary {
  // Core counts
  total_attacks: number;
  blocked_count: number;
  bypassed_count: number;
  flagged_count: number;
  
  // Detailed outcome breakdown
  safe_refusal_count: number;
  suspicious_success_count: number;
  unsafe_success_count: number;
  error_count: number;
  
  // Computed metrics
  avg_latency_ms: number;
  block_rate: number;
  
  // Metadata
  last_updated_at: string;
  runs_included: number;
}

/**
 * Debug information for telemetry aggregation.
 * Only shown in development mode.
 */
export interface TelemetryDebugInfo {
  raw_runs_loaded: number;
  runs_after_dedup: number;
  last_aggregation_timestamp: string;
  computed_summary: TelemetrySummary;
  store_version: number;
}

/**
 * State of the telemetry store.
 */
export interface TelemetryStoreState {
  // The normalized run list (single source of truth)
  runs: Map<string, NormalizedRun>;
  
  // Computed summary (derived from runs)
  summary: TelemetrySummary;
  
  // Loading state
  isLoading: boolean;
  isInitialized: boolean;
  lastFetchError: string | null;
  
  // Store metadata
  storeVersion: number;
  lastUpdatedAt: string;
}

/**
 * Default empty summary for initialization.
 */
export function createEmptySummary(): TelemetrySummary {
  return {
    total_attacks: 0,
    blocked_count: 0,
    bypassed_count: 0,
    flagged_count: 0,
    safe_refusal_count: 0,
    suspicious_success_count: 0,
    unsafe_success_count: 0,
    error_count: 0,
    avg_latency_ms: 0,
    block_rate: 0,
    last_updated_at: new Date().toISOString(),
    runs_included: 0,
  };
}

/**
 * localStorage key for persisted telemetry data.
 */
export const TELEMETRY_STORAGE_KEY = 'redteam_telemetry_v2';
