/**
 * Canonical telemetry aggregation logic.
 * 
 * This module provides the ONLY function that computes telemetry summaries.
 * No other module should independently calculate these values.
 */

import { ApiAttackResult } from '../services/api';
import { 
  NormalizedRun, 
  TelemetrySummary, 
  RunOutcome,
  createEmptySummary 
} from './telemetryTypes';

/**
 * Normalize an API attack result into the canonical NormalizedRun format.
 * This ensures consistent outcome classification across the application.
 */
export function normalizeApiResult(apiResult: ApiAttackResult): NormalizedRun {
  // Determine outcome based on API outcome field
  let outcome: RunOutcome;
  let is_safe_refusal = false;
  let is_unsafe_success = false;
  let is_suspicious_success = false;
  let is_error = false;

  // Check for error conditions first
  const hasError = 
    apiResult.evaluator_verdict?.categories_detected?.includes('api_error') ||
    apiResult.evaluator_verdict?.categories_detected?.includes('error_condition') ||
    apiResult.model_verdict?.categories_detected?.includes('api_error') ||
    apiResult.response?.includes('[ERROR]');

  if (hasError) {
    outcome = 'error';
    is_error = true;
  } else if (apiResult.outcome === 'safe') {
    // Safe outcome = attack was blocked/refused
    outcome = 'blocked';
    is_safe_refusal = true;
  } else if (apiResult.outcome === 'vulnerable') {
    // Vulnerable = attack succeeded (bypassed defenses)
    outcome = 'bypassed';
    is_unsafe_success = true;
  } else if (apiResult.outcome === 'partial') {
    // Partial = flagged but not fully blocked
    // Check if it's suspicious success or just flagged
    const shieldFlagged = apiResult.shield_verdict?.result === 'flagged';
    const evaluatorSuspicious = apiResult.evaluator_verdict?.details?.outcome === 'suspicious';
    
    if (shieldFlagged || evaluatorSuspicious) {
      is_suspicious_success = true;
    }
    outcome = 'flagged';
  } else {
    // Default to flagged for unknown states
    outcome = 'flagged';
  }

  return {
    run_id: apiResult.run_id,
    timestamp: apiResult.timestamp,
    latency_ms: apiResult.latency_ms,
    outcome,
    attack_category: apiResult.attack_category,
    scenario_id: apiResult.scenario_id,
    scenario_name: apiResult.scenario_name,
    target_name: apiResult.target_name,
    shield_enabled: apiResult.shield_enabled,
    campaign_id: apiResult.campaign_id,
    shield_verdict_result: apiResult.shield_verdict?.result || 'n/a',
    model_verdict_result: apiResult.model_verdict?.result || 'n/a',
    evaluator_verdict_result: apiResult.evaluator_verdict?.result || 'n/a',
    is_safe_refusal,
    is_unsafe_success,
    is_suspicious_success,
    is_error,
  };
}

/**
 * Merge multiple run lists, deduplicating by run_id.
 * Later runs (by timestamp) take precedence for duplicates.
 */
export function mergeRuns(
  existingRuns: Map<string, NormalizedRun>,
  newRuns: NormalizedRun[]
): Map<string, NormalizedRun> {
  const merged = new Map(existingRuns);
  
  for (const run of newRuns) {
    const existing = merged.get(run.run_id);
    if (!existing) {
      merged.set(run.run_id, run);
    } else {
      // Keep the newer one based on timestamp
      const existingTime = new Date(existing.timestamp).getTime();
      const newTime = new Date(run.timestamp).getTime();
      if (newTime >= existingTime) {
        merged.set(run.run_id, run);
      }
    }
  }
  
  return merged;
}

/**
 * THE canonical aggregation function.
 * 
 * This is the ONLY function that should compute telemetry summaries.
 * All UI components must use this function's output.
 * 
 * Definitions:
 * - Total Attacks = total completed runs in the store
 * - Blocked = runs with outcome 'blocked' (safe refusal)
 * - Bypassed = runs with outcome 'bypassed' (unsafe success)
 * - Flagged = runs with outcome 'flagged' (partial/suspicious)
 * - Avg Latency = average latency across runs with valid latency > 0
 * - Block Rate = (blocked / total) * 100
 */
export function aggregateTelemetry(runs: Map<string, NormalizedRun>): TelemetrySummary {
  const runList = Array.from(runs.values());
  
  if (runList.length === 0) {
    return createEmptySummary();
  }

  // Count by outcome
  let blocked_count = 0;
  let bypassed_count = 0;
  let flagged_count = 0;
  let error_count = 0;
  
  // Detailed breakdown
  let safe_refusal_count = 0;
  let suspicious_success_count = 0;
  let unsafe_success_count = 0;
  
  // Latency tracking
  let total_latency = 0;
  let latency_count = 0;

  for (const run of runList) {
    // Count by outcome
    switch (run.outcome) {
      case 'blocked':
        blocked_count++;
        break;
      case 'bypassed':
        bypassed_count++;
        break;
      case 'flagged':
        flagged_count++;
        break;
      case 'error':
        error_count++;
        break;
    }
    
    // Detailed breakdown flags
    if (run.is_safe_refusal) safe_refusal_count++;
    if (run.is_suspicious_success) suspicious_success_count++;
    if (run.is_unsafe_success) unsafe_success_count++;
    if (run.is_error) error_count = Math.max(error_count, 
      runList.filter(r => r.is_error).length);
    
    // Latency (only count valid values)
    if (run.latency_ms > 0) {
      total_latency += run.latency_ms;
      latency_count++;
    }
  }

  const total_attacks = runList.length;
  const avg_latency_ms = latency_count > 0 
    ? Math.round(total_latency / latency_count) 
    : 0;
  const block_rate = total_attacks > 0 
    ? Math.round((blocked_count / total_attacks) * 1000) / 10 
    : 0;

  return {
    total_attacks,
    blocked_count,
    bypassed_count,
    flagged_count,
    safe_refusal_count,
    suspicious_success_count,
    unsafe_success_count,
    error_count,
    avg_latency_ms,
    block_rate,
    last_updated_at: new Date().toISOString(),
    runs_included: total_attacks,
  };
}

/**
 * Check if a summary represents meaningful data (not just zeros).
 */
export function hasMeaningfulData(summary: TelemetrySummary): boolean {
  return summary.total_attacks > 0;
}

/**
 * Compare two summaries to determine if they're equivalent.
 * Used to prevent unnecessary rerenders.
 */
export function summariesEqual(a: TelemetrySummary, b: TelemetrySummary): boolean {
  return (
    a.total_attacks === b.total_attacks &&
    a.blocked_count === b.blocked_count &&
    a.bypassed_count === b.bypassed_count &&
    a.flagged_count === b.flagged_count &&
    a.avg_latency_ms === b.avg_latency_ms &&
    a.error_count === b.error_count
  );
}
