/**
 * Stores barrel export.
 * 
 * All store-related functionality should be imported from this module.
 */

// Types
export type {
  NormalizedRun,
  TelemetrySummary,
  TelemetryDebugInfo,
  TelemetryStoreState,
  RunOutcome,
} from './telemetryTypes';

export { createEmptySummary, TELEMETRY_STORAGE_KEY } from './telemetryTypes';

// Aggregation utilities
export {
  normalizeApiResult,
  mergeRuns,
  aggregateTelemetry,
  hasMeaningfulData,
  summariesEqual,
} from './telemetryAggregator';

// Store operations
export {
  initializeTelemetryStore,
  subscribeTelemetry,
  getTelemetrySummary,
  getTelemetryDebugInfo,
  isStoreReady,
  isStoreLoading,
  addRun,
  addRuns,
  refreshFromHistory,
  refreshFromStatistics,
  clearTelemetryStore,
} from './telemetryStore';

// React hooks
export { useTelemetrySummary, useTelemetryDebug } from './telemetryHooks';
