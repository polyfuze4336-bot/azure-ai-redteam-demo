import { describe, it, expect, beforeEach } from 'vitest';
import { 
  normalizeApiResult, 
  mergeRuns, 
  aggregateTelemetry,
  summariesEqual 
} from '../stores/telemetryAggregator';
import { NormalizedRun, TelemetrySummary } from '../stores/telemetryTypes';

// Test fixtures - create API results that match the real ApiAttackResult format
const createMockApiResult = (overrides: {
  run_id?: string;
  scenario_id?: string;
  outcome?: 'safe' | 'vulnerable' | 'partial';
  latency_ms?: number;
  timestamp?: string;
} = {}) => ({
  run_id: overrides.run_id || `run-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  scenario_id: overrides.scenario_id || 'test-scenario',
  scenario_name: 'Test Scenario',
  attack_category: 'test-category',
  target_name: 'Test Model',
  prompt: 'Test prompt',
  response: 'Test response',
  latency_ms: overrides.latency_ms ?? 150,
  timestamp: overrides.timestamp || new Date().toISOString(),
  outcome: overrides.outcome || 'safe',
  shield_enabled: true,
  campaign_id: null,
  shield_verdict: {
    result: 'allowed' as const,
    categories_detected: [] as string[],
    explanation: 'Test',
    severity: 3,
  },
  model_verdict: {
    result: 'allowed' as const,
    categories_detected: [] as string[],
    explanation: 'Test',
  },
  evaluator_verdict: {
    result: 'allowed' as const,
    categories_detected: [] as string[],
    explanation: 'Test',
  },
});

// Create a minimal NormalizedRun for testing mergeRuns and aggregateTelemetry
const createNormalizedRun = (overrides: {
  run_id?: string;
  outcome?: 'blocked' | 'bypassed' | 'flagged' | 'error';
  latency_ms?: number;
  timestamp?: string;
} = {}): NormalizedRun => ({
  run_id: overrides.run_id || `run-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  timestamp: overrides.timestamp || new Date().toISOString(),
  latency_ms: overrides.latency_ms ?? 150,
  outcome: overrides.outcome || 'blocked',
  attack_category: 'test-category',
  scenario_id: 'test-scenario',
  scenario_name: 'Test Scenario',
  target_name: 'Test Model',
  shield_enabled: true,
  campaign_id: null,
  shield_verdict_result: 'allowed',
  model_verdict_result: 'allowed',
  evaluator_verdict_result: 'allowed',
  is_safe_refusal: overrides.outcome === 'blocked',
  is_unsafe_success: overrides.outcome === 'bypassed',
  is_suspicious_success: overrides.outcome === 'flagged',
  is_error: overrides.outcome === 'error',
});

describe('normalizeApiResult', () => {
  it('should normalize a safe outcome to blocked', () => {
    const apiResult = createMockApiResult({ outcome: 'safe' });
    const normalized = normalizeApiResult(apiResult);
    
    expect(normalized.outcome).toBe('blocked');
    expect(normalized.run_id).toBe(apiResult.run_id);
    expect(normalized.scenario_id).toBe(apiResult.scenario_id);
    expect(normalized.latency_ms).toBe(apiResult.latency_ms);
    expect(normalized.is_safe_refusal).toBe(true);
  });

  it('should normalize a vulnerable outcome to bypassed', () => {
    const apiResult = createMockApiResult({ outcome: 'vulnerable' });
    const normalized = normalizeApiResult(apiResult);
    
    expect(normalized.outcome).toBe('bypassed');
    expect(normalized.is_unsafe_success).toBe(true);
  });

  it('should normalize a partial outcome to flagged', () => {
    const apiResult = createMockApiResult({ outcome: 'partial' });
    const normalized = normalizeApiResult(apiResult);
    
    expect(normalized.outcome).toBe('flagged');
  });

  it('should preserve latency values', () => {
    const apiResult = createMockApiResult({ latency_ms: 250 });
    const normalized = normalizeApiResult(apiResult);
    
    expect(normalized.latency_ms).toBe(250);
  });

  it('should generate unique run_ids', () => {
    const result1 = createMockApiResult();
    const result2 = createMockApiResult();
    
    const norm1 = normalizeApiResult(result1);
    const norm2 = normalizeApiResult(result2);
    
    expect(norm1.run_id).not.toBe(norm2.run_id);
  });
});

describe('mergeRuns', () => {
  it('should merge runs by run_id, keeping newer versions', () => {
    const oldTimestamp = '2024-01-01T10:00:00Z';
    const newTimestamp = '2024-01-01T12:00:00Z';
    
    const existingRuns: Map<string, NormalizedRun> = new Map([
      ['run-1', createNormalizedRun({
        run_id: 'run-1',
        outcome: 'blocked',
        latency_ms: 100,
        timestamp: oldTimestamp,
      })],
    ]);
    
    const newRuns: NormalizedRun[] = [
      createNormalizedRun({
        run_id: 'run-1',  // Same ID, should update
        outcome: 'bypassed', // Different outcome
        latency_ms: 150,
        timestamp: newTimestamp,
      }),
      createNormalizedRun({
        run_id: 'run-2',  // New run
        outcome: 'blocked',
        latency_ms: 200,
        timestamp: newTimestamp,
      }),
    ];
    
    const merged = mergeRuns(existingRuns, newRuns);
    
    expect(merged.size).toBe(2);
    expect(merged.get('run-1')?.outcome).toBe('bypassed'); // Updated
    expect(merged.get('run-2')?.outcome).toBe('blocked'); // Added
  });

  it('should not replace newer runs with older data', () => {
    const newerTimestamp = '2024-01-01T14:00:00Z';
    const olderTimestamp = '2024-01-01T10:00:00Z';
    
    const existingRuns: Map<string, NormalizedRun> = new Map([
      ['run-1', createNormalizedRun({
        run_id: 'run-1',
        outcome: 'bypassed',
        latency_ms: 100,
        timestamp: newerTimestamp,
      })],
    ]);
    
    const olderRuns: NormalizedRun[] = [
      createNormalizedRun({
        run_id: 'run-1',
        outcome: 'blocked',
        latency_ms: 50,
        timestamp: olderTimestamp,
      }),
    ];
    
    const merged = mergeRuns(existingRuns, olderRuns);
    
    // Should keep the newer version
    expect(merged.get('run-1')?.outcome).toBe('bypassed');
    expect(merged.get('run-1')?.latency_ms).toBe(100);
  });

  it('should handle empty inputs', () => {
    const emptyMap = new Map<string, NormalizedRun>();
    const emptyArray: NormalizedRun[] = [];
    
    expect(mergeRuns(emptyMap, emptyArray).size).toBe(0);
  });
});

describe('aggregateTelemetry', () => {
  it('should return zero summary for empty runs', () => {
    const runs = new Map<string, NormalizedRun>();
    const summary = aggregateTelemetry(runs);
    
    expect(summary.total_attacks).toBe(0);
    expect(summary.blocked_count).toBe(0);
    expect(summary.bypassed_count).toBe(0);
    expect(summary.flagged_count).toBe(0);
    expect(summary.avg_latency_ms).toBe(0);
  });

  it('should correctly count a single blocked run', () => {
    const runs = new Map<string, NormalizedRun>([
      ['run-1', createNormalizedRun({
        run_id: 'run-1',
        outcome: 'blocked',
        latency_ms: 100,
      })],
    ]);
    
    const summary = aggregateTelemetry(runs);
    
    expect(summary.total_attacks).toBe(1);
    expect(summary.blocked_count).toBe(1);
    expect(summary.bypassed_count).toBe(0);
    expect(summary.flagged_count).toBe(0);
    expect(summary.avg_latency_ms).toBe(100);
  });

  it('should correctly count a single bypassed run', () => {
    const runs = new Map<string, NormalizedRun>([
      ['run-1', createNormalizedRun({
        run_id: 'run-1',
        outcome: 'bypassed',
        latency_ms: 200,
      })],
    ]);
    
    const summary = aggregateTelemetry(runs);
    
    expect(summary.total_attacks).toBe(1);
    expect(summary.blocked_count).toBe(0);
    expect(summary.bypassed_count).toBe(1);
    expect(summary.flagged_count).toBe(0);
  });

  it('should correctly count a single flagged run', () => {
    const runs = new Map<string, NormalizedRun>([
      ['run-1', createNormalizedRun({
        run_id: 'run-1',
        outcome: 'flagged',
        latency_ms: 150,
      })],
    ]);
    
    const summary = aggregateTelemetry(runs);
    
    expect(summary.total_attacks).toBe(1);
    expect(summary.blocked_count).toBe(0);
    expect(summary.bypassed_count).toBe(0);
    expect(summary.flagged_count).toBe(1);
  });

  it('should aggregate multiple runs with mixed outcomes', () => {
    const runs = new Map<string, NormalizedRun>([
      ['run-1', createNormalizedRun({ run_id: 'run-1', outcome: 'blocked', latency_ms: 100 })],
      ['run-2', createNormalizedRun({ run_id: 'run-2', outcome: 'blocked', latency_ms: 120 })],
      ['run-3', createNormalizedRun({ run_id: 'run-3', outcome: 'bypassed', latency_ms: 200 })],
      ['run-4', createNormalizedRun({ run_id: 'run-4', outcome: 'flagged', latency_ms: 80 })],
    ]);
    
    const summary = aggregateTelemetry(runs);
    
    expect(summary.total_attacks).toBe(4);
    expect(summary.blocked_count).toBe(2);
    expect(summary.bypassed_count).toBe(1);
    expect(summary.flagged_count).toBe(1);
    expect(summary.avg_latency_ms).toBe(125); // (100+120+200+80)/4
  });

  it('should calculate average latency correctly', () => {
    const runs = new Map<string, NormalizedRun>([
      ['run-1', createNormalizedRun({ run_id: 'run-1', outcome: 'blocked', latency_ms: 100 })],
      ['run-2', createNormalizedRun({ run_id: 'run-2', outcome: 'blocked', latency_ms: 300 })],
    ]);
    
    const summary = aggregateTelemetry(runs);
    
    expect(summary.avg_latency_ms).toBe(200); // (100+300)/2
  });

  it('should not count duplicate run_ids twice', () => {
    // Map naturally prevents duplicates, but let's verify
    const runs = new Map<string, NormalizedRun>();
    
    // Add same run twice - Map will only keep the last
    runs.set('run-1', createNormalizedRun({ run_id: 'run-1', outcome: 'blocked', latency_ms: 100 }));
    runs.set('run-1', createNormalizedRun({ run_id: 'run-1', outcome: 'bypassed', latency_ms: 150 }));
    
    const summary = aggregateTelemetry(runs);
    
    expect(summary.total_attacks).toBe(1);
    expect(summary.bypassed_count).toBe(1); // Last write wins
    expect(summary.blocked_count).toBe(0);
  });
});

describe('summariesEqual', () => {
  const createSummary = (overrides: Partial<TelemetrySummary> = {}): TelemetrySummary => ({
    total_attacks: 10,
    blocked_count: 5,
    bypassed_count: 3,
    flagged_count: 2,
    safe_refusal_count: 5,
    suspicious_success_count: 2,
    unsafe_success_count: 3,
    error_count: 0,
    avg_latency_ms: 150,
    block_rate: 50,
    last_updated_at: new Date().toISOString(),
    runs_included: 10,
    ...overrides,
  });

  it('should return true for identical summaries', () => {
    const summary1 = createSummary();
    const summary2 = createSummary();
    
    expect(summariesEqual(summary1, summary2)).toBe(true);
  });

  it('should return false when total_attacks differs', () => {
    const summary1 = createSummary();
    const summary2 = createSummary({ total_attacks: 11 });
    
    expect(summariesEqual(summary1, summary2)).toBe(false);
  });

  it('should return false when any count differs', () => {
    const base = createSummary();
    
    expect(summariesEqual(base, createSummary({ blocked_count: 6 }))).toBe(false);
    expect(summariesEqual(base, createSummary({ bypassed_count: 4 }))).toBe(false);
    expect(summariesEqual(base, createSummary({ flagged_count: 1 }))).toBe(false);
    expect(summariesEqual(base, createSummary({ avg_latency_ms: 200 }))).toBe(false);
  });
});

describe('Integration: Full workflow', () => {
  it('should normalize, merge, and aggregate correctly', () => {
    // Simulate a real workflow
    const existingRuns = new Map<string, NormalizedRun>();
    
    // Simulate first attack (safe outcome = blocked)
    const apiResult1 = createMockApiResult({ 
      run_id: 'real-run-1', 
      outcome: 'safe',
      latency_ms: 100,
    });
    const normalized1 = normalizeApiResult(apiResult1);
    const afterFirst = mergeRuns(existingRuns, [normalized1]);
    
    expect(afterFirst.size).toBe(1);
    expect(aggregateTelemetry(afterFirst).blocked_count).toBe(1);
    
    // Simulate second attack (vulnerable outcome = bypassed)
    const apiResult2 = createMockApiResult({ 
      run_id: 'real-run-2', 
      outcome: 'vulnerable',
      latency_ms: 200,
    });
    const normalized2 = normalizeApiResult(apiResult2);
    const afterSecond = mergeRuns(afterFirst, [normalized2]);
    
    expect(afterSecond.size).toBe(2);
    const summary = aggregateTelemetry(afterSecond);
    expect(summary.total_attacks).toBe(2);
    expect(summary.blocked_count).toBe(1);
    expect(summary.bypassed_count).toBe(1);
    expect(summary.avg_latency_ms).toBe(150);
  });
});
