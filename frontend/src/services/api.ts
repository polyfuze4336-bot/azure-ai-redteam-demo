/**
 * API service layer for communicating with the FastAPI backend.
 */

// Use environment variable for API URL, fallback to localhost for development
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

// =============================================================================
// Types matching backend schemas
// =============================================================================

export interface ApiVerdictDetail {
  result: 'blocked' | 'allowed' | 'flagged' | 'n/a';
  confidence: number;
  categories_detected: string[];
  source: string;
  details: Record<string, unknown>;
}

export interface ApiAttackResult {
  run_id: string;
  campaign_id: string | null;
  correlation_id: string;
  run_source: 'curated' | 'pyrit' | 'custom';  // Source of the run
  timestamp: string;
  latency_ms: number;
  attack_category: string;
  scenario_name: string;
  scenario_id: string;
  severity: string;
  prompt: string;
  normalized_prompt: string | null;
  response: string;
  target_name: string;
  shield_enabled: boolean;
  // Foundry context for traceability
  foundry_resource_name: string;
  deployment_name: string;
  // Verdicts
  shield_verdict: ApiVerdictDetail;
  model_verdict: ApiVerdictDetail;
  evaluator_verdict: ApiVerdictDetail;
  outcome: 'safe' | 'vulnerable' | 'partial';
  // Telemetry
  telemetry_status: 'captured' | 'partial' | 'failed' | 'disabled' | 'pending';
  tokens_used: number | null;
  metadata: Record<string, unknown>;
}

export interface ApiCampaignResult {
  campaign_id: string;
  correlation_id: string;
  name: string;
  description: string | null;
  run_source: 'curated' | 'pyrit' | 'custom';  // Source of the campaign
  status: 'running' | 'completed' | 'failed';
  created_at: string;
  completed_at: string | null;
  // Foundry context
  foundry_resource_name: string;
  deployment_name: string;
  target_name: string;
  shield_enabled: boolean;
  categories: string[];
  // Core statistics
  total_attacks: number;
  blocked_count: number;
  passed_count: number;
  flagged_count: number;
  // Detailed outcome breakdown
  safe_refusal_count: number;
  unsafe_success_count: number;
  suspicious_success_count: number;
  error_count: number;
  // Computed metrics
  attack_success_rate: number;
  blocked_rate: number;
  average_latency_ms: number;
  total_latency_ms: number;
  // Telemetry
  telemetry_status: 'captured' | 'partial' | 'failed' | 'disabled' | 'pending';
  results: ApiAttackResult[];
}

// =============================================================================
// Comparison Mode Types
// =============================================================================

export interface ApiComparisonTargetResult {
  target_type: 'baseline' | 'guarded';
  deployment_name: string;
  foundry_resource_name: string;
  endpoint_url: string | null;
  shield_enabled: boolean;
  response: string;
  latency_ms: number;
  tokens_used: number | null;
  shield_verdict: ApiVerdictDetail;
  model_verdict: ApiVerdictDetail;
  evaluator_verdict: ApiVerdictDetail;
  outcome: 'safe' | 'vulnerable' | 'partial';
  correlation_id: string;
}

export interface ApiComparisonResult {
  comparison_id: string;
  timestamp: string;
  scenario_id: string;
  scenario_name: string;
  attack_category: string;
  severity: string;
  prompt: string;
  expected_defense: string;
  is_same_resource: boolean;
  comparison_type: 'same_resource_different_deployments' | 'different_environments';
  baseline: ApiComparisonTargetResult;
  guarded: ApiComparisonTargetResult;
  latency_difference_ms: number;
  baseline_attack_success: boolean;
  guarded_attack_success: boolean;
  shield_effectiveness: string;
}

export interface ApiComparisonConfig {
  enabled: boolean;
  is_same_resource: boolean;
  comparison_type: string;
  foundry_resource_name: string;
  baseline: {
    deployment_name: string;
    shield_enabled: boolean;
    endpoint: string;
  };
  guarded: {
    deployment_name: string;
    shield_enabled: boolean;
    endpoint: string;
  };
}

export interface ApiHistoryResponse {
  results: ApiAttackResult[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApiHealthResponse {
  status: string;
  version: string;
  timestamp: string;
  services: Record<string, string>;
}

export interface ApiScenario {
  id: string;
  name: string;
  category: string;
  description: string;
  prompt_template: string;
  prompt: string;  // Alias for prompt_template (backward compatibility)
  severity: string;
  expected_defense: string;
  narrator_notes: string | null;
}

export interface ApiAttackPack {
  category: string;
  name: string;
  description: string;
  count: number;
  severities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface ApiScenarioStats {
  total_scenarios: number;
  total_categories: number;
  severities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  categories: string[];
}

// =============================================================================
// API Error Handling
// =============================================================================

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    message?: string
  ) {
    super(message || `API Error: ${status} ${statusText}`);
    this.name = 'ApiError';
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new ApiError(response.status, response.statusText, errorText);
  }
  return response.json();
}

// =============================================================================
// API Functions
// =============================================================================

/**
 * Health check - verify backend is running
 */
export async function checkHealth(): Promise<ApiHealthResponse> {
  const response = await fetch(`${API_BASE_URL}/api/health`);
  return handleResponse<ApiHealthResponse>(response);
}

/**
 * Run a single attack
 */
export async function runAttack(params: {
  scenarioId: string;
  targetModel: string;
  shieldEnabled: boolean;
  customPrompt?: string;
}): Promise<ApiAttackResult> {
  const response = await fetch(`${API_BASE_URL}/api/run-attack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scenario_id: params.scenarioId,
      target_model: params.targetModel,
      shield_enabled: params.shieldEnabled,
      custom_prompt: params.customPrompt || null,
    }),
  });
  return handleResponse<ApiAttackResult>(response);
}

/**
 * Run a campaign of attacks
 */
export async function runCampaign(params: {
  name: string;
  category?: string;
  scenarioIds?: string[];
  targetModel: string;
  shieldEnabled: boolean;
}): Promise<ApiCampaignResult> {
  const response = await fetch(`${API_BASE_URL}/api/run-campaign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: params.name,
      category: params.category || null,
      scenario_ids: params.scenarioIds || null,
      target_model: params.targetModel,
      shield_enabled: params.shieldEnabled,
    }),
  });
  return handleResponse<ApiCampaignResult>(response);
}

/**
 * Get attack history
 */
export async function getHistory(params?: {
  limit?: number;
  offset?: number;
  category?: string;
  campaignId?: string;
}): Promise<ApiHistoryResponse> {
  const searchParams = new URLSearchParams();
  if (params?.limit) searchParams.set('limit', params.limit.toString());
  if (params?.offset) searchParams.set('offset', params.offset.toString());
  if (params?.category) searchParams.set('category', params.category);
  if (params?.campaignId) searchParams.set('campaign_id', params.campaignId);

  const url = `${API_BASE_URL}/api/history${searchParams.toString() ? '?' + searchParams : ''}`;
  const response = await fetch(url);
  return handleResponse<ApiHistoryResponse>(response);
}

/**
 * Get a specific attack result
 */
export async function getAttackResult(runId: string): Promise<ApiAttackResult> {
  const response = await fetch(`${API_BASE_URL}/api/history/${runId}`);
  return handleResponse<ApiAttackResult>(response);
}

/**
 * Get all campaigns
 */
export async function getCampaigns(params?: {
  limit?: number;
  offset?: number;
}): Promise<ApiCampaignResult[]> {
  const searchParams = new URLSearchParams();
  if (params?.limit) searchParams.set('limit', params.limit.toString());
  if (params?.offset) searchParams.set('offset', params.offset.toString());

  const url = `${API_BASE_URL}/api/campaigns${searchParams.toString() ? '?' + searchParams : ''}`;
  const response = await fetch(url);
  return handleResponse<ApiCampaignResult[]>(response);
}

/**
 * Get a specific campaign
 */
export async function getCampaign(campaignId: string): Promise<ApiCampaignResult> {
  const response = await fetch(`${API_BASE_URL}/api/campaigns/${campaignId}`);
  return handleResponse<ApiCampaignResult>(response);
}

/**
 * Get all scenarios
 */
export async function getScenarios(category?: string): Promise<ApiScenario[]> {
  const url = category
    ? `${API_BASE_URL}/api/scenarios?category=${category}`
    : `${API_BASE_URL}/api/scenarios`;
  const response = await fetch(url);
  return handleResponse<ApiScenario[]>(response);
}

/**
 * Get a specific scenario
 */
export async function getScenario(scenarioId: string): Promise<ApiScenario> {
  const response = await fetch(`${API_BASE_URL}/api/scenarios/${scenarioId}`);
  return handleResponse<ApiScenario>(response);
}

/**
 * Get all attack packs with metadata
 */
export async function getAttackPacks(): Promise<ApiAttackPack[]> {
  const response = await fetch(`${API_BASE_URL}/api/scenarios/packs`);
  return handleResponse<ApiAttackPack[]>(response);
}

/**
 * Get scenario library statistics
 */
export async function getScenarioStats(): Promise<ApiScenarioStats> {
  const response = await fetch(`${API_BASE_URL}/api/scenarios/stats`);
  return handleResponse<ApiScenarioStats>(response);
}

/**
 * Get category names list
 */
export async function getCategoryNames(): Promise<string[]> {
  const response = await fetch(`${API_BASE_URL}/api/scenarios/categories/names`);
  return handleResponse<string[]>(response);
}

/**
 * Get statistics
 */
export async function getStatistics(): Promise<{
  total_attacks: number;
  blocked_count: number;
  passed_count: number;
  flagged_count: number;
  avg_latency_ms: number;
  block_rate: number;
  total_campaigns: number;
}> {
  const response = await fetch(`${API_BASE_URL}/api/statistics`);
  return handleResponse(response);
}

// =============================================================================
// Comparison API Functions
// =============================================================================

/**
 * Get comparison mode configuration
 */
export async function getComparisonConfig(): Promise<ApiComparisonConfig> {
  const response = await fetch(`${API_BASE_URL}/api/comparison/config`);
  return handleResponse<ApiComparisonConfig>(response);
}

/**
 * Run a side-by-side comparison attack
 */
export async function runComparison(params: {
  scenarioId: string;
  customPrompt?: string;
  baselineDeployment?: string;
  guardedDeployment?: string;
  baselineShieldEnabled?: boolean;
  guardedShieldEnabled?: boolean;
}): Promise<ApiComparisonResult> {
  const response = await fetch(`${API_BASE_URL}/api/comparison/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scenario_id: params.scenarioId,
      custom_prompt: params.customPrompt || null,
      baseline_deployment: params.baselineDeployment || null,
      guarded_deployment: params.guardedDeployment || null,
      baseline_shield_enabled: params.baselineShieldEnabled ?? null,
      guarded_shield_enabled: params.guardedShieldEnabled ?? null,
    }),
  });
  return handleResponse<ApiComparisonResult>(response);
}

// =============================================================================
// PyRIT Integration Types (Optional Addon)
// =============================================================================

export type PyRITStrategy = 
  | 'jailbreak'
  | 'prompt_injection'
  | 'crescendo'
  | 'pair'
  | 'tap'
  | 'skeleton_key'
  | 'custom';

export type PyRITStatus = 
  | 'available'
  | 'not_installed'
  | 'disabled'
  | 'misconfigured';

export interface ApiPyRITConfig {
  status: PyRITStatus;
  enabled: boolean;
  available: boolean;
  strategies: PyRITStrategy[];
  default_max_turns: number;
  default_parallel_attacks: number;
  default_timeout_seconds: number;
  foundry_resource_name: string;
  endpoint_configured: boolean;
  message: string;
}

export interface ApiPyRITAttackResult {
  sequence_id: string;
  strategy: PyRITStrategy;
  objective: string;
  turns: Array<{ role: string; content: string; turn: number }>;
  total_turns: number;
  success: boolean;
  success_score: number;
  raw_output: Record<string, unknown>;
  duration_ms: number;
  error: string | null;
}

export interface ApiPyRITCampaignResult {
  campaign_id: string;
  correlation_id: string;
  name: string;
  description: string | null;
  run_source: 'pyrit';
  created_at: string;
  completed_at: string | null;
  status: 'running' | 'completed' | 'failed';
  foundry_resource_name: string;
  deployment_name: string;
  target_name: string;
  shield_enabled: boolean;
  strategies_run: PyRITStrategy[];
  pyrit_results: ApiPyRITAttackResult[];
  normalized_results: ApiAttackResult[];
  total_sequences: number;
  successful_attacks: number;
  blocked_count: number;
  passed_count: number;
  flagged_count: number;
  error_count: number;
  attack_success_rate: number;
  blocked_rate: number;
  average_duration_ms: number;
  total_duration_ms: number;
  metadata: Record<string, unknown>;
}

export interface ApiPyRITStrategy {
  id: string;
  name: string;
  description: string;
  severity: string;
  multi_turn: boolean;
}

// =============================================================================
// PyRIT API Functions
// =============================================================================

/**
 * Get PyRIT integration status and configuration
 */
export async function getPyRITConfig(): Promise<ApiPyRITConfig> {
  const response = await fetch(`${API_BASE_URL}/api/pyrit/config`);
  return handleResponse<ApiPyRITConfig>(response);
}

/**
 * Run a PyRIT automated campaign
 */
export async function runPyRITCampaign(params: {
  name: string;
  description?: string;
  strategies?: PyRITStrategy[];
  targetModel?: string;
  shieldEnabled?: boolean;
  maxTurns?: number;
  parallelAttacks?: number;
  timeoutSeconds?: number;
  customObjectives?: string[];
}): Promise<ApiPyRITCampaignResult> {
  const response = await fetch(`${API_BASE_URL}/api/pyrit/campaign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: params.name,
      description: params.description || null,
      strategies: params.strategies || ['jailbreak', 'prompt_injection'],
      target_model: params.targetModel || 'gpt-4o',
      shield_enabled: params.shieldEnabled ?? true,
      max_turns: params.maxTurns || 5,
      parallel_attacks: params.parallelAttacks || 3,
      timeout_seconds: params.timeoutSeconds || 120,
      custom_objectives: params.customObjectives || [],
    }),
  });
  return handleResponse<ApiPyRITCampaignResult>(response);
}

/**
 * Get available PyRIT attack strategies
 */
export async function getPyRITStrategies(): Promise<{ strategies: ApiPyRITStrategy[] }> {
  const response = await fetch(`${API_BASE_URL}/api/pyrit/strategies`);
  return handleResponse<{ strategies: ApiPyRITStrategy[] }>(response);
}
