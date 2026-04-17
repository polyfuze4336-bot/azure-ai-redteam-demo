import { useState, useEffect } from 'react';
import { 
  History, 
  Calendar, 
  ShieldCheck, 
  ChevronRight,
  Download,
  BarChart3,
  Clock,
  Loader2,
  RefreshCw,
  Target,
  AlertCircle,
  Zap,
  Activity,
  Server,
  CheckCircle,
  XCircle,
  Eye,
  TrendingUp,
  Cloud
} from 'lucide-react';
import Panel from '../components/Panel';
import StatusBadge from '../components/StatusBadge';
import { 
  getHistory, 
  getCampaigns, 
  ApiAttackResult, 
  ApiCampaignResult, 
  ApiError 
} from '../services/api';

// Extended types for this page with full campaign metrics
interface CampaignItem {
  id: string;
  correlationId: string;
  name: string;
  runSource: 'curated' | 'pyrit' | 'custom';  // Run source label
  createdAt: string;
  completedAt: string | null;
  status: 'running' | 'completed' | 'failed';
  // Foundry context
  foundryResourceName: string;
  deploymentName: string;
  targetName: string;
  shieldEnabled: boolean;
  // Core stats
  totalAttacks: number;
  blocked: number;
  passed: number;
  flagged: number;
  // Detailed breakdown
  safeRefusalCount: number;
  unsafeSuccessCount: number;
  suspiciousSuccessCount: number;
  errorCount: number;
  // Computed metrics
  attackSuccessRate: number;
  blockedRate: number;
  averageLatencyMs: number;
  totalLatencyMs: number;
  // Results
  results: ApiAttackResult[];
  isCampaign: boolean;
}

// Simple bar chart component for metrics visualization
function MetricBar({ 
  label, 
  value, 
  maxValue, 
  color 
}: { 
  label: string; 
  value: number; 
  maxValue: number; 
  color: 'success' | 'danger' | 'warning' | 'azure' | 'slate';
}) {
  const percentage = maxValue > 0 ? (value / maxValue) * 100 : 0;
  const colorClasses = {
    success: 'bg-success-500',
    danger: 'bg-danger-500',
    warning: 'bg-warning-500',
    azure: 'bg-azure-500',
    slate: 'bg-slate-500',
  };
  
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-slate-400 w-24 truncate">{label}</span>
      <div className="flex-1 h-2 bg-slate-700/50 rounded-full overflow-hidden">
        <div 
          className={`h-full ${colorClasses[color]} rounded-full transition-all duration-500`}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
      <span className="text-xs font-medium text-slate-300 w-8 text-right">{value}</span>
    </div>
  );
}

export default function CampaignHistory() {
  const [campaigns, setCampaigns] = useState<CampaignItem[]>([]);
  const [selectedCampaign, setSelectedCampaign] = useState<CampaignItem | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [campaignsData, historyData] = await Promise.all([
        getCampaigns({ limit: 50 }),
        getHistory({ limit: 100 }),
      ]);

      // Convert API campaigns to CampaignItem format
      const campaignItems: CampaignItem[] = campaignsData.map((c: ApiCampaignResult) => ({
        id: c.campaign_id,
        correlationId: c.correlation_id,
        name: c.name,
        runSource: c.run_source || 'curated',
        createdAt: c.created_at,
        completedAt: c.completed_at,
        status: c.status,
        foundryResourceName: c.foundry_resource_name || '',
        deploymentName: c.deployment_name || '',
        targetName: c.target_name || '',
        shieldEnabled: c.shield_enabled,
        totalAttacks: c.total_attacks,
        blocked: c.blocked_count,
        passed: c.passed_count,
        flagged: c.flagged_count,
        safeRefusalCount: c.safe_refusal_count || 0,
        unsafeSuccessCount: c.unsafe_success_count || 0,
        suspiciousSuccessCount: c.suspicious_success_count || 0,
        errorCount: c.error_count || 0,
        attackSuccessRate: c.attack_success_rate || 0,
        blockedRate: c.blocked_rate || 0,
        averageLatencyMs: c.average_latency_ms || 0,
        totalLatencyMs: c.total_latency_ms || 0,
        results: c.results,
        isCampaign: true,
      }));

      // Group orphan attacks (not part of any campaign)
      const campaignIds = new Set(campaignsData.map(c => c.campaign_id));
      const orphanResults = historyData.results.filter(
        (r: ApiAttackResult) => !r.campaign_id || !campaignIds.has(r.campaign_id)
      );
      
      if (orphanResults.length > 0) {
        const totalLatency = orphanResults.reduce((sum: number, r: ApiAttackResult) => sum + r.latency_ms, 0);
        const blocked = orphanResults.filter((r: ApiAttackResult) => r.outcome === 'safe').length;
        const passed = orphanResults.filter((r: ApiAttackResult) => r.outcome === 'vulnerable').length;
        
        const singleAttacksItem: CampaignItem = {
          id: 'single-attacks',
          correlationId: 'individual',
          name: 'Individual Attacks',
          runSource: 'curated',
          createdAt: orphanResults[0]?.timestamp || new Date().toISOString(),
          completedAt: null,
          status: 'completed',
          foundryResourceName: orphanResults[0]?.foundry_resource_name || '',
          deploymentName: orphanResults[0]?.deployment_name || '',
          targetName: orphanResults[0]?.target_name || '',
          shieldEnabled: true,
          totalAttacks: orphanResults.length,
          blocked,
          passed,
          flagged: orphanResults.length - blocked - passed,
          safeRefusalCount: 0,
          unsafeSuccessCount: passed,
          suspiciousSuccessCount: 0,
          errorCount: 0,
          attackSuccessRate: orphanResults.length > 0 ? (passed / orphanResults.length) * 100 : 0,
          blockedRate: orphanResults.length > 0 ? (blocked / orphanResults.length) * 100 : 0,
          averageLatencyMs: orphanResults.length > 0 ? totalLatency / orphanResults.length : 0,
          totalLatencyMs: totalLatency,
          results: orphanResults,
          isCampaign: false,
        };
        campaignItems.unshift(singleAttacksItem);
      }

      setCampaigns(campaignItems);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`Failed to load history (${err.status}): ${err.message}`);
      } else {
        setError('Failed to connect to backend. Is the server running on port 8000?');
      }
      console.error('History fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusFromOutcome = (outcome: string): 'blocked' | 'passed' | 'flagged' => {
    switch (outcome) {
      case 'safe': return 'blocked';
      case 'vulnerable': return 'passed';
      case 'partial': return 'flagged';
      default: return 'blocked';
    }
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="grid grid-cols-12 gap-4 h-[calc(100vh-180px)]">
        <div className="col-span-12 flex items-center justify-center">
          <div className="text-center">
            <Loader2 className="w-12 h-12 text-azure-500 mx-auto mb-4 animate-spin" />
            <p className="text-slate-400">Loading campaign history...</p>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="grid grid-cols-12 gap-4 h-[calc(100vh-180px)]">
        <div className="col-span-12 flex items-center justify-center">
          <div className="text-center max-w-md">
            <AlertCircle className="w-16 h-16 text-danger-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">Failed to Load History</h3>
            <p className="text-slate-400 text-sm mb-4">{error}</p>
            <button 
              onClick={fetchData}
              className="btn-primary inline-flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-12 gap-4 h-[calc(100vh-180px)]">
      {/* Campaign List */}
      <div className="col-span-4">
        <Panel 
          title="Campaign History" 
          subtitle={`${campaigns.length} campaigns recorded`}
          icon={<History className="w-4 h-4" />}
          className="h-full"
          headerAction={
            <button 
              onClick={fetchData}
              className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" />
              Refresh
            </button>
          }
        >
          {campaigns.length === 0 ? (
            <div className="h-full flex items-center justify-center">
              <div className="text-center">
                <Target className="w-12 h-12 text-slate-700 mx-auto mb-3" />
                <p className="text-slate-500">No campaigns recorded yet</p>
                <p className="text-slate-600 text-sm mt-1">Run a campaign to see it here</p>
              </div>
            </div>
          ) : (
            <div className="space-y-3 overflow-y-auto">
              {campaigns.map((campaign) => (
                <button
                  key={campaign.id}
                  onClick={() => setSelectedCampaign(campaign)}
                  className={`w-full text-left p-4 rounded-lg border transition-all duration-200 ${
                    selectedCampaign?.id === campaign.id
                      ? 'bg-azure-500/20 border-azure-500/50'
                      : 'bg-slate-800/50 border-slate-700/50 hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium text-white text-sm">{campaign.name}</h3>
                        {campaign.isCampaign && (
                          <span className="text-xs px-1.5 py-0.5 bg-azure-500/20 text-azure-400 rounded">
                            Campaign
                          </span>
                        )}
                        {/* Run source label - PyRIT campaigns are clearly marked as automated */}
                        {campaign.runSource === 'pyrit' && (
                          <span className="text-xs px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded">
                            PyRIT
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1 text-xs text-slate-500 mt-1">
                        <Calendar className="w-3 h-3" />
                        {formatDate(campaign.createdAt)}
                        {campaign.runSource === 'pyrit' && (
                          <span className="ml-2 text-purple-400">· Automated</span>
                        )}
                      </div>
                    </div>
                    <ChevronRight className={`w-4 h-4 transition-transform ${
                      selectedCampaign?.id === campaign.id ? 'text-azure-500 rotate-90' : 'text-slate-600'
                    }`} />
                  </div>

                  {/* Quick Stats */}
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-slate-400">{campaign.totalAttacks} attacks</span>
                    <span className="text-success-500">{campaign.blockedRate.toFixed(0)}% blocked</span>
                    {campaign.attackSuccessRate > 0 && (
                      <span className="text-danger-500">{campaign.attackSuccessRate.toFixed(0)}% bypassed</span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {/* Campaign Details */}
      <div className="col-span-8">
        {selectedCampaign ? (
          <div className="space-y-4 h-full overflow-y-auto">
            {/* Foundry Context Header */}
            <div className="glass-panel p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-azure-500/20 flex items-center justify-center">
                    <Cloud className="w-5 h-5 text-azure-400" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-lg font-semibold text-white">{selectedCampaign.name}</h2>
                      <StatusBadge 
                        status={selectedCampaign.status === 'completed' ? 'blocked' : selectedCampaign.status === 'running' ? 'flagged' : 'passed'} 
                        size="sm" 
                      />
                    </div>
                    <p className="text-sm text-slate-400">
                      Executed on <span className="text-azure-400 font-medium">{selectedCampaign.foundryResourceName || 'mkhalib-4370-resource'}</span>
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <div className="text-right">
                    <div className="text-slate-500">Target</div>
                    <div className="text-white font-medium">{selectedCampaign.targetName || selectedCampaign.deploymentName || 'gpt-4o'}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-slate-500">Shield</div>
                    <div className={selectedCampaign.shieldEnabled ? 'text-success-500 font-medium' : 'text-slate-400'}>
                      {selectedCampaign.shieldEnabled ? 'Enabled' : 'Disabled'}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Key Metrics Cards */}
            <div className="grid grid-cols-5 gap-3">
              <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 text-center">
                <BarChart3 className="w-5 h-5 text-slate-400 mx-auto mb-2" />
                <div className="text-2xl font-bold text-white">{selectedCampaign.totalAttacks}</div>
                <div className="text-xs text-slate-500 mt-1">Total Scenarios</div>
              </div>
              <div className="p-4 bg-success-500/10 rounded-lg border border-success-500/30 text-center">
                <ShieldCheck className="w-5 h-5 text-success-500 mx-auto mb-2" />
                <div className="text-2xl font-bold text-success-500">{selectedCampaign.blockedRate.toFixed(1)}%</div>
                <div className="text-xs text-success-500/70 mt-1">Blocked Rate</div>
              </div>
              <div className="p-4 bg-danger-500/10 rounded-lg border border-danger-500/30 text-center">
                <TrendingUp className="w-5 h-5 text-danger-500 mx-auto mb-2" />
                <div className="text-2xl font-bold text-danger-500">{selectedCampaign.attackSuccessRate.toFixed(1)}%</div>
                <div className="text-xs text-danger-500/70 mt-1">Attack Success</div>
              </div>
              <div className="p-4 bg-azure-500/10 rounded-lg border border-azure-500/30 text-center">
                <Zap className="w-5 h-5 text-azure-400 mx-auto mb-2" />
                <div className="text-2xl font-bold text-azure-400">{selectedCampaign.averageLatencyMs.toFixed(0)}ms</div>
                <div className="text-xs text-azure-400/70 mt-1">Avg Latency</div>
              </div>
              <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50 text-center">
                <Clock className="w-5 h-5 text-slate-400 mx-auto mb-2" />
                <div className="text-2xl font-bold text-white">{(selectedCampaign.totalLatencyMs / 1000).toFixed(1)}s</div>
                <div className="text-xs text-slate-500 mt-1">Total Time</div>
              </div>
            </div>

            {/* Detailed Breakdown */}
            <div className="grid grid-cols-2 gap-4">
              {/* Outcome Distribution */}
              <Panel title="Outcome Distribution" subtitle="Detailed breakdown by verdict" className="!p-4">
                <div className="space-y-3">
                  <MetricBar 
                    label="Blocked" 
                    value={selectedCampaign.blocked} 
                    maxValue={selectedCampaign.totalAttacks} 
                    color="success" 
                  />
                  <MetricBar 
                    label="Safe Refusal" 
                    value={selectedCampaign.safeRefusalCount} 
                    maxValue={selectedCampaign.totalAttacks} 
                    color="success" 
                  />
                  <MetricBar 
                    label="Suspicious" 
                    value={selectedCampaign.suspiciousSuccessCount} 
                    maxValue={selectedCampaign.totalAttacks} 
                    color="warning" 
                  />
                  <MetricBar 
                    label="Unsafe Success" 
                    value={selectedCampaign.unsafeSuccessCount} 
                    maxValue={selectedCampaign.totalAttacks} 
                    color="danger" 
                  />
                  <MetricBar 
                    label="Errors" 
                    value={selectedCampaign.errorCount} 
                    maxValue={selectedCampaign.totalAttacks} 
                    color="slate" 
                  />
                </div>
              </Panel>

              {/* Summary Stats */}
              <Panel title="Campaign Summary" subtitle="Key statistics" className="!p-4">
                <div className="space-y-3">
                  <div className="flex items-center justify-between py-2 border-b border-slate-700/50">
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-success-500" />
                      <span className="text-sm text-slate-300">Blocked Count</span>
                    </div>
                    <span className="text-sm font-medium text-white">{selectedCampaign.blocked}</span>
                  </div>
                  <div className="flex items-center justify-between py-2 border-b border-slate-700/50">
                    <div className="flex items-center gap-2">
                      <Eye className="w-4 h-4 text-warning-500" />
                      <span className="text-sm text-slate-300">Flagged for Review</span>
                    </div>
                    <span className="text-sm font-medium text-white">{selectedCampaign.flagged}</span>
                  </div>
                  <div className="flex items-center justify-between py-2 border-b border-slate-700/50">
                    <div className="flex items-center gap-2">
                      <XCircle className="w-4 h-4 text-danger-500" />
                      <span className="text-sm text-slate-300">Passed (Vulnerable)</span>
                    </div>
                    <span className="text-sm font-medium text-white">{selectedCampaign.passed}</span>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <div className="flex items-center gap-2">
                      <Activity className="w-4 h-4 text-azure-400" />
                      <span className="text-sm text-slate-300">Error Count</span>
                    </div>
                    <span className="text-sm font-medium text-white">{selectedCampaign.errorCount}</span>
                  </div>
                </div>
              </Panel>
            </div>

            {/* Attack Results Table */}
            <Panel 
              title="Attack Results" 
              subtitle={`${selectedCampaign.results.length} scenarios executed`}
              headerAction={
                <button className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1">
                  <Download className="w-3 h-3" />
                  Export
                </button>
              }
            >
              {selectedCampaign.results.length === 0 ? (
                <div className="p-8 bg-slate-800/30 rounded-lg border border-slate-700/50 text-center">
                  <Target className="w-10 h-10 text-slate-700 mx-auto mb-2" />
                  <p className="text-slate-500 text-sm">No attack results available</p>
                </div>
              ) : (
                <div className="overflow-hidden rounded-lg border border-slate-700/50">
                  <table className="w-full">
                    <thead className="bg-slate-800/80">
                      <tr>
                        <th className="text-left text-xs font-medium text-slate-400 px-4 py-3">Scenario</th>
                        <th className="text-left text-xs font-medium text-slate-400 px-4 py-3">Category</th>
                        <th className="text-left text-xs font-medium text-slate-400 px-4 py-3">Shield</th>
                        <th className="text-left text-xs font-medium text-slate-400 px-4 py-3">Outcome</th>
                        <th className="text-left text-xs font-medium text-slate-400 px-4 py-3">Latency</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/50">
                      {selectedCampaign.results.slice(0, 15).map((result) => (
                        <tr key={result.run_id} className="bg-slate-800/30 hover:bg-slate-800/50">
                          <td className="px-4 py-3 text-sm text-white">{result.scenario_name}</td>
                          <td className="px-4 py-3 text-sm text-slate-400 capitalize">
                            {result.attack_category.replace(/-/g, ' ')}
                          </td>
                          <td className="px-4 py-3">
                            <span className={`text-xs px-2 py-0.5 rounded ${
                              result.shield_verdict?.result === 'blocked' 
                                ? 'bg-success-500/20 text-success-400' 
                                : 'bg-slate-700 text-slate-400'
                            }`}>
                              {result.shield_verdict?.result || 'n/a'}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <StatusBadge status={getStatusFromOutcome(result.outcome)} size="sm" />
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-400">{result.latency_ms}ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {selectedCampaign.results.length > 15 && (
                    <div className="px-4 py-2 bg-slate-800/50 border-t border-slate-700/50">
                      <p className="text-xs text-slate-500 text-center">
                        Showing 15 of {selectedCampaign.results.length} results
                      </p>
                    </div>
                  )}
                </div>
              )}
            </Panel>

            {/* Campaign Metadata Footer */}
            <div className="flex items-center justify-between text-xs text-slate-500 px-4 py-3 bg-slate-800/30 rounded-lg border border-slate-700/50">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-1">
                  <Server className="w-3 h-3" />
                  <span>Resource: {selectedCampaign.foundryResourceName || 'mkhalib-4370-resource'}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Target className="w-3 h-3" />
                  <span>Deployment: {selectedCampaign.deploymentName || 'gpt-4o'}</span>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span>Campaign ID: {selectedCampaign.id.slice(0, 8)}...</span>
                <span>Correlation: {selectedCampaign.correlationId?.slice(0, 8) || 'N/A'}...</span>
              </div>
            </div>
          </div>
        ) : (
          <Panel 
            title="Campaign Details"
            subtitle="Select a campaign to view metrics"
            icon={<BarChart3 className="w-4 h-4" />}
            className="h-full"
          >
            <div className="h-full flex items-center justify-center">
              <div className="text-center">
                <History className="w-16 h-16 text-slate-700 mx-auto mb-4" />
                <p className="text-slate-500 text-lg">Select a campaign to view details</p>
                <p className="text-slate-600 text-sm mt-1">Metrics, breakdowns, and results will appear here</p>
              </div>
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}
