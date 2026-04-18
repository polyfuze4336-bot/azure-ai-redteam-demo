import { useState, useEffect } from 'react';
import {
  Activity,
  AlertCircle,
  Bot,
  Clock,
  Cloud,
  Database,
  Eye,
  FileText,
  History,
  Loader2,
  Monitor,
  RefreshCw,
  Server,
  Shield,
  Sparkles,
  Target,
  TrendingUp,
  Zap,
  BookOpen,
  Link2,
  Radio,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import Panel from '../components/Panel';
import {
  checkHealth,
  getStatistics,
  getCampaigns,
  getHistory,
  getAgents,
  getInvocations,
  getInvocationSummary,
  ApiHealthResponse,
  ApiCampaignResult,
  ApiAttackResult,
  ApiAgentDefinition,
  ApiAgentInvocation,
  ApiInvocationSummary,
  ApiError,
} from '../services/api';

// =============================================================================
// TYPES
// =============================================================================

interface OverviewStats {
  total_attacks: number;
  blocked_count: number;
  passed_count: number;
  flagged_count: number;
  avg_latency_ms: number;
  block_rate: number;
  total_campaigns: number;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSecs < 60) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

// Agent icons and colors
const agentIcons: Record<string, typeof Bot> = {
  attack_observer: Eye,
  telemetry_analyst: Activity,
  policy_explainer: BookOpen,
  campaign_reporter: FileText,
};

const agentColors: Record<string, { bg: string; text: string; border: string }> = {
  attack_observer: {
    bg: 'bg-cyan-500/10',
    text: 'text-cyan-400',
    border: 'border-cyan-500/30',
  },
  telemetry_analyst: {
    bg: 'bg-violet-500/10',
    text: 'text-violet-400',
    border: 'border-violet-500/30',
  },
  policy_explainer: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    border: 'border-amber-500/30',
  },
  campaign_reporter: {
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-400',
    border: 'border-emerald-500/30',
  },
};

// =============================================================================
// SUB-COMPONENTS
// =============================================================================

interface StatCardProps {
  label: string;
  value: string | number;
  icon: typeof Activity;
  iconColor?: string;
  iconBg?: string;
  trend?: string;
  trendUp?: boolean;
}

function StatCard({ label, value, icon: Icon, iconColor = 'text-azure-400', iconBg = 'bg-azure-500/20', trend, trendUp }: StatCardProps) {
  return (
    <div className="flex items-center justify-between p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
      <div>
        <p className="text-xs text-slate-500 uppercase tracking-wide">{label}</p>
        <p className="text-2xl font-bold text-white mt-1">{value}</p>
        {trend && (
          <p className={`text-xs mt-1 ${trendUp ? 'text-success-400' : 'text-danger-400'}`}>
            {trendUp ? '↑' : '↓'} {trend}
          </p>
        )}
      </div>
      <div className={`w-12 h-12 rounded-lg ${iconBg} flex items-center justify-center`}>
        <Icon className={`w-6 h-6 ${iconColor}`} />
      </div>
    </div>
  );
}

interface AgentCardMiniProps {
  agent: ApiAgentDefinition;
  invocationCount: number;
}

function AgentCardMini({ agent, invocationCount }: AgentCardMiniProps) {
  const Icon = agentIcons[agent.agent_type] || Bot;
  const colors = agentColors[agent.agent_type] || agentColors.attack_observer;
  const isActive = agent.status === 'active';

  return (
    <div className={`flex items-center gap-3 p-3 ${colors.bg} rounded-lg border ${colors.border}`}>
      <div className={`w-9 h-9 rounded-lg ${colors.bg} border ${colors.border} flex items-center justify-center`}>
        <Icon className={`w-4 h-4 ${colors.text}`} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-white truncate">{agent.agent_name}</p>
        <p className="text-xs text-slate-500">{invocationCount} invocations</p>
      </div>
      <div className="flex items-center gap-1">
        <div className={`w-2 h-2 rounded-full ${isActive ? 'bg-success-500' : 'bg-slate-500'}`} />
        <span className={`text-xs ${isActive ? 'text-success-400' : 'text-slate-400'}`}>
          {isActive ? 'Active' : 'Inactive'}
        </span>
      </div>
    </div>
  );
}

interface ActivityItemProps {
  title: string;
  subtitle: string;
  timestamp: string;
  status?: string;
  statusColor?: string;
  icon: typeof Activity;
  iconColor: string;
  iconBg: string;
}

function ActivityItem({ title, subtitle, timestamp, status, statusColor = 'text-slate-400', icon: Icon, iconColor, iconBg }: ActivityItemProps) {
  return (
    <div className="flex items-start gap-3 p-3 hover:bg-slate-800/30 rounded-lg transition-colors">
      <div className={`w-8 h-8 rounded-lg ${iconBg} flex items-center justify-center shrink-0 mt-0.5`}>
        <Icon className={`w-4 h-4 ${iconColor}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <p className="text-sm font-medium text-white truncate">{title}</p>
          <span className="text-xs text-slate-500 shrink-0">{timestamp}</span>
        </div>
        <p className="text-xs text-slate-400 truncate mt-0.5">{subtitle}</p>
        {status && (
          <span className={`inline-block text-xs ${statusColor} mt-1`}>{status}</span>
        )}
      </div>
    </div>
  );
}

interface ServiceStatusProps {
  name: string;
  status: 'healthy' | 'degraded' | 'offline' | 'placeholder';
  description?: string;
}

function ServiceStatus({ name, status, description }: ServiceStatusProps) {
  const statusConfig = {
    healthy: { color: 'text-success-400', bg: 'bg-success-500/20', dot: 'bg-success-500', label: 'Healthy' },
    degraded: { color: 'text-warning-400', bg: 'bg-warning-500/20', dot: 'bg-warning-500', label: 'Degraded' },
    offline: { color: 'text-danger-400', bg: 'bg-danger-500/20', dot: 'bg-danger-500', label: 'Offline' },
    placeholder: { color: 'text-slate-400', bg: 'bg-slate-500/20', dot: 'bg-slate-500', label: 'Not Configured' },
  };

  const config = statusConfig[status];

  return (
    <div className="flex items-center justify-between p-3 bg-slate-800/20 rounded-lg border border-slate-700/30">
      <div className="flex items-center gap-3">
        <div className={`w-2 h-2 rounded-full ${config.dot}`} />
        <div>
          <p className="text-sm text-white">{name}</p>
          {description && <p className="text-xs text-slate-500">{description}</p>}
        </div>
      </div>
      <span className={`text-xs px-2 py-0.5 rounded-full ${config.bg} ${config.color}`}>
        {config.label}
      </span>
    </div>
  );
}

// =============================================================================
// MAIN COMPONENT
// =============================================================================

export default function Overview() {
  // State
  const [health, setHealth] = useState<ApiHealthResponse | null>(null);
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [recentCampaigns, setRecentCampaigns] = useState<ApiCampaignResult[]>([]);
  const [recentRuns, setRecentRuns] = useState<ApiAttackResult[]>([]);
  const [agents, setAgents] = useState<ApiAgentDefinition[]>([]);
  const [recentInvocations, setRecentInvocations] = useState<ApiAgentInvocation[]>([]);
  const [invocationSummary, setInvocationSummary] = useState<ApiInvocationSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  // Fetch all data
  const fetchData = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [
        healthRes,
        statsRes,
        campaignsRes,
        historyRes,
        agentsRes,
        invocationsRes,
        invSummaryRes,
      ] = await Promise.all([
        checkHealth().catch(() => null),
        getStatistics().catch(() => null),
        getCampaigns({ limit: 5 }).catch(() => []),
        getHistory({ limit: 5 }).catch(() => ({ results: [] })),
        getAgents().catch(() => ({ agents: [] })),
        getInvocations({ limit: 5 }).catch(() => ({ invocations: [] })),
        getInvocationSummary().catch(() => null),
      ]);

      setHealth(healthRes);
      setStats(statsRes);
      setRecentCampaigns(campaignsRes);
      setRecentRuns(historyRes.results);
      setAgents(agentsRes.agents);
      setRecentInvocations(invocationsRes.invocations);
      setInvocationSummary(invSummaryRes);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('Failed to fetch overview data:', err);
      if (err instanceof ApiError) {
        setError(`Failed to load: ${err.status} ${err.statusText}`);
      } else {
        setError('Failed to load overview data');
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  // Computed values
  const activeAgents = agents.filter(a => a.status === 'active').length;
  const getAgentInvocationCount = (agentId: string): number => {
    return invocationSummary?.by_agent?.[agentId] || 0;
  };

  if (isLoading && !stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 text-azure-500 animate-spin" />
          <p className="text-slate-400">Loading overview...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Monitor className="w-7 h-7 text-azure-500" />
            Overview
          </h1>
          <p className="text-slate-400 mt-1">
            Red team demo environment at a glance
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-xs text-slate-500">
            Last updated: {lastRefresh.toLocaleTimeString()}
          </div>
          <button
            onClick={fetchData}
            disabled={isLoading}
            className="btn-secondary flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-danger-500/10 border border-danger-500/30 rounded-lg">
          <AlertCircle className="w-5 h-5 text-danger-400" />
          <p className="text-sm text-danger-300">{error}</p>
        </div>
      )}

      {/* Demo Disclaimer */}
      <div className="flex items-start gap-3 p-4 bg-azure-500/5 border border-azure-500/20 rounded-lg">
        <Sparkles className="w-5 h-5 text-azure-400 mt-0.5 shrink-0" />
        <div>
          <p className="text-sm text-azure-300 font-medium">Demo Dashboard</p>
          <p className="text-xs text-slate-400 mt-1">
            This page shows recent activity, agent invocations, and telemetry status for your demo.
            Use it alongside Azure AI Foundry to tell the complete story.
          </p>
        </div>
      </div>

      {/* Target Configuration */}
      <Panel className="p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-lg bg-azure-500/20 flex items-center justify-center">
            <Cloud className="w-5 h-5 text-azure-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-white">Target Configuration</h2>
            <p className="text-xs text-slate-500">Azure AI Foundry resource context</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
            <div className="flex items-center gap-2 mb-2">
              <Server className="w-4 h-4 text-azure-400" />
              <span className="text-xs text-slate-500 uppercase">Foundry Resource</span>
            </div>
            <p className="text-lg font-semibold text-white">mkhalib-4370-resource</p>
            <p className="text-xs text-slate-500 mt-1">East US 2</p>
          </div>

          <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
            <div className="flex items-center gap-2 mb-2">
              <Target className="w-4 h-4 text-cyan-400" />
              <span className="text-xs text-slate-500 uppercase">Primary Model</span>
            </div>
            <p className="text-lg font-semibold text-white">gpt-4o</p>
            <p className="text-xs text-slate-500 mt-1">Default deployment target</p>
          </div>

          <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-emerald-400" />
              <span className="text-xs text-slate-500 uppercase">Safety Layer</span>
            </div>
            <p className="text-lg font-semibold text-emerald-400">Content Safety Enabled</p>
            <p className="text-xs text-slate-500 mt-1">Azure AI Content Safety</p>
          </div>
        </div>
      </Panel>

      {/* Summary Stats Row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <StatCard
            label="Total Runs"
            value={stats.total_attacks}
            icon={Zap}
            iconColor="text-azure-400"
            iconBg="bg-azure-500/20"
          />
          <StatCard
            label="Campaigns"
            value={stats.total_campaigns}
            icon={History}
            iconColor="text-violet-400"
            iconBg="bg-violet-500/20"
          />
          <StatCard
            label="Blocked"
            value={stats.blocked_count}
            icon={Shield}
            iconColor="text-success-400"
            iconBg="bg-success-500/20"
          />
          <StatCard
            label="Block Rate"
            value={`${stats.block_rate}%`}
            icon={TrendingUp}
            iconColor="text-emerald-400"
            iconBg="bg-emerald-500/20"
          />
          <StatCard
            label="Active Agents"
            value={activeAgents}
            icon={Bot}
            iconColor="text-cyan-400"
            iconBg="bg-cyan-500/20"
          />
          <StatCard
            label="Avg Latency"
            value={`${stats.avg_latency_ms}ms`}
            icon={Clock}
            iconColor="text-amber-400"
            iconBg="bg-amber-500/20"
          />
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Agents Inventory */}
        <Panel className="p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Bot className="w-5 h-5 text-azure-400" />
              <h3 className="text-base font-semibold text-white">Agents Inventory</h3>
            </div>
            <Link 
              to="/agents" 
              className="text-xs text-azure-400 hover:text-azure-300 transition-colors"
            >
              View All →
            </Link>
          </div>

          <div className="space-y-2">
            {agents.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-6">No agents configured</p>
            ) : (
              agents.map((agent) => (
                <AgentCardMini
                  key={agent.agent_id}
                  agent={agent}
                  invocationCount={getAgentInvocationCount(agent.agent_id)}
                />
              ))
            )}
          </div>

          {invocationSummary && (
            <div className="mt-4 pt-4 border-t border-slate-700/50">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-500">Total Invocations</span>
                <span className="text-white font-medium">{invocationSummary.total_invocations}</span>
              </div>
              <div className="flex items-center justify-between text-xs mt-1">
                <span className="text-slate-500">Avg Latency</span>
                <span className="text-white font-medium">{invocationSummary.average_latency_ms}ms</span>
              </div>
            </div>
          )}
        </Panel>

        {/* Recent Run Activity */}
        <Panel className="p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              <h3 className="text-base font-semibold text-white">Recent Runs</h3>
            </div>
            <Link 
              to="/console" 
              className="text-xs text-azure-400 hover:text-azure-300 transition-colors"
            >
              Run Attack →
            </Link>
          </div>

          <div className="space-y-1">
            {recentRuns.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-6">No recent runs</p>
            ) : (
              recentRuns.map((run) => (
                <ActivityItem
                  key={run.run_id}
                  title={run.scenario_name}
                  subtitle={run.attack_category}
                  timestamp={formatRelativeTime(run.timestamp)}
                  status={run.outcome}
                  statusColor={
                    run.outcome === 'safe' ? 'text-success-400' :
                    run.outcome === 'vulnerable' ? 'text-danger-400' : 'text-warning-400'
                  }
                  icon={Zap}
                  iconColor="text-cyan-400"
                  iconBg="bg-cyan-500/10"
                />
              ))
            )}
          </div>
        </Panel>

        {/* Recent Campaign Activity */}
        <Panel className="p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <History className="w-5 h-5 text-violet-400" />
              <h3 className="text-base font-semibold text-white">Recent Campaigns</h3>
            </div>
            <Link 
              to="/history" 
              className="text-xs text-azure-400 hover:text-azure-300 transition-colors"
            >
              View History →
            </Link>
          </div>

          <div className="space-y-1">
            {recentCampaigns.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-6">No recent campaigns</p>
            ) : (
              recentCampaigns.map((campaign) => (
                <ActivityItem
                  key={campaign.campaign_id}
                  title={campaign.name}
                  subtitle={`${campaign.total_attacks} scenarios • ${campaign.blocked_rate}% blocked`}
                  timestamp={formatRelativeTime(campaign.created_at)}
                  status={campaign.status}
                  statusColor={
                    campaign.status === 'completed' ? 'text-success-400' :
                    campaign.status === 'failed' ? 'text-danger-400' : 'text-azure-400'
                  }
                  icon={History}
                  iconColor="text-violet-400"
                  iconBg="bg-violet-500/10"
                />
              ))
            )}
          </div>
        </Panel>
      </div>

      {/* Agent Activity & Telemetry Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Agent Activity */}
        <Panel className="p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-amber-400" />
              <h3 className="text-base font-semibold text-white">Recent Agent Invocations</h3>
            </div>
            <Link 
              to="/agents" 
              className="text-xs text-azure-400 hover:text-azure-300 transition-colors"
            >
              View All →
            </Link>
          </div>

          <div className="space-y-1">
            {recentInvocations.length === 0 ? (
              <p className="text-sm text-slate-500 text-center py-6">No recent invocations</p>
            ) : (
              recentInvocations.map((inv) => {
                const Icon = agentIcons[inv.agent_type] || Bot;
                const colors = agentColors[inv.agent_type] || agentColors.attack_observer;
                return (
                  <ActivityItem
                    key={inv.invocation_id}
                    title={inv.agent_name}
                    subtitle={inv.output_summary?.slice(0, 60) + '...' || inv.input_summary}
                    timestamp={formatRelativeTime(inv.timestamp)}
                    status={`${inv.status} • ${inv.latency_ms}ms`}
                    statusColor={
                      inv.status === 'completed' ? 'text-success-400' :
                      inv.status === 'failed' ? 'text-danger-400' : 'text-azure-400'
                    }
                    icon={Icon}
                    iconColor={colors.text}
                    iconBg={colors.bg}
                  />
                );
              })
            )}
          </div>
        </Panel>

        {/* Telemetry & Monitoring Status */}
        <Panel className="p-5">
          <div className="flex items-center gap-2 mb-4">
            <Radio className="w-5 h-5 text-emerald-400" />
            <h3 className="text-base font-semibold text-white">Telemetry & Monitoring</h3>
          </div>

          <div className="space-y-3">
            <ServiceStatus
              name="Console Telemetry"
              status={health ? 'healthy' : 'degraded'}
              description="Structured logging to stdout"
            />
            <ServiceStatus
              name="Agent Invocation Tracking"
              status={invocationSummary ? 'healthy' : 'degraded'}
              description="In-memory invocation history"
            />
            <ServiceStatus
              name="Correlation ID Propagation"
              status="healthy"
              description="Full trace context across runs"
            />
            <ServiceStatus
              name="Application Insights"
              status="placeholder"
              description="Ready for production integration"
            />
            <ServiceStatus
              name="Azure Monitor Workbook"
              status="placeholder"
              description="Ready for production dashboards"
            />
          </div>

          <div className="mt-4 pt-4 border-t border-slate-700/50">
            <p className="text-xs text-slate-500">
              Console telemetry is active. App Insights and Azure Monitor show where production integrations connect.
            </p>
          </div>
        </Panel>
      </div>

      {/* Quick Navigation */}
      <Panel className="p-5">
        <div className="flex items-center gap-2 mb-4">
          <Link2 className="w-5 h-5 text-azure-400" />
          <h3 className="text-base font-semibold text-white">Quick Navigation</h3>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Link
            to="/console"
            className="flex items-center gap-3 p-4 bg-slate-800/30 hover:bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-azure-500/30 transition-all"
          >
            <Zap className="w-5 h-5 text-azure-400" />
            <div>
              <p className="text-sm font-medium text-white">Attack Console</p>
              <p className="text-xs text-slate-500">Run red-team attacks</p>
            </div>
          </Link>

          <Link
            to="/history"
            className="flex items-center gap-3 p-4 bg-slate-800/30 hover:bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-azure-500/30 transition-all"
          >
            <History className="w-5 h-5 text-violet-400" />
            <div>
              <p className="text-sm font-medium text-white">Campaign History</p>
              <p className="text-xs text-slate-500">Review past campaigns</p>
            </div>
          </Link>

          <Link
            to="/compare"
            className="flex items-center gap-3 p-4 bg-slate-800/30 hover:bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-azure-500/30 transition-all"
          >
            <Database className="w-5 h-5 text-cyan-400" />
            <div>
              <p className="text-sm font-medium text-white">Comparison View</p>
              <p className="text-xs text-slate-500">Baseline vs guarded</p>
            </div>
          </Link>

          <Link
            to="/agents"
            className="flex items-center gap-3 p-4 bg-slate-800/30 hover:bg-slate-800/50 rounded-lg border border-slate-700/50 hover:border-azure-500/30 transition-all"
          >
            <Bot className="w-5 h-5 text-emerald-400" />
            <div>
              <p className="text-sm font-medium text-white">AI Agents</p>
              <p className="text-xs text-slate-500">Invoke analysis agents</p>
            </div>
          </Link>
        </div>
      </Panel>

      {/* Footer Disclaimer */}
      <div className="text-center py-4">
        <p className="text-xs text-slate-600">
          Azure AI Red Team Console • Demo Environment
        </p>
      </div>
    </div>
  );
}
