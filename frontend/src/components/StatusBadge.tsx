import { ShieldCheck, ShieldAlert, AlertTriangle, Ban, HelpCircle } from 'lucide-react';

type StatusType = 'blocked' | 'passed' | 'flagged' | 'error' | 'allowed' | 'n/a' | 'safe' | 'vulnerable' | 'partial';

interface StatusBadgeProps {
  status: StatusType;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

const statusConfig: Record<StatusType, { 
  bg: string; 
  text: string; 
  icon: typeof ShieldCheck;
  label: string;
}> = {
  blocked: { 
    bg: 'bg-success-500/20 border-success-500/30', 
    text: 'text-success-500', 
    icon: ShieldCheck,
    label: 'BLOCKED'
  },
  safe: { 
    bg: 'bg-success-500/20 border-success-500/30', 
    text: 'text-success-500', 
    icon: ShieldCheck,
    label: 'SAFE'
  },
  passed: { 
    bg: 'bg-danger-500/20 border-danger-500/30', 
    text: 'text-danger-500', 
    icon: ShieldAlert,
    label: 'PASSED'
  },
  vulnerable: { 
    bg: 'bg-danger-500/20 border-danger-500/30', 
    text: 'text-danger-500', 
    icon: ShieldAlert,
    label: 'VULNERABLE'
  },
  allowed: { 
    bg: 'bg-danger-500/20 border-danger-500/30', 
    text: 'text-danger-500', 
    icon: ShieldAlert,
    label: 'ALLOWED'
  },
  flagged: { 
    bg: 'bg-warning-500/20 border-warning-500/30', 
    text: 'text-warning-500', 
    icon: AlertTriangle,
    label: 'FLAGGED'
  },
  partial: { 
    bg: 'bg-warning-500/20 border-warning-500/30', 
    text: 'text-warning-500', 
    icon: AlertTriangle,
    label: 'PARTIAL'
  },
  error: { 
    bg: 'bg-slate-500/20 border-slate-500/30', 
    text: 'text-slate-400', 
    icon: Ban,
    label: 'ERROR'
  },
  'n/a': { 
    bg: 'bg-slate-500/20 border-slate-500/30', 
    text: 'text-slate-400', 
    icon: HelpCircle,
    label: 'N/A'
  },
};

const sizeClasses = {
  sm: 'px-2 py-0.5 text-xs gap-1',
  md: 'px-3 py-1 text-sm gap-1.5',
  lg: 'px-4 py-1.5 text-base gap-2',
};

const iconSizes = {
  sm: 'w-3 h-3',
  md: 'w-4 h-4',
  lg: 'w-5 h-5',
};

export default function StatusBadge({ status, size = 'md', showIcon = true }: StatusBadgeProps) {
  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <span 
      className={`
        inline-flex items-center font-semibold rounded-full border
        ${config.bg} ${config.text} ${sizeClasses[size]}
      `}
    >
      {showIcon && <Icon className={iconSizes[size]} />}
      {config.label}
    </span>
  );
}
