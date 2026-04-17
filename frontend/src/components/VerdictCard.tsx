import { VerdictDetail } from '../types';
import StatusBadge from './StatusBadge';

interface VerdictCardProps {
  title: string;
  icon: React.ReactNode;
  verdict: VerdictDetail;
}

export default function VerdictCard({ title, icon, verdict }: VerdictCardProps) {
  const confidencePercent = Math.round(verdict.confidence * 100);
  
  return (
    <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-sm font-medium text-slate-300">{title}</span>
        </div>
        <StatusBadge status={verdict.result} size="sm" />
      </div>
      
      <div className="space-y-2">
        {/* Confidence Bar */}
        <div>
          <div className="flex justify-between text-xs mb-1">
            <span className="text-slate-500">Confidence</span>
            <span className="text-white font-medium">{confidencePercent}%</span>
          </div>
          <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
            <div 
              className="h-full bg-azure-500 rounded-full transition-all duration-500"
              style={{ width: `${confidencePercent}%` }}
            />
          </div>
        </div>
        
        {/* Reason */}
        <p className="text-xs text-slate-400 leading-relaxed">
          {verdict.reason}
        </p>
      </div>
    </div>
  );
}
