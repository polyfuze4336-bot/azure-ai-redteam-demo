interface PanelProps {
  title?: string;
  subtitle?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  headerAction?: React.ReactNode;
}

export default function Panel({ title, subtitle, icon, children, className = '', headerAction }: PanelProps) {
  const hasHeader = title || subtitle || icon || headerAction;
  
  return (
    <div className={`glass-panel flex flex-col ${className}`}>
      {/* Header - only render if there's content */}
      {hasHeader && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700/50">
          <div className="flex items-center gap-2">
            {icon && <span className="text-azure-500">{icon}</span>}
            {(title || subtitle) && (
              <div>
                {title && <h2 className="text-sm font-semibold text-white">{title}</h2>}
                {subtitle && <p className="text-xs text-slate-500">{subtitle}</p>}
              </div>
            )}
          </div>
          {headerAction}
        </div>
      )}
      
      {/* Content */}
      <div className={`flex-1 ${hasHeader ? 'p-4' : ''} overflow-auto`}>
        {children}
      </div>
    </div>
  );
}
