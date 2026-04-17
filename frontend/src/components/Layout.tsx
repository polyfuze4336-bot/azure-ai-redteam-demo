import { Outlet, NavLink } from 'react-router-dom';
import { Shield, Crosshair, History, GitCompare, Activity, Cloud } from 'lucide-react';
import SummaryBar from './SummaryBar';

export default function Layout() {
  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-200 ${
      isActive
        ? 'bg-azure-500 text-white shadow-lg shadow-azure-500/30'
        : 'text-slate-300 hover:bg-slate-800 hover:text-white'
    }`;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {/* Top Navigation */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-[1800px] mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-azure-500" />
                <Crosshair className="w-4 h-4 text-danger-500 absolute -bottom-1 -right-1" />
              </div>
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-azure-500 to-cyan-400 bg-clip-text text-transparent">
                  Azure AI Red Team Console
                </h1>
                <p className="text-xs text-slate-500">Adversarial Testing Platform</p>
              </div>
            </div>

            {/* Navigation */}
            <nav className="flex items-center gap-2">
              <NavLink to="/" className={navLinkClass}>
                <Crosshair className="w-4 h-4" />
                Attack Console
              </NavLink>
              <NavLink to="/history" className={navLinkClass}>
                <History className="w-4 h-4" />
                Campaign History
              </NavLink>
              <NavLink to="/compare" className={navLinkClass}>
                <GitCompare className="w-4 h-4" />
                Comparison
              </NavLink>
            </nav>

            {/* Status & Resource Context */}
            <div className="flex items-center gap-4">
              {/* Foundry Resource Context */}
              <div className="flex items-center gap-2 px-3 py-1.5 bg-azure-500/10 border border-azure-500/30 rounded-lg">
                <Cloud className="w-4 h-4 text-azure-400" />
                <div className="flex items-center gap-1 text-xs">
                  <span className="text-slate-400">Resource:</span>
                  <span className="text-azure-400 font-medium">mkhalib-4370-resource</span>
                </div>
              </div>
              
              {/* System Status */}
              <div className="flex items-center gap-2 text-sm">
                <Activity className="w-4 h-4 text-success-500 animate-pulse" />
                <span className="text-slate-400">Online</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Summary Bar */}
      <SummaryBar />

      {/* Main Content */}
      <main className="max-w-[1800px] mx-auto px-6 py-6">
        <Outlet />
      </main>
    </div>
  );
}
