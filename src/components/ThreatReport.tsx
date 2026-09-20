import React from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, Bug } from 'lucide-react';
import { ReportFinding } from '../workers/heuristics.worker';

interface ThreatReportProps {
  findings: ReportFinding[];
  isAnalyzing: boolean;
}

export function ThreatReport({ findings, isAnalyzing }: ThreatReportProps) {
  if (isAnalyzing) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-400 animate-pulse">
        <Bug className="w-12 h-12 mb-4 opacity-50" />
        <p className="text-lg font-medium tracking-wide">Analyzing Engine Active...</p>
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-emerald-400">
        <ShieldCheck className="w-16 h-16 mb-4" />
        <h3 className="text-xl font-bold">No Threats Detected</h3>
        <p className="text-sm text-emerald-500/70 mt-2 text-center px-4">
          The sandboxed analysis did not find any known dark patterns or malicious signatures.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full overflow-y-auto pr-2 custom-scrollbar">
      <div className="mb-6 flex items-center gap-3 text-rose-500">
        <ShieldAlert className="w-8 h-8" />
        <h2 className="text-2xl font-bold">Threats Detected</h2>
      </div>

      <div className="flex flex-col gap-4">
        {findings.map((finding, idx) => (
          <div
            key={idx}
            className={`p-4 rounded-xl border ${
              finding.severity === 'critical'
                ? 'bg-rose-950/30 border-rose-500/50 text-rose-200'
                : finding.severity === 'high'
                ? 'bg-orange-950/30 border-orange-500/50 text-orange-200'
                : 'bg-amber-950/30 border-amber-500/50 text-amber-200'
            }`}
          >
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <h4 className="font-semibold capitalize mb-1">{finding.type.replace('_', ' ')}</h4>
                <p className="text-sm opacity-90">{finding.message}</p>
                {finding.snippet && (
                  <div className="mt-3 bg-black/40 p-2 rounded text-xs font-mono break-all border border-white/5">
                    {finding.snippet}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
