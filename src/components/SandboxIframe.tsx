'use client';

import React, { useState } from 'react';
import { Shield, RefreshCw, ExternalLink, AlertOctagon, Layers, Globe } from 'lucide-react';

interface SandboxIframeProps {
  url: string;
  isAvailable?: boolean;
  unavailableReason?: string;
}

export function SandboxIframe({ url, isAvailable = true, unavailableReason }: SandboxIframeProps) {
  const [mode, setMode] = useState<'proxied' | 'direct'>('proxied');
  const [refreshKey, setRefreshKey] = useState(0);

  if (!url) return null;

  // Dedicated preview endpoint strips X-Frame-Options and injects <base href> so sites like YouTube render smoothly
  const previewSrc =
    mode === 'proxied'
      ? `/api/preview?url=${encodeURIComponent(url)}&v=${refreshKey}`
      : url;

  return (
    <div className="w-full h-96 rounded-2xl border border-slate-200 overflow-hidden bg-white shadow-inner flex flex-col transition-all">
      {/* Sandbox Toolbar */}
      <div className="bg-slate-100/90 px-4 py-2.5 border-b border-slate-200 flex flex-wrap items-center justify-between text-xs text-slate-600 gap-2">
        <div className="flex items-center gap-2 max-w-sm truncate">
          <Shield className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
          <span className="font-semibold text-slate-700 truncate">{url}</span>
          <span className="bg-emerald-100 text-emerald-800 text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0">
            Isolated Sandbox
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Mode Switcher */}
          <div className="flex bg-slate-200/80 p-0.5 rounded-lg text-[11px] font-medium">
            <button
              onClick={() => setMode('proxied')}
              title="Renders through Lumina proxy to bypass X-Frame-Options on YouTube, Google, etc."
              className={`px-2 py-1 rounded-md transition-all flex items-center gap-1 ${
                mode === 'proxied'
                  ? 'bg-white text-slate-800 font-bold shadow-xs'
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              <Layers className="w-3 h-3 text-sky-600" />
              <span>DOM Proxy (All Sites)</span>
            </button>
            <button
              onClick={() => setMode('direct')}
              title="Loads direct iframe (may be blocked by sites sending X-Frame-Options: SAMEORIGIN)"
              className={`px-2 py-1 rounded-md transition-all flex items-center gap-1 ${
                mode === 'direct'
                  ? 'bg-white text-slate-800 font-bold shadow-xs'
                  : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              <Globe className="w-3 h-3 text-slate-500" />
              <span>Direct Frame</span>
            </button>
          </div>

          <button
            onClick={() => setRefreshKey((k) => k + 1)}
            title="Reload sandbox preview"
            className="p-1 text-slate-500 hover:text-slate-800 rounded-md hover:bg-slate-200 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>

          <a
            href={url}
            target="_blank"
            rel="noreferrer"
            title="Open URL in new tab"
            className="p-1 text-slate-500 hover:text-slate-800 rounded-md hover:bg-slate-200 transition-colors flex items-center"
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      </div>

      {/* Frame Container or Unavailable Screen */}
      <div className="relative flex-1 bg-slate-50">
        {!isAvailable ? (
          <div className="w-full h-full flex flex-col items-center justify-center p-6 text-center bg-slate-50">
            <div className="w-12 h-12 rounded-2xl bg-rose-50 text-rose-500 flex items-center justify-center mb-3 shadow-inner">
              <AlertOctagon className="w-6 h-6" />
            </div>
            <h4 className="text-sm font-bold text-slate-800 mb-1">Webpage Not Available</h4>
            <p className="text-xs text-rose-600 font-medium max-w-sm mb-2">
              {unavailableReason || 'Destination returned HTTP 404 or domain does not resolve.'}
            </p>
            <p className="text-[11px] text-slate-400 max-w-xs leading-relaxed">
              Sandbox preview is disabled because the destination host is offline or the requested resource does not exist.
            </p>
          </div>
        ) : (
          <iframe
            key={previewSrc}
            src={previewSrc}
            title="Lumina Threat Sandbox Preview"
            className="w-full h-full border-0 bg-white"
            // Sandbox protects parent window from breakout or tampering
            sandbox="allow-same-origin allow-forms allow-scripts allow-popups"
          />
        )}
      </div>
    </div>
  );
}

export default SandboxIframe;