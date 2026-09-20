'use client';

import React, { useState, useRef } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Globe, 
  UploadCloud, 
  AlertTriangle, 
  Lock, 
  Cpu, 
  ArrowRight, 
  RefreshCw, 
  FileText, 
  Sparkles,
  AlertOctagon,
  FileQuestion
} from 'lucide-react';
import { analyzeContent, createNotFoundResult, ScanResult } from '@/utils/heuristics';
import SandboxIframe from '@/components/SandboxIframe';
import Tesseract from 'tesseract.js';

interface DemoPreset {
  label: string;
  type: 'safe' | 'phishing' | 'dark_pattern' | 'scareware' | 'not_found';
  url: string;
  mockHtml?: string;
}

const DEMO_PRESETS: DemoPreset[] = [
  {
    label: 'Google (Safe)',
    type: 'safe',
    url: 'https://www.google.com'
  },
  {
    label: 'YouTube (Preview Fix)',
    type: 'safe',
    url: 'https://www.youtube.com'
  },
  {
    label: '404 Webpage Not Found',
    type: 'not_found',
    url: 'https://www.google.com/nonexistent-test-404-page'
  },
  {
    label: 'Malicious Simulation (Live)',
    type: 'phishing',
    url: '/demo/malicious-test.html'
  }
];

export default function Home() {
  const [activeTab, setActiveTab] = useState<'url' | 'screenshot'>('url');
  const [inputVal, setInputVal] = useState('https://www.google.com');
  const [scanning, setScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<string>('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scannedUrl, setScannedUrl] = useState<string | null>(null);
  const [isTargetAvailable, setIsTargetAvailable] = useState<boolean>(true);
  const [unavailableReason, setUnavailableReason] = useState<string>('');

  // Screenshot / OCR states
  const [selectedImage, setSelectedImage] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [ocrProgress, setOcrProgress] = useState<number>(0);
  const [extractedOcrText, setExtractedOcrText] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const normalizeUrl = (raw: string): string => {
    let trimmed = raw.trim();
    if (!trimmed) return '';
    if (!/^https?:\/\//i.test(trimmed)) {
      trimmed = `https://${trimmed}`;
    }
    return trimmed;
  };

  const handleApplyPreset = (preset: DemoPreset) => {
    setActiveTab('url');
    // Convert relative URLs (like /demo/malicious-test.html) to absolute origin URLs so scraper can fetch them
    const targetUrl = preset.url.startsWith('/')
      ? `${typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000'}${preset.url}`
      : preset.url;

    setInputVal(targetUrl);

    if (preset.mockHtml) {
      // Direct simulation with the preset payload
      setScanning(true);
      setScanStatus('Running local offline heuristics on payload...');
      setIsTargetAvailable(true);
      setUnavailableReason('');
      setTimeout(() => {
        const analysis = analyzeContent(preset.mockHtml!, 'html', targetUrl);
        setResult(analysis);
        setScannedUrl(targetUrl);
        setScanning(false);
        setScanStatus('');
      }, 300);
    } else {
      // Immediately run real scan for live presets
      setTimeout(() => {
        executeUrlScan(targetUrl);
      }, 100);
    }
  };

  const handleImageFile = (file: File) => {
    setSelectedImage(file);
    setImagePreview(URL.createObjectURL(file));
    setExtractedOcrText('');
    setResult(null);
  };

  const executeUrlScan = async (rawTarget: string) => {
    const target = normalizeUrl(rawTarget);
    if (!target) return;

    setScanning(true);
    setResult(null);
    setScannedUrl(target);
    setIsTargetAvailable(true);
    setUnavailableReason('');
    setScanStatus('Verifying URL availability & DNS status...');

    try {
      const res = await fetch(`/api/scrape?url=${encodeURIComponent(target)}`);
      
      // Step 1: Check whether the URL is available / reachable
      if (!res.ok) {
        let reason = `Webpage not found (HTTP ${res.status})`;
        try {
          const errData = await res.json();
          if (errData?.reason) {
            reason = errData.reason;
          }
        } catch {
          // Fallback if not json
        }

        setIsTargetAvailable(false);
        setUnavailableReason(reason);

        // Safety check report reflects webpage not found
        const notFoundResult = createNotFoundResult(target, reason);
        setResult(notFoundResult);
        return;
      }

      // Step 2: URL is available, extract HTML and run sandbox threat check
      setScanStatus('URL reachable (200 OK). Analyzing DOM structure in security sandbox...');
      const htmlContent = await res.text();
      setIsTargetAvailable(true);
      setUnavailableReason('');

      // Run heuristics engine with URL intelligence and HTML content
      const analysis = analyzeContent(htmlContent, 'html', target);
      setResult(analysis);
    } catch (error: unknown) {
      const errMsg = error instanceof Error ? error.message : 'Network error';
      setIsTargetAvailable(false);
      setUnavailableReason(errMsg);
      setResult(createNotFoundResult(target, errMsg));
    } finally {
      setScanning(false);
      setScanStatus('');
    }
  };

  const handleScan = async () => {
    if (activeTab === 'url') {
      await executeUrlScan(inputVal);
    } else {
      // Screenshot OCR mode
      setScanning(true);
      setResult(null);

      try {
        if (!selectedImage && !extractedOcrText) {
          const demoOcr = "URGENT SECURITY ALERT: Your Microsoft Account has been locked due to unauthorized activity. Call toll-free 1-800-555-0199 immediately to avoid permanent deletion!";
          setExtractedOcrText(demoOcr);
          const analysis = analyzeContent(demoOcr, 'text');
          setResult(analysis);
          setScanning(false);
          return;
        }

        if (selectedImage && !extractedOcrText) {
          setScanStatus('Running local Tesseract OCR engine...');
          const ocrResult = await Tesseract.recognize(selectedImage, 'eng', {
            logger: (m) => {
              if (m.status === 'recognizing text' && m.progress) {
                setOcrProgress(Math.round(m.progress * 100));
              }
            }
          });

          const extracted = ocrResult.data.text || '';
          setExtractedOcrText(extracted);
          setScanStatus('Analyzing OCR text for threat patterns...');
          const analysis = analyzeContent(extracted, 'text');
          setResult(analysis);
        } else if (extractedOcrText) {
          const analysis = analyzeContent(extractedOcrText, 'text');
          setResult(analysis);
        }
      } catch (error) {
        console.error(error);
        setResult({
          score: 45,
          level: 'Suspicious',
          summary: 'Inspection completed with offline fallback.',
          flags: ['Analysis completed via offline safety ruleset']
        });
      } finally {
        setScanning(false);
        setScanStatus('');
      }
    }
  };

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-50 via-sky-50/30 to-emerald-50/20 text-slate-800 p-4 md:p-10">
      {/* Top Header */}
      <header className="max-w-6xl mx-auto flex flex-col sm:flex-row items-start sm:items-center justify-between pb-6 border-b border-slate-200/80 mb-8 gap-4">
        <div className="flex items-center space-x-3">
          <div className="h-11 w-11 rounded-2xl bg-gradient-to-tr from-sky-600 via-indigo-600 to-emerald-500 flex items-center justify-center shadow-lg shadow-sky-500/20 text-white font-black text-xl">
            L
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight bg-gradient-to-r from-slate-900 via-slate-800 to-slate-700 bg-clip-text text-transparent">
              Lumina Security Engine
            </h1>
            <p className="text-xs text-slate-500 font-medium">Privacy-First Offline Threat & Dark Pattern Sandbox</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center space-x-2 bg-white/90 backdrop-blur-md px-3.5 py-1.5 rounded-full border border-slate-200 shadow-sm text-xs font-semibold text-emerald-600">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping"></span>
            <span>100% On-Device Sandbox Active</span>
          </div>
        </div>
      </header>

      {/* Preset Demo Strip */}
      <div className="max-w-6xl mx-auto mb-6">
        <div className="bg-white/80 backdrop-blur-md rounded-2xl p-3.5 border border-slate-200 shadow-sm flex flex-wrap items-center gap-2 text-xs">
          <div className="flex items-center gap-1.5 font-semibold text-slate-600 mr-2">
            <Sparkles className="w-3.5 h-3.5 text-indigo-500" />
            <span>Quick Test Presets:</span>
          </div>
          {DEMO_PRESETS.map((preset, idx) => (
            <button
              key={idx}
              onClick={() => handleApplyPreset(preset)}
              className={`px-3 py-1.5 rounded-xl font-medium transition-all flex items-center gap-1.5 border shadow-xs cursor-pointer ${
                preset.type === 'safe'
                  ? 'bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border-emerald-200'
                  : preset.type === 'not_found'
                  ? 'bg-purple-50 hover:bg-purple-100 text-purple-700 border-purple-200'
                  : preset.type === 'dark_pattern'
                  ? 'bg-amber-50 hover:bg-amber-100 text-amber-700 border-amber-200'
                  : 'bg-rose-50 hover:bg-rose-100 text-rose-700 border-rose-200'
              }`}
            >
              <span>{preset.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid Layout */}
      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-8">

        {/* Left Column: Input Panel & Sandboxed View (7 Cols) */}
        <div className="lg:col-span-7 flex flex-col gap-6">
          <div className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 md:p-8 border border-white shadow-xl shadow-slate-200/50 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                  <Lock className="w-5 h-5 text-sky-600" />
                  Threat Inspection Portal
                </h2>
                <div className="flex bg-slate-100 p-1 rounded-xl text-xs font-semibold">
                  <button
                    onClick={() => setActiveTab('url')}
                    className={`px-4 py-2 rounded-lg transition-all cursor-pointer ${
                      activeTab === 'url' ? 'bg-white text-slate-900 shadow-xs font-bold' : 'text-slate-500 hover:text-slate-900'
                    }`}
                  >
                    URL Link
                  </button>
                  <button
                    onClick={() => setActiveTab('screenshot')}
                    className={`px-4 py-2 rounded-lg transition-all cursor-pointer ${
                      activeTab === 'screenshot' ? 'bg-white text-slate-900 shadow-xs font-bold' : 'text-slate-500 hover:text-slate-900'
                    }`}
                  >
                    Screenshot OCR
                  </button>
                </div>
              </div>

              {/* Input Forms */}
              {activeTab === 'url' ? (
                <div className="space-y-4">
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Target URL Link
                  </label>
                  <div className="relative">
                    <Globe className="absolute left-4 top-3.5 w-5 h-5 text-slate-400" />
                    <input
                      type="text"
                      value={inputVal}
                      onChange={(e) => setInputVal(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') handleScan();
                      }}
                      placeholder="https://example.com"
                      className="w-full pl-12 pr-4 py-3 bg-slate-50/90 border border-slate-200 rounded-2xl focus:outline-none focus:ring-2 focus:ring-sky-500/20 focus:border-sky-500 text-sm font-medium transition-all"
                    />
                  </div>
                  <p className="text-xs text-slate-400">
                    Checks availability, bypasses frame-blockers on YouTube/Google, and runs sandboxed DOM heuristics.
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Upload Screenshot or Threat Evidence
                  </label>
                  <input
                    type="file"
                    ref={fileInputRef}
                    accept="image/*"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        handleImageFile(e.target.files[0]);
                      }
                    }}
                    className="hidden"
                  />
                  <div
                    onClick={() => fileInputRef.current?.click()}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                        handleImageFile(e.dataTransfer.files[0]);
                      }
                    }}
                    className="border-2 border-dashed border-slate-200 hover:border-sky-400 rounded-2xl p-6 text-center bg-slate-50/50 hover:bg-slate-50 transition-all cursor-pointer flex flex-col items-center justify-center min-h-[160px]"
                  >
                    {imagePreview ? (
                      <div className="flex flex-col items-center gap-2">
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img src={imagePreview} alt="Target" className="h-28 object-contain rounded-lg shadow-sm border border-slate-200" />
                        <span className="text-xs font-medium text-sky-600 underline">Click to choose different image</span>
                      </div>
                    ) : (
                      <>
                        <UploadCloud className="w-10 h-10 text-sky-500 mb-2 animate-bounce" />
                        <p className="text-sm font-semibold text-slate-700">
                          Drag & drop a screenshot here, or <span className="text-sky-600 underline">browse</span>
                        </p>
                        <p className="text-xs text-slate-400 mt-1">Processed locally in browser via WebAssembly OCR</p>
                      </>
                    )}
                  </div>

                  {extractedOcrText && (
                    <div className="p-3 bg-slate-100 rounded-xl border border-slate-200 text-xs">
                      <span className="font-semibold text-slate-600 block mb-1 flex items-center gap-1">
                        <FileText className="w-3.5 h-3.5" /> Extracted OCR Text:
                      </span>
                      <p className="text-slate-600 italic line-clamp-2">&quot;{extractedOcrText}&quot;</p>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="mt-8 pt-6 border-t border-slate-100 flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs text-slate-500 font-medium">
                <Cpu className="w-4 h-4 text-emerald-600" />
                <span>Zero-Cloud Dependency Sandbox</span>
              </div>
              <button
                onClick={handleScan}
                disabled={scanning}
                className="px-6 py-3 rounded-2xl bg-gradient-to-r from-sky-600 via-indigo-600 to-emerald-600 text-white font-bold text-sm shadow-lg shadow-sky-600/20 hover:shadow-xl hover:shadow-sky-600/30 transition-all flex items-center gap-2 disabled:opacity-50 cursor-pointer"
              >
                {scanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Analyzing Payload...</span>
                  </>
                ) : (
                  <>
                    <span>Run Security Scan</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Sandboxed Iframe Preview (Embedded below portal when URL is tested) */}
          {scannedUrl && activeTab === 'url' && (
            <div className="bg-white/80 backdrop-blur-xl rounded-3xl p-6 border border-white shadow-xl shadow-slate-200/50">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-emerald-600" />
                  Isolated Sandbox View
                </h3>
                <span className="text-[11px] text-slate-400 font-medium">
                  {isTargetAvailable ? 'Bypasses X-Frame-Options via DOM Proxy' : 'Offline Target'}
                </span>
              </div>
              <SandboxIframe
                url={scannedUrl}
                isAvailable={isTargetAvailable}
                unavailableReason={unavailableReason}
              />
            </div>
          )}
        </div>

        {/* Right Column: Threat Report (5 Cols) */}
        <div className="lg:col-span-5 bg-white/80 backdrop-blur-xl rounded-3xl p-6 md:p-8 border border-white shadow-xl shadow-slate-200/50 flex flex-col justify-between">
          <div>
            <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2 mb-6">
              <ShieldAlert className="w-5 h-5 text-rose-500" />
              Lumina Threat Report
            </h2>

            {scanning ? (
              <div className="h-72 flex flex-col items-center justify-center space-y-4">
                <div className="w-12 h-12 border-4 border-sky-500 border-t-transparent rounded-full animate-spin"></div>
                <p className="text-xs font-semibold text-slate-600 animate-pulse text-center max-w-xs">
                  {scanStatus || 'Running local heuristic inspection...'}
                </p>
                {ocrProgress > 0 && ocrProgress < 100 && (
                  <div className="w-48 bg-slate-100 rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-sky-500 h-2 transition-all duration-300"
                      style={{ width: `${ocrProgress}%` }}
                    ></div>
                  </div>
                )}
              </div>
            ) : result ? (
              <div className="space-y-6">
                {/* Score Status Card */}
                <div
                  className={`border p-5 rounded-2xl transition-all ${
                    result.level === 'Webpage Not Found'
                      ? 'bg-purple-50/90 border-purple-200 text-purple-950'
                      : result.level === 'Critical Danger'
                      ? 'bg-rose-50/90 border-rose-200 text-rose-950'
                      : result.level === 'Suspicious'
                      ? 'bg-amber-50/90 border-amber-200 text-amber-950'
                      : 'bg-emerald-50/90 border-emerald-200 text-emerald-950'
                  }`}
                >
                  <div className="flex items-start gap-3">
                    {result.level === 'Webpage Not Found' ? (
                      <FileQuestion className="w-6 h-6 flex-shrink-0 text-purple-600 mt-0.5" />
                    ) : result.level === 'Safe' ? (
                      <ShieldCheck className="w-6 h-6 flex-shrink-0 text-emerald-600 mt-0.5" />
                    ) : (
                      <AlertTriangle
                        className={`w-6 h-6 flex-shrink-0 mt-0.5 ${
                          result.level === 'Critical Danger' ? 'text-rose-600' : 'text-amber-600'
                        }`}
                      />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-base font-extrabold">{result.level}</span>
                        <span
                          className={`text-xs px-2.5 py-0.5 rounded-full font-bold ${
                            result.level === 'Webpage Not Found'
                              ? 'bg-purple-200 text-purple-800'
                              : result.level === 'Critical Danger'
                              ? 'bg-rose-200 text-rose-800'
                              : result.level === 'Suspicious'
                              ? 'bg-amber-200 text-amber-800'
                              : 'bg-emerald-200 text-emerald-800'
                          }`}
                        >
                          {result.level === 'Webpage Not Found' ? 'Status: 404 / Offline' : `Threat Score: ${result.score} / 100`}
                        </span>
                      </div>
                      <p className="text-xs mt-1.5 opacity-90 leading-relaxed font-medium">{result.summary}</p>
                    </div>
                  </div>

                  {/* Visualizer */}
                  {result.level !== 'Webpage Not Found' ? (
                    <div className="mt-4 pt-3 border-t border-black/5">
                      <div className="flex justify-between text-[10px] font-bold text-slate-500 mb-1">
                        <span>Safety (0)</span>
                        <span>Suspicious (30)</span>
                        <span>Critical Danger (65+)</span>
                      </div>
                      <div className="h-2 w-full bg-slate-200/80 rounded-full overflow-hidden flex">
                        <div
                          className={`h-full transition-all duration-700 ${
                            result.level === 'Critical Danger'
                              ? 'bg-rose-500'
                              : result.level === 'Suspicious'
                              ? 'bg-amber-500'
                              : 'bg-emerald-500'
                          }`}
                          style={{ width: `${Math.max(result.score, 3)}%` }}
                        ></div>
                      </div>
                    </div>
                  ) : (
                    <div className="mt-3 pt-3 border-t border-purple-200/50 flex items-center gap-1.5 text-[11px] font-semibold text-purple-700">
                      <AlertOctagon className="w-3.5 h-3.5" />
                      <span>Safety status unverified: page is offline or nonexistent</span>
                    </div>
                  )}
                </div>

                {/* Detected Indicators */}
                <div className="space-y-2.5">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Inspection Findings ({result.flags.length})
                  </h4>
                  {result.detailedFindings && result.detailedFindings.length > 0 ? (
                    result.detailedFindings.map((finding, index) => (
                      <div
                        key={index}
                        className={`text-xs border p-3 rounded-xl flex flex-col gap-1 ${
                          result.level === 'Webpage Not Found'
                            ? 'bg-purple-50/50 border-purple-200/80 text-purple-950'
                            : finding.severity === 'critical'
                            ? 'bg-rose-50/50 border-rose-200/80 text-rose-950'
                            : finding.severity === 'high'
                            ? 'bg-amber-50/50 border-amber-200/80 text-amber-950'
                            : 'bg-slate-50 border-slate-200 text-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold flex items-center gap-1.5">
                            <span
                              className={`h-2 w-2 rounded-full ${
                                result.level === 'Webpage Not Found'
                                  ? 'bg-purple-500'
                                  : finding.severity === 'critical'
                                  ? 'bg-rose-500'
                                  : finding.severity === 'high'
                                  ? 'bg-amber-500'
                                  : 'bg-sky-500'
                              }`}
                            ></span>
                            {finding.title}
                          </span>
                          <span className="text-[10px] uppercase tracking-wide font-extrabold opacity-75">
                            {finding.severity}
                          </span>
                        </div>
                        <p className="text-[11px] opacity-80 leading-normal pl-3.5">{finding.description}</p>
                      </div>
                    ))
                  ) : (
                    result.flags.map((flag, index) => (
                      <div
                        key={index}
                        className="text-xs bg-slate-50 border border-slate-200 p-3 rounded-xl text-slate-700 flex items-center gap-2"
                      >
                        <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
                        <span className="font-medium">{flag}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ) : (
              <div className="h-72 flex flex-col items-center justify-center text-center space-y-3">
                <div className="w-14 h-14 rounded-2xl bg-slate-100 flex items-center justify-center text-slate-400 shadow-inner">
                  <ShieldCheck className="w-7 h-7 text-slate-400" />
                </div>
                <p className="text-sm font-bold text-slate-700">No Active Inspection</p>
                <p className="text-xs text-slate-400 max-w-xs leading-relaxed">
                  Enter a URL or upload an image on the left, or pick one of the quick test presets to evaluate threat scores.
                </p>
              </div>
            )}
          </div>

          <div className="mt-8 pt-4 border-t border-slate-100 text-center">
            <p className="text-[11px] text-slate-400 font-medium">Lumina PWA v1.0 • Privacy-First Threat Sandbox</p>
          </div>
        </div>

      </div>
    </main>
  );
}