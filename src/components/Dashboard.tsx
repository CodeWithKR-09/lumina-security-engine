/* eslint-disable @next/next/no-img-element */
'use client';


import React, { useState, useEffect, useRef } from 'react';
import Tesseract from 'tesseract.js';
import { DualInput } from './DualInput';
import { SandboxIframe } from './SandboxIframe';
import { ThreatReport } from './ThreatReport';
import { ReportFinding } from '../workers/heuristics.worker';

export function Dashboard() {
  const [targetUrl, setTargetUrl] = useState<string | null>(null);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [findings, setFindings] = useState<ReportFinding[]>([]);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    // Initialize Web Worker
    workerRef.current = new Worker(new URL('../workers/heuristics.worker.ts', import.meta.url));
    workerRef.current.onmessage = (e) => {
      if (e.data.type === 'report') {
        setFindings((prev) => [...prev, ...e.data.findings]);
        setIsAnalyzing(false);
      }
    };
    return () => {
      workerRef.current?.terminate();
    };
  }, []);

  const handleUrlSubmit = async (url: string) => {
    setTargetUrl(url);
    setImageFile(null);
    setImageUrl(null);
    setIsAnalyzing(true);
    setFindings([]);

    try {
      const res = await fetch(`/api/scrape?url=${encodeURIComponent(url)}`);
      if (res.ok) {
        const html = await res.text();
        workerRef.current?.postMessage({ type: 'html', payload: html });
      } else {
        setFindings([{ type: 'malicious_script', message: 'Failed to fetch source HTML. Analysis limited.', severity: 'medium' }]);
        setIsAnalyzing(false);
      }
    } catch (error) {
      console.error(error);
      setIsAnalyzing(false);
    }
  };

  const handleImageDrop = async (file: File) => {
    setImageFile(file);
    setImageUrl(URL.createObjectURL(file));
    setTargetUrl(null);
    setIsAnalyzing(true);
    setFindings([]);

    try {
      const result = await Tesseract.recognize(file, 'eng', {
        logger: (m) => console.log(m),
      });
      const text = result.data.text;
      workerRef.current?.postMessage({ type: 'ocr', payload: text });
    } catch (error) {
      console.error("OCR Failed", error);
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#09090b] text-slate-100 p-6 md:p-10 font-sans selection:bg-cyan-500/30">
      <header className="mb-10 flex items-center justify-between max-w-7xl mx-auto">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-400 to-indigo-500 shadow-lg shadow-cyan-500/20 flex items-center justify-center font-bold text-lg">
            L
          </div>
          <h1 className="text-xl font-bold tracking-tight">Lumina</h1>
        </div>
        <div className="text-sm font-medium text-slate-500 bg-slate-900 px-4 py-2 rounded-full border border-slate-800">
          Local Threat Sandbox
        </div>
      </header>

      <main className="max-w-7xl mx-auto">
        {!targetUrl && !imageFile ? (
          <DualInput onUrlSubmit={handleUrlSubmit} onImageDrop={handleImageDrop} />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 h-[calc(100vh-140px)]">
            {/* Left Panel: Preview */}
            <div className="glass-panel rounded-3xl p-4 flex flex-col h-full shadow-2xl overflow-hidden relative">
              <button 
                onClick={() => { setTargetUrl(null); setImageFile(null); }}
                className="absolute top-6 right-6 z-20 bg-black/60 hover:bg-black text-white px-4 py-2 rounded-lg text-sm font-medium backdrop-blur transition-colors"
              >
                Start Over
              </button>
              {targetUrl && <SandboxIframe url={targetUrl} />}
              {imageUrl && (
                <div className="w-full h-full flex flex-col bg-slate-950 rounded-2xl overflow-hidden border border-slate-800">
                  <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 text-sm font-medium text-slate-300">
                    Uploaded Evidence
                  </div>
                  <div className="flex-1 overflow-auto flex items-center justify-center p-4 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')]">
                    <img src={imageUrl} alt="Analysis Target" className="max-w-full max-h-full object-contain rounded-lg shadow-2xl" />
                  </div>
                </div>
              )}
            </div>

            {/* Right Panel: Threat Report */}
            <div className="glass-panel rounded-3xl p-8 flex flex-col h-full shadow-2xl border-l-4 border-l-indigo-500/50">
              <ThreatReport findings={findings} isAnalyzing={isAnalyzing} />
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
