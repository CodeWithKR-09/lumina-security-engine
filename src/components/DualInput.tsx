import React, { useState, useCallback } from 'react';
import { UploadCloud, Link as LinkIcon } from 'lucide-react';
import clsx from 'clsx';

interface DualInputProps {
  onUrlSubmit: (url: string) => void;
  onImageDrop: (file: File) => void;
}

export function DualInput({ onUrlSubmit, onImageDrop }: DualInputProps) {
  const [url, setUrl] = useState('');
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        onImageDrop(e.dataTransfer.files[0]);
      }
    },
    [onImageDrop]
  );

  const handleUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url) {
      onUrlSubmit(url);
    }
  };

  return (
    <div className="flex flex-col gap-6 w-full max-w-2xl mx-auto mt-10">
      <div className="text-center mb-4">
        <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-indigo-400 to-cyan-400">
          Lumina Security Engine
        </h1>
        <p className="text-slate-400 mt-2">Local Dark Pattern & Threat Sandbox</p>
      </div>

      <form onSubmit={handleUrlSubmit} className="relative group">
        <div className="absolute inset-y-0 left-0 flex items-center pl-4 pointer-events-none text-slate-500 group-focus-within:text-cyan-400 transition-colors">
          <LinkIcon className="w-5 h-5" />
        </div>
        <input
          type="url"
          required
          placeholder="Paste a suspicious URL to sandbox..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full bg-slate-900/50 border border-slate-700/50 text-slate-100 text-sm rounded-2xl focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50 block p-4 pl-12 transition-all outline-none"
        />
        <button
          type="submit"
          className="absolute right-2 top-2 bottom-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl px-6 font-medium transition-colors"
        >
          Analyze
        </button>
      </form>

      <div className="flex items-center gap-4 text-slate-600 font-medium">
        <div className="h-px bg-slate-800 flex-1"></div>
        OR
        <div className="h-px bg-slate-800 flex-1"></div>
      </div>

      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={clsx(
          "relative flex flex-col items-center justify-center w-full h-64 border-2 border-dashed rounded-3xl transition-all cursor-pointer overflow-hidden",
          isDragging
            ? "border-indigo-500 bg-indigo-500/10"
            : "border-slate-700 hover:border-slate-500 hover:bg-slate-800/30 bg-slate-900/20"
        )}
      >
        <div className="flex flex-col items-center justify-center pt-5 pb-6 pointer-events-none">
          <UploadCloud
            className={clsx(
              "w-12 h-12 mb-4 transition-colors",
              isDragging ? "text-indigo-400" : "text-slate-400"
            )}
          />
          <p className="mb-2 text-sm text-slate-300">
            <span className="font-semibold">Click to upload</span> or drag and drop
          </p>
          <p className="text-xs text-slate-500">Analyze screenshots for hidden text & social proof</p>
        </div>
        <input
          type="file"
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          accept="image/*"
          onChange={(e) => {
            if (e.target.files && e.target.files.length > 0) {
              onImageDrop(e.target.files[0]);
            }
          }}
        />
      </div>
    </div>
  );
}
