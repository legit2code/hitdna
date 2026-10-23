import React, { useState } from 'react';
import { Copy, Check, ChevronDown, ChevronRight } from 'lucide-react';

interface DiagnosticJsonDrawerProps {
  title: string;
  data: any;
  defaultExpanded?: boolean;
}

export const DiagnosticJsonDrawer: React.FC<DiagnosticJsonDrawerProps> = ({
  title,
  data,
  defaultExpanded = true,
}) => {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [copied, setCopied] = useState(false);

  const jsonString = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950/80 font-mono text-xs">
      <div className="flex items-center justify-between px-3 py-2 bg-slate-900 border-b border-slate-800">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center space-x-2 text-slate-300 hover:text-cyan-300 font-semibold text-xs text-left"
        >
          {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          <span>{title}</span>
        </button>
        <button
          onClick={handleCopy}
          className="flex items-center space-x-1 px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] transition-colors"
          title="Copy raw JSON"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-emerald-400" />
              <span className="text-emerald-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3 text-slate-400" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      {expanded && (
        <pre className="p-3 text-[11px] leading-relaxed text-slate-300 overflow-x-auto max-h-80 select-all font-mono whitespace-pre-wrap">
          {jsonString}
        </pre>
      )}
    </div>
  );
};
