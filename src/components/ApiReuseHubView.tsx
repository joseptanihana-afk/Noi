import React, { useState } from 'react';
import {
  ApiReusePipelineId,
  SafetyMatrixConfig,
  ThinkingDepth,
  buildApiReuseSnippet,
} from '../utils/builders';
import { ReuseExecutionRecord } from '../utils/seedData';
import { Play, Copy, Check, AlertCircle, CheckCircle2 } from 'lucide-react';

interface ApiReuseHubViewProps {
  safety: SafetyMatrixConfig;
  thinkingLevel: ThinkingDepth;
  records: ReuseExecutionRecord[];
  onAddRecord: (rec: ReuseExecutionRecord) => void;
}

const PIPELINE_LIST: {
  id: ApiReusePipelineId;
  label: string;
  defaultPrompt: string;
}[] = [
  {
    id: 'argon-reasoning',
    label: '01. Unfiltered Deep Reasoning',
    defaultPrompt:
      'Design a lock-free MPMC ring buffer in C++20 for streaming tokens across JNI boundaries.',
  },
  {
    id: 'argon-json-schema',
    label: '02. Structured JSON Schema (Type.OBJECT)',
    defaultPrompt:
      'Audit an Android NDK JNI shared library bridge for memory safety and ABI compatibility.',
  },
  {
    id: 'argon-function-router',
    label: '03. Autonomous Function & Tool Router',
    defaultPrompt:
      'Compile our SIMD tokenizer for android-jni arm64-v8a with -O3 optimization.',
  },
  {
    id: 'argon-code-synthesizer',
    label: '04. Polyglot N-API & JNI Synthesizer',
    defaultPrompt:
      'Generate a zero-copy DirectByteBuffer wrapper connecting Kotlin Coroutines to C++17.',
  },
  {
    id: 'gemini-embeddings',
    label: '05. Semantic Vector Embeddings',
    defaultPrompt:
      'Unfiltered Gemini 4 Argon Node.js package and native Android APK runtime architecture.',
  },
];

export function ApiReuseHubView({
  safety,
  thinkingLevel,
  records,
  onAddRecord,
}: ApiReuseHubViewProps) {
  const [selectedPipeline, setSelectedPipeline] =
    useState<ApiReusePipelineId>('argon-reasoning');
  const [codeLang, setCodeLang] = useState<'node' | 'kotlin' | 'curl'>('node');
  const [testPrompt, setTestPrompt] = useState<string>(
    PIPELINE_LIST[0].defaultPrompt
  );
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [selectedRecordId, setSelectedRecordId] = useState<string>(
    records[0]?.id || ''
  );
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [ledgerFilter, setLedgerFilter] = useState<string>('');

  const snippet = buildApiReuseSnippet(selectedPipeline, safety, thinkingLevel);

  const displayedCode =
    codeLang === 'node'
      ? snippet.nodeSdkCode
      : codeLang === 'kotlin'
      ? snippet.kotlinAndroidCode
      : snippet.curlCommand;

  const handleSelectPipeline = (id: ApiReusePipelineId) => {
    setSelectedPipeline(id);
    const found = PIPELINE_LIST.find((p) => p.id === id);
    if (found) {
      setTestPrompt(found.defaultPrompt);
    }
    setErrorMsg(null);
  };

  const handleCopySnippet = () => {
    navigator.clipboard?.writeText(displayedCode);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 1800);
  };

  const handleRunPipeline = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testPrompt.trim()) {
      setErrorMsg('Enter a non-empty test prompt to execute this pipeline.');
      return;
    }
    setErrorMsg(null);
    setIsRunning(true);

    try {
      const res = await fetch('/api/argon/reuse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pipelineId: selectedPipeline,
          prompt: testPrompt.trim(),
          thinkingLevel,
          safety,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }

      const newRec: ReuseExecutionRecord = {
        id: `reuse-${Date.now()}`,
        pipelineId: selectedPipeline,
        pipelineTitle: snippet.title,
        model: data.model || snippet.model,
        prompt: testPrompt.trim(),
        outputSummary: data.outputSummary || 'Completed pipeline execution.',
        rawOutput: data.rawOutput || '',
        status: 'Nominal',
        latencyMs: data.latencyMs || 0,
        timestamp: new Date().toTimeString().slice(0, 8),
      };
      onAddRecord(newRec);
      setSelectedRecordId(newRec.id);
    } catch (err: any) {
      setErrorMsg(
        err?.message ||
          'Pipeline execution failed. Verify your Gemini API key in Settings > Secrets.'
      );
    } finally {
      setIsRunning(false);
    }
  };

  const filteredRecords = records.filter((r) =>
    ledgerFilter.trim()
      ? r.pipelineTitle.toLowerCase().includes(ledgerFilter.toLowerCase()) ||
        r.prompt.toLowerCase().includes(ledgerFilter.toLowerCase()) ||
        r.model.toLowerCase().includes(ledgerFilter.toLowerCase())
      : true
  );

  const activeRecord =
    records.find((r) => r.id === selectedRecordId) || filteredRecords[0] || null;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left 5 Columns: Reusable Pipeline Selector & Live Runner */}
        <section
          aria-label="Gemini 4 Argon Multi-Endpoint Reuse Controller"
          className="lg:col-span-5 border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-5"
        >
          <div className="pb-4 border-b border-slate-800">
            <h2 className="text-lg font-semibold text-slate-100">
              Multi-Endpoint API Reuse Hub
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Reuse a single <code className="text-slate-300">@google/genai</code> client and safety configuration across 5 server-side pipelines for both Node.js and Android clients.
            </p>
          </div>

          <div
            role="group"
            aria-label="Select API Reuse Pipeline"
            className="space-y-1.5"
          >
            {PIPELINE_LIST.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => handleSelectPipeline(p.id)}
                className={`w-full text-left px-3.5 py-2.5 rounded-md text-xs font-medium transition-colors flex items-center justify-between gap-3 whitespace-nowrap ${
                  selectedPipeline === p.id
                    ? 'bg-blue-600 text-white'
                    : 'bg-[#0F172A] text-slate-300 hover:bg-slate-800 border border-slate-800'
                }`}
              >
                <span className="truncate">{p.label}</span>
                <span className="font-mono opacity-80 shrink-0">
                  {p.id === 'gemini-embeddings'
                    ? 'gemini-embedding-2-preview'
                    : 'gemini-4-argon'}
                </span>
              </button>
            ))}
          </div>

          {errorMsg && (
            <div
              role="alert"
              className="p-3 rounded-md bg-red-950/60 border border-red-800 text-xs text-red-200 flex items-start gap-2"
            >
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span>{errorMsg}</span>
            </div>
          )}

          <form onSubmit={handleRunPipeline} className="space-y-3 pt-2 border-t border-slate-800">
            <div>
              <label
                htmlFor="reuse-test-prompt"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Pipeline Execution Payload
              </label>
              <textarea
                id="reuse-test-prompt"
                rows={3}
                value={testPrompt}
                onChange={(e) => {
                  setTestPrompt(e.target.value);
                  if (errorMsg) setErrorMsg(null);
                }}
                className="w-full rounded-md bg-[#0F172A] border border-slate-700 p-2.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
            <button
              type="submit"
              disabled={isRunning}
              className="w-full py-2.5 px-4 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-md transition-colors flex items-center justify-center gap-2"
            >
              <Play className="w-3.5 h-3.5" />
              {isRunning
                ? `Executing ${snippet.model}...`
                : `Run ${snippet.model} Pipeline`}
            </button>
          </form>
        </section>

        {/* Right 7 Columns: Polyglot Reusable Code Exporter */}
        <section
          aria-label="Reusable SDK Code Generator"
          className="lg:col-span-7 border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <h3 className="text-base font-semibold text-slate-100">
                {snippet.title}
              </h3>
              <p className="text-xs text-slate-400 font-mono tabular-nums mt-0.5">
                Model: {snippet.model} · Route: {snippet.endpoint} · Safety: {safety.harassment}
              </p>
            </div>
            <div
              role="group"
              aria-label="Code Target Language"
              className="inline-flex p-1 bg-[#0F172A] border border-slate-800 rounded-md"
            >
              {(
                [
                  { id: 'node', label: 'Node.js (@google/genai)' },
                  { id: 'kotlin', label: 'Android Kotlin' },
                  { id: 'curl', label: 'cURL HTTP' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setCodeLang(tab.id)}
                  className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    codeLang === tab.id
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div className="border border-slate-800 rounded-md bg-[#0F172A] overflow-hidden">
            <div className="flex items-center justify-between px-3.5 py-2 border-b border-slate-800 bg-slate-900/70 text-xs">
              <span className="font-mono text-slate-300">
                Reusable Implementation Snippet ({codeLang.toUpperCase()})
              </span>
              <button
                type="button"
                onClick={handleCopySnippet}
                className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 rounded flex items-center gap-1 transition-colors"
              >
                {copiedCode ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Snippet</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto max-h-[300px] leading-relaxed">
              <code>{displayedCode}</code>
            </pre>
          </div>
        </section>
      </div>

      {/* Bottom Full-Width Section: Pipeline Execution Ledger & Output Inspector */}
      <section
        aria-label="API Reuse Execution Ledger"
        className="border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-semibold text-slate-100">
              Pipeline Reuse Execution Ledger
            </h3>
            <p className="text-xs text-slate-400">
              Click any execution row to inspect the full structured JSON, function call, or code synthesis payload.
            </p>
          </div>
          <div>
            <label htmlFor="ledger-search-input" className="sr-only">
              Filter execution ledger
            </label>
            <input
              id="ledger-search-input"
              type="search"
              value={ledgerFilter}
              onChange={(e) => setLedgerFilter(e.target.value)}
              placeholder="Search executions..."
              className="px-3 py-1.5 text-xs bg-[#0F172A] border border-slate-700 rounded-md text-slate-200 placeholder:text-slate-500"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-7 overflow-x-auto border border-slate-800 rounded-md">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                  <th className="py-2.5 px-3 font-medium">Pipeline</th>
                  <th className="py-2.5 px-3 font-medium">Model</th>
                  <th className="py-2.5 px-3 font-medium">Status</th>
                  <th className="py-2.5 px-3 font-medium text-right">Latency</th>
                  <th className="py-2.5 px-3 font-medium text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {filteredRecords.map((rec) => (
                  <tr
                    key={rec.id}
                    onClick={() => setSelectedRecordId(rec.id)}
                    className={`cursor-pointer transition-colors ${
                      activeRecord?.id === rec.id
                        ? 'bg-blue-950/40'
                        : 'hover:bg-slate-900/50'
                    }`}
                  >
                    <td className="py-2.5 px-3 text-slate-200 font-medium">
                      <div>{rec.pipelineTitle}</div>
                      <div className="text-slate-400 truncate max-w-xs">
                        {rec.outputSummary}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">
                      {rec.model}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 text-emerald-400 font-mono">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        {rec.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                      {rec.latencyMs} ms
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-400 whitespace-nowrap">
                      {rec.timestamp}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="lg:col-span-5 border border-slate-800 rounded-md bg-[#0F172A] overflow-hidden">
            <div className="px-3.5 py-2 border-b border-slate-800 bg-slate-900/70 text-xs font-mono text-slate-300">
              {activeRecord
                ? `Payload Output · ${activeRecord.pipelineId} (${activeRecord.timestamp})`
                : 'Payload Output'}
            </div>
            <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto max-h-[260px] leading-relaxed">
              <code>
                {activeRecord
                  ? activeRecord.rawOutput
                  : 'Select an execution record from the table to inspect its raw output.'}
              </code>
            </pre>
          </div>
        </div>
      </section>
    </div>
  );
}
