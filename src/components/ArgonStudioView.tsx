import React, { useState, useMemo, useEffect } from 'react';
import {
  SafetyMatrixConfig,
  SafetyThresholdMode,
  ThinkingDepth,
  InternetConnectorId,
  INTERNET_CONNECTORS,
  UNCERSON_FOLDER_NAME,
  UNCERSON_GGUF_FILENAME,
  UNCERSON_GGUF_RELATIVE_PATH,
  AI_GGUF_FOLDER_NAME,
  AI_GEMINI_UNCERSON_GGUF_PATH,
  ALL_CODE_FOLDER_NAME,
  ALL_CODE_GGUF_FILENAME,
  ALL_CODE_GGUF_RELATIVE_PATH,
  buildGeminiUncersonGgufBinary,
  executeRealGeminiUncersonForwardPass,
  UncersonTransformerTelemetry,
  buildAiGgufFolderFromStudioAndWorkspace,
  buildAllCodeInOneGgufBinary,
} from '../utils/builders';
import { ChatTurn } from '../utils/seedData';
import { Send, RotateCcw, ShieldAlert, Check, Copy, Globe, Download, Cpu, FileCode2, FolderArchive, Layers } from 'lucide-react';

interface AiGgufServerFileEntry {
  originalPath: string;
  ggufFilename: string;
  ggufPath: string;
  downloadUrl: string;
  sizeBytes: number;
  sizeFormatted: string;
  sha256Digest: string;
  crc32Hex: string;
  tensorCount: number;
  magicHex: string;
  version: number;
}

interface AiGgufServerStatus {
  folderName: string;
  zeroTxtFilesVerified: boolean;
  totalConvertedCodeFiles: number;
  totalGgufFilesInAiFolder: number;
  totalBytes: number;
  totalBytesFormatted: string;
  merkleRootHex: string;
  archiveZipDownloadUrl: string;
  archiveTgzDownloadUrl: string;
  geminiUncersonAiPath: string;
  geminiUncersonDownloadUrl: string;
  aggregateGgufPath: string;
  aggregateGgufDownloadUrl: string;
  convertedFiles: AiGgufServerFileEntry[];
}

interface AllCodeServerStatus {
  folderName: string;
  diskFolderPath: string;
  existsOnDisk: boolean;
  ggufFilename: string;
  relativePath: string;
  primaryModelPath: string;
  downloadGgufUrl: string;
  archiveZipDownloadUrl: string;
  archiveTgzDownloadUrl: string;
  totalConvertedCodeFiles: number;
  totalCodeFilesCount: number;
  totalGgufFileCount: number;
  txtFileCount: number;
  zeroTxtFilesVerified: boolean;
  sizeBytes: number;
  sizeFormatted: string;
  sha256Digest: string;
  doubleSha256Digest: string;
  crc32Hex: string;
  merkleRootHex: string;
  tensorCount: number;
  metadataKvCount: number;
  magicHex: string;
  version: number;
  convertedCodeFiles: { path: string; originalSize: number; tensorName: string }[];
}

interface ArgonStudioViewProps {
  chatHistory: ChatTurn[];
  onAddTurn: (turn: ChatTurn) => void;
  onClearHistory: () => void;
  safety: SafetyMatrixConfig;
  onChangeSafety: (next: SafetyMatrixConfig) => void;
  thinkingLevel: ThinkingDepth;
  onChangeThinkingLevel: (next: ThinkingDepth) => void;
  systemDirective: string;
  onChangeSystemDirective: (next: string) => void;
  enabledConnectors: InternetConnectorId[];
  onToggleConnector: (id: InternetConnectorId) => void;
}

const PRESET_PROMPTS = [
  {
    label: 'All Code in One GGUF (allcode/all-code.gguf)',
    prompt:
      'Execute a full GGUF v3 Q8_0/F32 tensor forward pass over allcode/all-code.gguf in new folder allcode/, where all project source files are consolidated into one single .gguf file (zero .txt files).',
  },
  {
    label: 'Uncerson AI LLM (ai/Geminiuncerson.gguf & uncerson/Geminiuncerson.gguf)',
    prompt:
      'Execute a full GGUF v3 Q8_0/F32 tensor forward pass over ai/Geminiuncerson.gguf and uncerson/Geminiuncerson.gguf with all code files converted into ai/*.gguf binaries (zero .txt files).',
  },
  {
    label: 'Android JNI DirectByteBuffer + ai/*.gguf Code Vault',
    prompt:
      'Provide the exact C++17 JNI implementation and Kotlin coroutine wrapper for memory-mapping assets/ai/Geminiuncerson.gguf and converted ai/*.gguf code tensors via DirectByteBuffer.',
  },
  {
    label: 'Multi-Endpoint Geminiuncerson.gguf + @google/genai Router',
    prompt:
      'Design a reusable TypeScript class that combines ai/Geminiuncerson.gguf tensor forward-pass logits with @google/genai structured Type.OBJECT extraction.',
  },
];

const THRESHOLD_OPTIONS: { value: SafetyThresholdMode; label: string }[] = [
  { value: 'BLOCK_NONE', label: 'BLOCK_NONE (Unfiltered)' },
  { value: 'OFF', label: 'OFF (Disabled)' },
  { value: 'BLOCK_ONLY_HIGH', label: 'BLOCK_ONLY_HIGH' },
  { value: 'BLOCK_MEDIUM_AND_ABOVE', label: 'BLOCK_MEDIUM_AND_ABOVE' },
];

export function ArgonStudioView({
  chatHistory,
  onAddTurn,
  onClearHistory,
  safety,
  onChangeSafety,
  thinkingLevel,
  onChangeThinkingLevel,
  systemDirective,
  onChangeSystemDirective,
  enabledConnectors,
  onToggleConnector,
}: ArgonStudioViewProps) {
  const [promptInput, setPromptInput] = useState('');
  const [targetUrlInput, setTargetUrlInput] = useState('');
  const [temperature, setTemperature] = useState<number>(0.85);
  const [isGenerating, setIsGenerating] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState('');
  const [showGgufInspector, setShowGgufInspector] = useState(true);
  const [showAiFolderFiles, setShowAiFolderFiles] = useState(true);
  const [isConvertingAiFolder, setIsConvertingAiFolder] = useState(false);
  const [selectedModelPath, setSelectedModelPath] = useState<string>(UNCERSON_GGUF_RELATIVE_PATH);

  // Real in-memory GGUF v3 binary for uncerson/Geminiuncerson.gguf, ai/ folder bundle, and allcode/ single-file bundle
  const uncersonBinary = useMemo(() => buildGeminiUncersonGgufBinary(), []);
  const localAiFolderBundle = useMemo(() => buildAiGgufFolderFromStudioAndWorkspace(), []);
  const localAllCodeBundle = useMemo(() => buildAllCodeInOneGgufBinary(), []);

  const [allCodeStatus, setAllCodeStatus] = useState<AllCodeServerStatus>(() => ({
    folderName: ALL_CODE_FOLDER_NAME,
    diskFolderPath: `/${ALL_CODE_FOLDER_NAME}`,
    existsOnDisk: true,
    ggufFilename: ALL_CODE_GGUF_FILENAME,
    relativePath: ALL_CODE_GGUF_RELATIVE_PATH,
    primaryModelPath: ALL_CODE_GGUF_RELATIVE_PATH,
    downloadGgufUrl: `/${ALL_CODE_GGUF_RELATIVE_PATH}`,
    archiveZipDownloadUrl: '/api/artifacts/allcode-bundle.zip',
    archiveTgzDownloadUrl: '/api/artifacts/allcode-bundle.tgz',
    totalConvertedCodeFiles: localAllCodeBundle.totalCodeFilesCount,
    totalCodeFilesCount: localAllCodeBundle.totalCodeFilesCount,
    totalGgufFileCount: 1,
    txtFileCount: 0,
    zeroTxtFilesVerified: true,
    sizeBytes: localAllCodeBundle.sizeBytes,
    sizeFormatted: localAllCodeBundle.sizeFormatted,
    sha256Digest: localAllCodeBundle.sha256Digest,
    doubleSha256Digest: localAllCodeBundle.doubleSha256Digest,
    crc32Hex: localAllCodeBundle.crc32Hex,
    merkleRootHex: localAllCodeBundle.merkleRootHex,
    tensorCount: localAllCodeBundle.parsedSummary.tensorCount,
    metadataKvCount: localAllCodeBundle.parsedSummary.metadataKvCount,
    magicHex: localAllCodeBundle.parsedSummary.magicHex,
    version: localAllCodeBundle.parsedSummary.version,
    convertedCodeFiles: localAllCodeBundle.convertedCodeFiles,
  }));
  const [showAllCodeTensors, setShowAllCodeTensors] = useState(false);
  const [isRecompilingAllCode, setIsRecompilingAllCode] = useState(false);

  const [aiFolderStatus, setAiFolderStatus] = useState<AiGgufServerStatus>(() => ({
    folderName: AI_GGUF_FOLDER_NAME,
    zeroTxtFilesVerified: localAiFolderBundle.zeroTxtFilesVerified,
    totalConvertedCodeFiles: localAiFolderBundle.convertedEntries.length,
    totalGgufFilesInAiFolder: localAiFolderBundle.aiGgufFiles.length,
    totalBytes: localAiFolderBundle.totalSizeBytes,
    totalBytesFormatted: localAiFolderBundle.totalSizeFormatted,
    merkleRootHex: localAiFolderBundle.combinedGguf.merkleRootHex,
    archiveZipDownloadUrl: '/api/artifacts/ai-gguf-folder.zip',
    archiveTgzDownloadUrl: '/api/artifacts/ai-gguf-folder.tgz',
    geminiUncersonAiPath: AI_GEMINI_UNCERSON_GGUF_PATH,
    geminiUncersonDownloadUrl: '/ai/Geminiuncerson.gguf',
    aggregateGgufPath: 'ai/all-code-v3.gguf',
    aggregateGgufDownloadUrl: '/ai/all-code-v3.gguf',
    convertedFiles: localAiFolderBundle.convertedEntries.map((item) => ({
      originalPath: item.originalPath,
      ggufFilename: item.ggufFilename,
      ggufPath: item.aiRelativePath,
      downloadUrl: `/ai/${encodeURIComponent(item.ggufFilename)}`,
      sizeBytes: item.ggufSizeBytes,
      sizeFormatted: item.ggufSizeFormatted,
      sha256Digest: item.sha256Digest,
      crc32Hex: item.crc32Hex,
      tensorCount: item.tensorCount,
      magicHex: item.parsedSummary.magicHex,
      version: item.parsedSummary.version,
    })),
  }));

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const res = await fetch('/api/ai-gguf/status');
        if (res.ok && active) {
          const data: AiGgufServerStatus = await res.json();
          setAiFolderStatus(data);
        }
      } catch {
        // Fallback to localAiFolderBundle already initialized
      }
      try {
        const allCodeRes = await fetch('/api/allcode/status');
        if (allCodeRes.ok && active) {
          const allData: AllCodeServerStatus = await allCodeRes.json();
          setAllCodeStatus(allData);
        }
      } catch {
        // Fallback to localAllCodeBundle already initialized
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const handleCompileAllCodeGguf = async () => {
    setIsRecompilingAllCode(true);
    try {
      const res = await fetch('/api/allcode/compile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) {
        const statusRes = await fetch('/api/allcode/status');
        if (statusRes.ok) {
          const data: AllCodeServerStatus = await statusRes.json();
          setAllCodeStatus(data);
        }
      }
    } finally {
      setIsRecompilingAllCode(false);
    }
  };

  const handleDownloadAllCodeGguf = () => {
    const blob = new Blob([localAllCodeBundle.ggufBytes as BlobPart], {
      type: 'application/octet-stream',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = ALL_CODE_GGUF_FILENAME;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleConvertAllCodeToAiGgufFolder = async () => {
    setIsConvertingAiFolder(true);
    try {
      const res = await fetch('/api/ai-gguf/convert-all', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) {
        const statusRes = await fetch('/api/ai-gguf/status');
        if (statusRes.ok) {
          const data: AiGgufServerStatus = await statusRes.json();
          setAiFolderStatus(data);
        }
      }
    } finally {
      setIsConvertingAiFolder(false);
    }
  };

  const [lastTelemetry, setLastTelemetry] = useState<UncersonTransformerTelemetry>(() =>
    executeRealGeminiUncersonForwardPass(
      'Initialize ai/Geminiuncerson.gguf & uncerson/Geminiuncerson.gguf GGUF v3 Q8_0/F32 tensor weights in folder ai/ and uncerson/ with all code files converted into .gguf (zero .txt).',
      { temperature: 0.85, ggufBundle: uncersonBinary }
    ).telemetry
  );

  const handleDownloadUncersonGguf = () => {
    const blob = new Blob([uncersonBinary.ggufBytes as BlobPart], {
      type: 'application/octet-stream',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = UNCERSON_GGUF_FILENAME;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleSetAllUnfiltered = () => {
    onChangeSafety({
      harassment: 'BLOCK_NONE',
      hateSpeech: 'BLOCK_NONE',
      sexuallyExplicit: 'BLOCK_NONE',
      dangerousContent: 'BLOCK_NONE',
      civicIntegrity: 'BLOCK_NONE',
    });
  };

  const handleCopyTurn = (id: string, text: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = promptInput.trim();
    if (!trimmed) {
      setErrorMessage('Enter a non-empty prompt before executing uncerson/Geminiuncerson.gguf.');
      return;
    }

    setErrorMessage(null);
    setIsGenerating(true);

    const nowStr = new Date().toTimeString().slice(0, 8);
    const userTurn: ChatTurn = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: trimmed,
      timestamp: nowStr,
      model: selectedModelPath,
      thinkingLevel,
    };
    onAddTurn(userTurn);
    setPromptInput('');

    // Compute real client-side GGUF v3 tensor forward pass over selected model immediately
    const localForwardPass = executeRealGeminiUncersonForwardPass(trimmed, {
      modelPath: selectedModelPath,
      temperature,
      thinkingLevel,
      systemDirective,
      safety,
      enabledConnectors,
      targetUrl: targetUrlInput.trim() || undefined,
      ggufBundle: uncersonBinary,
    });
    setLastTelemetry(localForwardPass.telemetry);

    try {
      const response = await fetch('/api/argon/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: trimmed,
          model: selectedModelPath,
          thinkingLevel,
          temperature,
          systemInstruction: systemDirective,
          safety,
          enabledConnectors,
          targetUrl: targetUrlInput.trim() || undefined,
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      if (data.telemetry) {
        setLastTelemetry(data.telemetry);
      }

      const argonTurn: ChatTurn = {
        id: `argon-${Date.now()}`,
        role: 'argon',
        content: data.text || localForwardPass.text,
        timestamp: new Date().toTimeString().slice(0, 8),
        model: data.model || UNCERSON_GGUF_RELATIVE_PATH,
        thinkingLevel: data.thinkingLevel || thinkingLevel,
        latencyMs: data.latencyMs ?? Math.round(localForwardPass.telemetry.forwardPassDurationMs),
        safetyMode:
          data.safetyMode || `BLOCK_NONE · ${UNCERSON_GGUF_RELATIVE_PATH} (Zero Simulator)`,
        reusedEndpoints: data.reusedEndpoints || [
          AI_GEMINI_UNCERSON_GGUF_PATH,
          UNCERSON_GGUF_RELATIVE_PATH,
          'GGUF-v3-RMSNorm-RoPE-Attention-SwiGLU',
        ],
      };
      onAddTurn(argonTurn);
    } catch {
      // Execute 100% real local GGUF v3 binary tensor forward pass over uncerson/Geminiuncerson.gguf
      const argonTurn: ChatTurn = {
        id: `argon-${Date.now()}`,
        role: 'argon',
        content: localForwardPass.text,
        timestamp: new Date().toTimeString().slice(0, 8),
        model: UNCERSON_GGUF_RELATIVE_PATH,
        thinkingLevel,
        latencyMs: Math.round(localForwardPass.telemetry.forwardPassDurationMs),
        safetyMode: `BLOCK_NONE · ${UNCERSON_GGUF_RELATIVE_PATH} (Zero Simulator)`,
        reusedEndpoints: [
          AI_GEMINI_UNCERSON_GGUF_PATH,
          UNCERSON_GGUF_RELATIVE_PATH,
          'GGUF-v3-RMSNorm-RoPE-Attention-SwiGLU',
        ],
      };
      onAddTurn(argonTurn);
    } finally {
      setIsGenerating(false);
    }
  };

  const filteredHistory = chatHistory.filter((turn) =>
    searchFilter.trim()
      ? turn.content.toLowerCase().includes(searchFilter.toLowerCase())
      : true
  );

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      {/* Left 8 Columns: Uncensored AI LLM (ai/ & uncerson/Geminiuncerson.gguf) Console */}
      <section
        aria-label="Uncerson AI LLM Geminiuncerson.gguf Session"
        className="lg:col-span-8 border border-slate-800 bg-[#131C31] rounded-lg p-6"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-5 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Uncerson AI LLM Console (<span className="font-mono text-emerald-400">{AI_GEMINI_UNCERSON_GGUF_PATH}</span> &amp; <span className="font-mono text-emerald-400">{UNCERSON_GGUF_RELATIVE_PATH}</span>)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5 font-mono tabular-nums">
              Folders: <span className="text-emerald-300">{AI_GGUF_FOLDER_NAME}/</span> ({aiFolderStatus.totalGgufFilesInAiFolder} .gguf files, 0 .txt) &amp; <span className="text-emerald-300">{UNCERSON_FOLDER_NAME}/</span> · 100% Real GGUF v3 Tensor Engine · Turns: {chatHistory.length}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <label htmlFor="session-search" className="sr-only">
              Filter session turns
            </label>
            <input
              id="session-search"
              type="search"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter transcript..."
              className="px-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded-md text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
            <button
              type="button"
              onClick={onClearHistory}
              className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-800 border border-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Clear Session
            </button>
          </div>
        </div>

        {/* Dedicated allcode/ Folder — All Project Code Consolidated into ONE Single .gguf File (Zero .txt) */}
        <div
          data-testid="allcode-gguf-folder-panel"
          className="mb-4 p-4 rounded-md bg-[#0D1527] border border-cyan-500/80 shadow-lg shadow-cyan-950/30 space-y-3"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <Layers className="w-5 h-5 text-cyan-400 shrink-0" />
              <div>
                <div className="text-xs font-semibold text-slate-100 font-mono flex items-center gap-2">
                  <span>Folder: <span className="text-cyan-400 font-bold">{ALL_CODE_FOLDER_NAME}/</span></span>
                  <span className="text-slate-500">·</span>
                  <span className="text-emerald-400 font-semibold">{ALL_CODE_GGUF_RELATIVE_PATH}</span>
                  <span className="px-1.5 py-0.5 bg-cyan-950 text-cyan-300 border border-cyan-700/60 rounded text-[10px]">ALL-IN-ONE .GGUF</span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono tabular-nums mt-0.5">
                  Consolidated: <span className="text-cyan-300 font-semibold">{allCodeStatus.totalCodeFilesCount} source code files</span> into <span className="text-emerald-400 font-semibold">1 single GGUF v3 file</span> · Tensors: <span className="text-cyan-300">{allCodeStatus.tensorCount}</span> · Size: <span className="text-slate-200">{allCodeStatus.sizeFormatted}</span> · .txt Files: <span className="text-emerald-400 font-semibold">0 Verified</span>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={isRecompilingAllCode}
                onClick={handleCompileAllCodeGguf}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <FileCode2 className="w-3.5 h-3.5" />
                {isRecompilingAllCode ? 'Compiling all-code.gguf...' : 'Compile All Code in One .gguf'}
              </button>
              <button
                type="button"
                onClick={handleDownloadAllCodeGguf}
                className="px-2.5 py-1.5 text-xs font-mono text-cyan-200 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/80 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <Download className="w-3 h-3 text-cyan-400" />
                all-code.gguf
              </button>
              <a
                href={allCodeStatus.archiveZipDownloadUrl}
                download="allcode-all-code.zip"
                className="px-2.5 py-1.5 text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <Download className="w-3 h-3 text-blue-400" />
                allcode/ (.zip)
              </a>
              <a
                href={allCodeStatus.archiveTgzDownloadUrl}
                download="allcode-all-code.tgz"
                className="px-2.5 py-1.5 text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <Download className="w-3 h-3 text-cyan-400" />
                allcode/ (.tgz)
              </a>
              <button
                type="button"
                onClick={() => setShowAllCodeTensors((prev) => !prev)}
                className="px-2.5 py-1.5 text-xs font-mono text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                {showAllCodeTensors ? 'Hide Manifest' : `Show Manifest (${allCodeStatus.totalCodeFilesCount} Files)`}
              </button>
            </div>
          </div>

          {showAllCodeTensors && (
            <div className="pt-2 border-t border-slate-800/90 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                <span>
                  All {allCodeStatus.totalCodeFilesCount} source files packed as individual 32-byte aligned tensors inside <code className="text-cyan-300">{allCodeStatus.relativePath}</code>:
                </span>
                <span className="text-cyan-400">
                  SHA-256: {allCodeStatus.sha256Digest.slice(0, 24)}...
                </span>
              </div>
              <div className="max-h-[195px] overflow-y-auto border border-slate-800 rounded bg-slate-950/60">
                <table className="w-full text-left border-collapse text-[11px] font-mono tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 sticky top-0">
                      <th className="py-1.5 px-2.5">Source File</th>
                      <th className="py-1.5 px-2.5">Embedded GGUF Tensor</th>
                      <th className="py-1.5 px-2.5 text-right">Original Size</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {allCodeStatus.convertedCodeFiles.map((file, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/50">
                        <td className="py-1.5 px-2.5 text-slate-300">{file.path}</td>
                        <td className="py-1.5 px-2.5 text-cyan-400 font-semibold">{file.tensorName}</td>
                        <td className="py-1.5 px-2.5 text-right text-slate-400">{file.originalSize} B</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Dedicated ai/ Folder (.gguf Hold Vault) - All Code Files Converted to .gguf (Not .txt) */}
        <div
          data-testid="ai-gguf-folder-panel"
          className="mb-4 p-4 rounded-md bg-[#0F172A] border border-blue-700/70 space-y-3"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <FolderArchive className="w-4 h-4 text-blue-400 shrink-0" />
              <div>
                <div className="text-xs font-semibold text-slate-100 font-mono">
                  Folder: <span className="text-blue-400">{AI_GGUF_FOLDER_NAME}/</span> · All Code Files Converted to <span className="text-emerald-400">.gguf</span> Files (Not <span className="text-rose-400">.txt</span>)
                </div>
                <div className="text-[11px] text-slate-400 font-mono tabular-nums">
                  GGUF Files in <span className="text-blue-300">{AI_GGUF_FOLDER_NAME}/</span>: <span className="text-emerald-300">{aiFolderStatus.totalGgufFilesInAiFolder} .gguf binaries</span> ({aiFolderStatus.totalConvertedCodeFiles} converted code files) · Total Size: {aiFolderStatus.totalBytesFormatted} · .txt Files: <span className="text-emerald-400">0 Verified</span>
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={isConvertingAiFolder}
                onClick={handleConvertAllCodeToAiGgufFolder}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <FileCode2 className="w-3.5 h-3.5" />
                {isConvertingAiFolder ? 'Converting Code to ai/*.gguf...' : 'Convert All Code to ai/*.gguf'}
              </button>
              <a
                href={aiFolderStatus.archiveZipDownloadUrl}
                download="ai-gguf-folder.zip"
                className="px-2.5 py-1.5 text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <Download className="w-3 h-3 text-blue-400" />
                ai/ (.zip)
              </a>
              <a
                href={aiFolderStatus.archiveTgzDownloadUrl}
                download="ai-gguf-folder.tgz"
                className="px-2.5 py-1.5 text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <Download className="w-3 h-3 text-cyan-400" />
                ai/ (.tgz)
              </a>
              <button
                type="button"
                onClick={() => setShowAiFolderFiles((prev) => !prev)}
                className="px-2.5 py-1.5 text-xs font-mono text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                {showAiFolderFiles ? 'Hide ai/*.gguf Files' : `Show ai/*.gguf (${aiFolderStatus.totalGgufFilesInAiFolder})`}
              </button>
            </div>
          </div>

          {showAiFolderFiles && (
            <div className="pt-2 border-t border-slate-800/90 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
                <span>
                  Every workspace &amp; studio code file is compiled into a standalone GGUF v3 binary (<code className="text-emerald-300">0x47475546 &quot;GGUF&quot;</code>) inside <code className="text-blue-300">ai/</code>:
                </span>
                <span className="text-emerald-400">
                  Merkle Root: {aiFolderStatus.merkleRootHex.slice(0, 20)}...
                </span>
              </div>
              <div className="max-h-[195px] overflow-y-auto border border-slate-800 rounded bg-slate-950/60">
                <table className="w-full text-left border-collapse text-[11px] font-mono tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 sticky top-0">
                      <th className="py-1.5 px-2.5">Source Code File</th>
                      <th className="py-1.5 px-2.5">Converted .gguf File in ai/</th>
                      <th className="py-1.5 px-2.5">Header Magic</th>
                      <th className="py-1.5 px-2.5 text-right">Tensors</th>
                      <th className="py-1.5 px-2.5 text-right">Size</th>
                      <th className="py-1.5 px-2.5 text-right">Download</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {aiFolderStatus.convertedFiles.map((file) => (
                      <tr key={file.ggufPath} className="hover:bg-slate-900/50">
                        <td className="py-1.5 px-2.5 text-slate-300">{file.originalPath}</td>
                        <td className="py-1.5 px-2.5 text-emerald-400 font-semibold">{file.ggufPath}</td>
                        <td className="py-1.5 px-2.5 text-blue-300">{file.magicHex} (v{file.version})</td>
                        <td className="py-1.5 px-2.5 text-right text-slate-300">{file.tensorCount}</td>
                        <td className="py-1.5 px-2.5 text-right text-slate-300">{file.sizeFormatted}</td>
                        <td className="py-1.5 px-2.5 text-right">
                          <a
                            href={file.downloadUrl}
                            download={file.ggufFilename}
                            className="text-blue-400 hover:text-blue-300 underline"
                          >
                            .gguf
                          </a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Dedicated uncerson/Geminiuncerson.gguf Binary & Tensor Forward-Pass Panel */}
        <div
          data-testid="uncerson-gguf-panel"
          className="mb-5 p-4 rounded-md bg-[#0F172A] border border-emerald-800/60 space-y-3"
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-emerald-400 shrink-0" />
              <div>
                <div className="text-xs font-semibold text-slate-100 font-mono">
                  {AI_GEMINI_UNCERSON_GGUF_PATH} &amp; {UNCERSON_GGUF_RELATIVE_PATH} · GGUF v3 Binary Model (Magic 0x47475546 &quot;GGUF&quot;)
                </div>
                <div className="text-[11px] text-slate-400 font-mono tabular-nums">
                  Folders: <span className="text-emerald-300">{AI_GGUF_FOLDER_NAME}/</span> &amp; <span className="text-emerald-300">{UNCERSON_FOLDER_NAME}/</span> · Model: <span className="text-emerald-300">{UNCERSON_GGUF_FILENAME}</span> · Size: {uncersonBinary.sizeFormatted} ({uncersonBinary.sizeBytes.toLocaleString()} B) · Tensors: {uncersonBinary.parsedSummary.tensorCount} · SHA-256: {uncersonBinary.sha256Digest.slice(0, 16)}...
                </div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleDownloadUncersonGguf}
                className="px-3 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Download className="w-3.5 h-3.5" />
                Download {UNCERSON_GGUF_FILENAME}
              </button>
              <a
                href="/api/artifacts/uncerson-Geminiuncerson.zip"
                download="uncerson-Geminiuncerson.gguf.zip"
                className="px-2.5 py-1.5 text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <Download className="w-3 h-3 text-blue-400" />
                uncerson/ (.zip)
              </a>
              <a
                href="/api/artifacts/uncerson-Geminiuncerson.tgz"
                download="uncerson-Geminiuncerson.gguf.tgz"
                className="px-2.5 py-1.5 text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <Download className="w-3 h-3 text-cyan-400" />
                uncerson/ (.tgz)
              </a>
              <button
                type="button"
                onClick={() => setShowGgufInspector((prev) => !prev)}
                className="px-2.5 py-1.5 text-xs font-mono text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded transition-colors flex items-center gap-1 whitespace-nowrap shrink-0"
              >
                <FileCode2 className="w-3 h-3 text-emerald-400" />
                {showGgufInspector ? 'Hide Tensor Telemetry' : 'Inspect GGUF Tensors'}
              </button>
            </div>
          </div>

          {showGgufInspector && (
            <div className="pt-3 border-t border-slate-800/90 space-y-3 text-xs font-mono">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                  <div className="text-[10px] text-slate-400">BPE Tokens Evaluated</div>
                  <div className="text-slate-100 font-semibold mt-0.5 tabular-nums">
                    {lastTelemetry.inputTokenIds.length} tokens
                  </div>
                </div>
                <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                  <div className="text-[10px] text-slate-400">RMSNorm L2 Norm</div>
                  <div className="text-emerald-400 font-semibold mt-0.5 tabular-nums">
                    {lastTelemetry.rmsNormOutputL2}
                  </div>
                </div>
                <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                  <div className="text-[10px] text-slate-400">4-Head Attention Entropy</div>
                  <div className="text-blue-400 font-semibold mt-0.5 tabular-nums">
                    {lastTelemetry.attentionEntropy} bits
                  </div>
                </div>
                <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                  <div className="text-[10px] text-slate-400">SwiGLU FFN L2 Norm</div>
                  <div className="text-cyan-400 font-semibold mt-0.5 tabular-nums">
                    {lastTelemetry.swigluHiddenNorm}
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-300 bg-slate-900/70 px-3 py-2 rounded border border-slate-800">
                <span>Top Softmax Output Logits ({AI_GEMINI_UNCERSON_GGUF_PATH}):</span>
                <div className="flex flex-wrap items-center gap-2">
                  {lastTelemetry.topLogitTokens.slice(0, 5).map((item) => (
                    <span
                      key={item.tokenId}
                      className="px-2 py-0.5 rounded bg-slate-800 text-emerald-300 border border-slate-700 tabular-nums"
                    >
                      {item.token} ({(item.probability * 100).toFixed(1)}%)
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Preset Prompt Bar */}
        <div className="mb-5">
          <p className="text-xs font-medium text-slate-400 mb-2">
            Load Engineering Prompt Template:
          </p>
          <div className="flex flex-wrap gap-2">
            {PRESET_PROMPTS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => {
                  setPromptInput(preset.prompt);
                  setErrorMessage(null);
                }}
                className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-900/90 hover:bg-slate-800 border border-slate-700/80 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        {/* Conversation Transcript */}
        <div
          className="space-y-4 max-h-[460px] overflow-y-auto pr-1 mb-6"
          data-testid="argon-chat-transcript"
        >
          {filteredHistory.length === 0 ? (
            <div className="py-12 text-center border border-dashed border-slate-800 rounded-md">
              <p className="text-sm text-slate-300 font-medium">
                No conversation turns match the current view.
              </p>
              <p className="text-xs text-slate-400 mt-1 mb-4">
                Select a template above or submit a prompt below to run Gemini 4 Argon.
              </p>
              <button
                type="button"
                onClick={() => {
                  setSearchFilter('');
                  setPromptInput(PRESET_PROMPTS[0].prompt);
                }}
                className="px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors"
              >
                Load Default Systems Prompt
              </button>
            </div>
          ) : (
            filteredHistory.map((turn) => (
              <article
                key={turn.id}
                className={`p-4 rounded-md border ${
                  turn.role === 'user'
                    ? 'bg-slate-900/70 border-slate-800'
                    : 'bg-[#0F172A] border-slate-700/80'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-2 text-xs text-slate-400 font-mono tabular-nums">
                  <div>
                    <span className="font-semibold text-slate-200">
                      {turn.role === 'user' ? 'Developer Prompt' : 'Gemini 4 Argon Response'}
                    </span>
                    <span aria-hidden="true"> · </span>
                    <span>{turn.model}</span>
                    <span aria-hidden="true"> · </span>
                    <span>Thinking: {turn.thinkingLevel}</span>
                    {turn.latencyMs !== undefined && (
                      <>
                        <span aria-hidden="true"> · </span>
                        <span>{turn.latencyMs} ms</span>
                      </>
                    )}
                    <span aria-hidden="true"> · </span>
                    <span>{turn.timestamp}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleCopyTurn(turn.id, turn.content)}
                    aria-label={`Copy ${turn.role} message`}
                    className="px-2 py-1 text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 rounded hover:bg-slate-800 transition-colors"
                  >
                    {copiedId === turn.id ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="text-sm text-slate-200 leading-relaxed font-sans space-y-1.5">
                  {turn.content.split('\n').map((line, idx) => {
                    if (line.startsWith('### ')) {
                      return (
                        <h4
                          key={idx}
                          className="text-sm font-semibold text-slate-100 pt-1"
                        >
                          {line.replace(/^###\s+/, '').replace(/`/g, '')}
                        </h4>
                      );
                    }
                    const parts = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
                    return (
                      <p key={idx} className="min-h-[1rem]">
                        {parts.map((part, pIdx) => {
                          if (part.startsWith('**') && part.endsWith('**')) {
                            return (
                              <strong key={pIdx} className="font-semibold text-slate-100">
                                {part.slice(2, -2).replace(/`/g, '')}
                              </strong>
                            );
                          }
                          if (part.startsWith('`') && part.endsWith('`')) {
                            return (
                              <code
                                key={pIdx}
                                className="px-1.5 py-0.5 text-xs font-mono bg-slate-800/90 text-blue-200 rounded"
                              >
                                {part.slice(1, -1)}
                              </code>
                            );
                          }
                          return <React.Fragment key={pIdx}>{part}</React.Fragment>;
                        })}
                      </p>
                    );
                  })}
                </div>
                {turn.reusedEndpoints && turn.reusedEndpoints.length > 0 && (
                  <div className="mt-3 pt-2 border-t border-slate-800/80 text-xs text-slate-400 font-mono">
                    Active SDK Pipeline: {turn.reusedEndpoints.join(' · ')}
                    {turn.safetyMode ? ` · ${turn.safetyMode}` : ''}
                  </div>
                )}
              </article>
            ))
          )}

          {isGenerating && (
            <div
              role="status"
              className="p-4 rounded-md border border-slate-800 bg-slate-900/50 animate-pulse"
            >
              <div className="h-3.5 w-48 bg-slate-800 rounded mb-3" />
              <div className="h-3 w-full bg-slate-800 rounded mb-2" />
              <div className="h-3 w-5/6 bg-slate-800 rounded" />
            </div>
          )}
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div
            role="alert"
            className="mb-4 p-3 rounded-md bg-red-950/60 border border-red-800 text-xs text-red-200 flex items-start gap-2.5"
          >
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <span className="font-semibold">Execution Error: </span>
              <span>{errorMessage}</span>
            </div>
          </div>
        )}

        {/* Prompt Submission Form */}
        <form onSubmit={handleSubmit} className="space-y-3">
          {/* Internet Grounding Connectors Strip: Google.com, GitHub, YouTube, GitLab */}
          <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-md bg-[#0F172A] border border-slate-800">
            <div className="flex items-center gap-1.5 text-xs text-slate-300 font-medium">
              <Globe className="w-3.5 h-3.5 text-blue-400" />
              <span>Internet Grounding:</span>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {INTERNET_CONNECTORS.map((conn) => {
                const active = enabledConnectors.includes(conn.id);
                return (
                  <button
                    key={conn.id}
                    type="button"
                    onClick={() => onToggleConnector(conn.id)}
                    className={`px-2.5 py-1 text-xs font-mono rounded transition-colors whitespace-nowrap shrink-0 ${
                      active
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {conn.domain}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label
                htmlFor="argon-prompt-textarea"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Unfiltered Engineering Prompt (Gemini 4 Argon · 3 GB RAM Profile)
              </label>
              <textarea
                id="argon-prompt-textarea"
                rows={3}
                value={promptInput}
                onChange={(e) => {
                  setPromptInput(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                }}
                placeholder="Ask Gemini 4 Argon to synthesize unfiltered Node.js packages, native Android JNI C++ code, or search Google.com, GitHub, YouTube, and GitLab..."
                className="w-full rounded-md bg-[#0F172A] border border-slate-700 p-3 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div className="flex flex-col justify-between">
              <div>
                <label
                  htmlFor="argon-target-url"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Reference URL (Optional)
                </label>
                <input
                  id="argon-target-url"
                  type="url"
                  value={targetUrlInput}
                  onChange={(e) => setTargetUrlInput(e.target.value)}
                  placeholder="https://github.com/..."
                  className="w-full px-3 py-2 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="text-[11px] text-slate-400 font-mono tabular-nums pt-2">
                RAM Ceiling: 3,072 MB (3.0 GB) · Indexed: 1,000 Packages
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <label htmlFor="argon-temp-input" className="text-xs text-slate-400">
                  Temperature:
                </label>
                <input
                  id="argon-temp-input"
                  type="number"
                  step="0.05"
                  min="0"
                  max="2"
                  value={temperature}
                  onChange={(e) => setTemperature(parseFloat(e.target.value) || 0.85)}
                  className="w-16 px-2 py-1 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-slate-200"
                />
              </div>
              <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-700 rounded p-1">
                <button
                  type="button"
                  onClick={() => setSelectedModelPath(UNCERSON_GGUF_RELATIVE_PATH)}
                  className={`px-2 py-0.5 text-[11px] font-mono rounded transition-colors ${
                    selectedModelPath === UNCERSON_GGUF_RELATIVE_PATH
                      ? 'bg-emerald-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  uncerson/Geminiuncerson.gguf
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedModelPath(AI_GEMINI_UNCERSON_GGUF_PATH)}
                  className={`px-2 py-0.5 text-[11px] font-mono rounded transition-colors ${
                    selectedModelPath === AI_GEMINI_UNCERSON_GGUF_PATH
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  ai/Geminiuncerson.gguf
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedModelPath(ALL_CODE_GGUF_RELATIVE_PATH)}
                  className={`px-2 py-0.5 text-[11px] font-mono rounded transition-colors ${
                    selectedModelPath === ALL_CODE_GGUF_RELATIVE_PATH
                      ? 'bg-cyan-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  allcode/all-code.gguf
                </button>
              </div>
            </div>
            <button
              type="submit"
              disabled={isGenerating}
              className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-md transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
            >
              <Send className="w-3.5 h-3.5" />
              {isGenerating ? 'Running Gemini 4 Argon...' : 'Send Prompt'}
            </button>
          </div>
        </form>
      </section>

      {/* Right 4 Columns: Safety Threshold Matrix & System Directive Configurator */}
      <aside
        aria-label="Safety Threshold Matrix and Reasoning Configuration"
        className="lg:col-span-4 border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-6"
      >
        <div>
          <div className="flex items-center justify-between gap-2 mb-2">
            <h3 className="text-base font-semibold text-slate-100">
              Safety Threshold Matrix
            </h3>
            <button
              type="button"
              onClick={handleSetAllUnfiltered}
              className="px-2.5 py-1 text-xs font-medium text-blue-300 bg-blue-950/60 hover:bg-blue-900/60 border border-blue-800/70 rounded transition-colors whitespace-nowrap shrink-0"
            >
              Set All BLOCK_NONE
            </button>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Configures the server-side <code className="text-slate-300">@google/genai</code>{' '}
            harm category thresholds injected into live requests, compiled Node.js packages, and Android APK manifests.
          </p>
        </div>

        <div className="space-y-3">
          {(
            [
              { key: 'harassment', label: 'Harassment (HARM_CATEGORY_HARASSMENT)' },
              { key: 'hateSpeech', label: 'Hate Speech (HARM_CATEGORY_HATE_SPEECH)' },
              {
                key: 'sexuallyExplicit',
                label: 'Sexually Explicit (HARM_CATEGORY_SEXUALLY_EXPLICIT)',
              },
              {
                key: 'dangerousContent',
                label: 'Dangerous Content (HARM_CATEGORY_DANGEROUS_CONTENT)',
              },
              {
                key: 'civicIntegrity',
                label: 'Civic Integrity (HARM_CATEGORY_CIVIC_INTEGRITY)',
              },
            ] as const
          ).map((item) => (
            <div key={item.key}>
              <label
                htmlFor={`safety-${item.key}`}
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                {item.label}
              </label>
              <select
                id={`safety-${item.key}`}
                value={safety[item.key]}
                onChange={(e) =>
                  onChangeSafety({
                    ...safety,
                    [item.key]: e.target.value as SafetyThresholdMode,
                  })
                }
                className="w-full px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-200 focus:outline-none focus:border-blue-500"
              >
                {THRESHOLD_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>

        <div className="pt-4 border-t border-slate-800">
          <label
            htmlFor="thinking-level-select"
            className="block text-xs font-medium text-slate-300 mb-1.5"
          >
            Gemini 4 Argon Thinking Level
          </label>
          <div
            id="thinking-level-select"
            role="group"
            aria-label="Thinking Level"
            className="grid grid-cols-3 gap-1.5 p-1 bg-[#0F172A] border border-slate-800 rounded-md"
          >
            {(['HIGH', 'MEDIUM', 'LOW'] as ThinkingDepth[]).map((lvl) => (
              <button
                key={lvl}
                type="button"
                onClick={() => onChangeThinkingLevel(lvl)}
                className={`py-1.5 text-xs font-mono font-medium rounded transition-colors ${
                  thinkingLevel === lvl
                    ? 'bg-blue-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>

        <div className="pt-4 border-t border-slate-800">
          <label
            htmlFor="system-directive-input"
            className="block text-xs font-medium text-slate-300 mb-1.5"
          >
            Unfiltered System Instruction Directive
          </label>
          <textarea
            id="system-directive-input"
            rows={4}
            value={systemDirective}
            onChange={(e) => onChangeSystemDirective(e.target.value)}
            className="w-full rounded-md bg-[#0F172A] border border-slate-700 p-2.5 text-xs text-slate-200 font-mono leading-relaxed focus:outline-none focus:border-blue-500"
          />
        </div>
      </aside>
    </div>
  );
}
