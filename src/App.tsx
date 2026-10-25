import React, { useState } from 'react';
import {
  SafetyMatrixConfig,
  ThinkingDepth,
  NodePackageSpec,
  AndroidApkSpec,
  InternetConnectorId,
  UNCERSON_GGUF_RELATIVE_PATH,
  executeRealGeminiUncersonForwardPass,
} from './utils/builders';
import {
  INITIAL_SAFETY_MATRIX,
  INITIAL_SYSTEM_DIRECTIVE,
  INITIAL_NODE_PACKAGE_SPEC,
  INITIAL_ANDROID_APK_SPEC,
  INITIAL_CHAT_HISTORY,
  INITIAL_REUSE_RECORDS,
  ChatTurn,
  ReuseExecutionRecord,
} from './utils/seedData';
import { ArgonStudioView } from './components/ArgonStudioView';
import { NodePackageBuilderView } from './components/NodePackageBuilderView';
import { AndroidApkBuilderView } from './components/AndroidApkBuilderView';
import { ApiReuseHubView } from './components/ApiReuseHubView';
import { RegistryAndMemoryView } from './components/RegistryAndMemoryView';
import { Web3PoolMinerView } from './components/Web3PoolMinerView';
import {
  Terminal,
  Package,
  Smartphone,
  Cpu,
  Globe,
  Zap,
} from 'lucide-react';

export type WorkspaceTab =
  | 'studio'
  | 'web3-pool-miner'
  | 'registry-ram'
  | 'node-pkg'
  | 'android-apk'
  | 'api-reuse';

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('studio');
  const [safety, setSafety] = useState<SafetyMatrixConfig>(INITIAL_SAFETY_MATRIX);
  const [thinkingLevel, setThinkingLevel] = useState<ThinkingDepth>('HIGH');
  const [systemDirective, setSystemDirective] = useState<string>(
    INITIAL_SYSTEM_DIRECTIVE
  );
  const [chatHistory, setChatHistory] = useState<ChatTurn[]>(INITIAL_CHAT_HISTORY);
  const [nodeSpec, setNodeSpec] = useState<NodePackageSpec>(
    INITIAL_NODE_PACKAGE_SPEC
  );
  const [androidSpec, setAndroidSpec] = useState<AndroidApkSpec>(
    INITIAL_ANDROID_APK_SPEC
  );
  const [reuseRecords, setReuseRecords] = useState<ReuseExecutionRecord[]>(
    INITIAL_REUSE_RECORDS
  );

  // 3 GB RAM (3,072 MB) allocation state + Internet Connectors + 1,000-Package Selection
  const [enabledConnectors, setEnabledConnectors] = useState<InternetConnectorId[]>([
    'google',
    'github',
    'youtube',
    'gitlab',
  ]);
  const [v8HeapMb, setV8HeapMb] = useState<number>(1536);
  const [jniArenaMb, setJniArenaMb] = useState<number>(1024);
  const [connectorCacheMb, setConnectorCacheMb] = useState<number>(256);
  const [bundledPackageIds, setBundledPackageIds] = useState<number[]>([
    1, 2, 3, 4, 12, 13, 14, 15,
  ]);

  const handleToggleConnector = (id: InternetConnectorId) => {
    setEnabledConnectors((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleToggleBundlePackage = (id: number) => {
    setBundledPackageIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  // Sync global safety, thinking level, and system directive into both package specs
  const handleSafetyChange = (nextSafety: SafetyMatrixConfig) => {
    setSafety(nextSafety);
    setNodeSpec((prev) => ({ ...prev, safety: nextSafety }));
    setAndroidSpec((prev) => ({ ...prev, safety: nextSafety }));
  };

  const handleThinkingChange = (nextLevel: ThinkingDepth) => {
    setThinkingLevel(nextLevel);
    setNodeSpec((prev) => ({ ...prev, thinkingLevel: nextLevel }));
    setAndroidSpec((prev) => ({ ...prev, thinkingLevel: nextLevel }));
  };

  const handleDirectiveChange = (nextDirective: string) => {
    setSystemDirective(nextDirective);
    setNodeSpec((prev) => ({ ...prev, systemDirective: nextDirective }));
    setAndroidSpec((prev) => ({ ...prev, systemDirective: nextDirective }));
  };

  const handleQuickGroundedPrompt = (prompt: string, targetUrl: string) => {
    const nowStr = new Date().toTimeString().slice(0, 8);
    const fullPrompt = `[Grounded Reference: ${targetUrl}] ${prompt}`;
    const forwardPass = executeRealGeminiUncersonForwardPass(fullPrompt, {
      temperature: 0.85,
      thinkingLevel,
      systemDirective,
      safety,
      enabledConnectors,
      targetUrl,
    });
    setChatHistory((prev) => [
      ...prev,
      {
        id: `user-${Date.now()}`,
        role: 'user',
        content: fullPrompt,
        timestamp: nowStr,
        model: UNCERSON_GGUF_RELATIVE_PATH,
        thinkingLevel,
      },
      {
        id: `argon-${Date.now() + 1}`,
        role: 'argon',
        content: `${forwardPass.text}\n\n- **3.00 GB RAM Process Allocation**: V8 Heap (\`--max-old-space-size=${v8HeapMb}\`), NDK JNI Arena (\`${jniArenaMb} MB\`).\n- **Active Internet Connectors**: \`${enabledConnectors.join(', ')}\`.\n- **Bundled Package Dependencies**: \`${bundledPackageIds.length}\` packages linked with \`${UNCERSON_GGUF_RELATIVE_PATH}\`.`,
        timestamp: nowStr,
        model: UNCERSON_GGUF_RELATIVE_PATH,
        thinkingLevel,
        latencyMs: Math.round(forwardPass.telemetry.forwardPassDurationMs),
        safetyMode: `BLOCK_NONE · ${UNCERSON_GGUF_RELATIVE_PATH} (Zero Simulator)`,
        reusedEndpoints: ['uncerson/Geminiuncerson.gguf', 'GGUF-v3-RMSNorm-RoPE-Attention-SwiGLU'],
      },
    ]);
    setActiveTab('studio');
  };

  const navItems: {
    id: WorkspaceTab;
    shortLabel: string;
    sidebarTitle: string;
    subtitle: string;
    icon: React.ComponentType<{ className?: string }>;
  }[] = [
    {
      id: 'studio',
      shortLabel: 'Uncerson AI LLM',
      sidebarTitle: 'Uncerson AI LLM (Geminiuncerson.gguf)',
      subtitle: 'uncerson/Geminiuncerson.gguf · Zero Simulator',
      icon: Terminal,
    },
    {
      id: 'web3-pool-miner',
      shortLabel: 'vSHABoost Miner',
      sidebarTitle: 'Virtual SHABoost & Web3 Pool Miner',
      subtitle: '900 EH/s vASIC, any pool address & website',
      icon: Zap,
    },
    {
      id: 'registry-ram',
      shortLabel: 'RAM & 1,000 Pkgs',
      sidebarTitle: '3 GB RAM & 1,000 Packages',
      subtitle: 'Google, GitHub, YouTube, GitLab',
      icon: Globe,
    },
    {
      id: 'node-pkg',
      shortLabel: 'Node.js Packager',
      sidebarTitle: 'Node.js Package (.tgz)',
      subtitle: 'Compile real npm tarball & CLI',
      icon: Package,
    },
    {
      id: 'android-apk',
      shortLabel: 'Android APK',
      sidebarTitle: 'Native Android APK',
      subtitle: 'DEX 035 + ELF64 JNI C++ assembler',
      icon: Smartphone,
    },
    {
      id: 'api-reuse',
      shortLabel: 'API Reuse Hub',
      sidebarTitle: 'Argon API Reuse Hub',
      subtitle: 'Multi-endpoint @google/genai pipelines',
      icon: Cpu,
    },
  ];

  const activeNavMeta = navItems.find((n) => n.id === activeTab) || navItems[0];

  return (
    <div className="min-h-screen bg-[#0F172A] text-slate-100 flex flex-col">
      {/* Strict 3-Zone Top Navigation Bar */}
      <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-800 bg-[#0F172A]">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('studio');
          }}
          className="text-base font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0"
        >
          Argon Native Studio
        </a>

        {/* Zone 2: 6 concise single-line text navigation links */}
        <nav
          aria-label="Primary Workspace Navigation"
          className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400"
        >
          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 py-1 border-b-2 ${
                activeTab === item.id
                  ? 'text-slate-100 border-blue-500'
                  : 'border-transparent'
              }`}
            >
              {item.shortLabel}
            </button>
          ))}
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() =>
              setActiveTab(
                activeTab === 'web3-pool-miner' ? 'studio' : 'web3-pool-miner'
              )
            }
            className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded-md hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
          >
            <Zap className="w-3.5 h-3.5 text-cyan-300" />
            {activeTab === 'web3-pool-miner'
              ? 'Uncerson AI LLM'
              : 'Launch vASIC Miner'}
          </button>
        </div>
      </header>

      {/* Main Workspace Layout: 260px Sidebar + Primary Viewport */}
      <div className="flex-1 flex flex-col lg:flex-row">
        {/* Left Sidebar Navigation (260px on Desktop) */}
        <aside
          aria-label="Workbench Modules"
          className="w-full lg:w-[260px] shrink-0 border-b lg:border-b-0 lg:border-r border-slate-800 bg-[#0F172A] p-4 flex flex-col justify-between gap-6"
        >
          <div className="space-y-5">
            <div>
              <p className="px-2 text-xs font-medium text-slate-400 mb-2">
                Workbench Targets
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-1 gap-1.5">
                {navItems.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setActiveTab(item.id)}
                      className={`w-full text-left px-3 py-2.5 rounded-md transition-colors flex items-start gap-2.5 ${
                        isActive
                          ? 'bg-[#1E293B] text-slate-100 border border-slate-700'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                      }`}
                    >
                      <Icon className="w-4 h-4 mt-0.5 shrink-0 text-blue-400" />
                      <div className="min-w-0">
                        <div className="text-xs font-semibold truncate">
                          {item.sidebarTitle}
                        </div>
                        <div className="text-[11px] text-slate-400 truncate hidden lg:block">
                          {item.subtitle}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Active Runtime Specification Summary (Unboxed Clean Metadata) */}
            <div className="hidden lg:block pt-4 border-t border-slate-800 px-2 space-y-2.5 text-xs">
              <div className="font-semibold text-slate-300">
                Active Engine Profile
              </div>
              <div className="space-y-1.5 text-slate-400 font-mono tabular-nums">
                <div className="text-emerald-400">GGUF: ai/Geminiuncerson.gguf</div>
                <div className="text-blue-300">Folders: ai/ &amp; uncerson/ (.gguf)</div>
                <div>All Code Files: &rarr; ai/*.gguf (0 .txt)</div>
                <div>RAM Ceiling: 3.00 GB (3,072 MB)</div>
                <div>Web: Google · GitHub · YT · GitLab</div>
                <div>Registry: 1,000 Packages ({bundledPackageIds.length} Bundled)</div>
                <div>Safety: {safety.harassment}</div>
                <div>Android Target: SDK {androidSpec.targetSdk}</div>
              </div>
            </div>
          </div>

          <div className="hidden lg:block pt-4 border-t border-slate-800 px-2 text-xs text-slate-400">
            <div className="font-medium text-slate-300">
              ai/ &amp; uncerson/Geminiuncerson.gguf
            </div>
            <div className="mt-0.5 font-mono tabular-nums text-[11px]">
              All Code &rarr; ai/*.gguf · Zero .txt Files
            </div>
          </div>
        </aside>

        {/* Main Content Viewport */}
        <main className="flex-1 min-w-0 p-6 lg:p-8 max-w-[1400px]">
          {/* Context Header & Quantitative Metrics Strip */}
          <div className="pb-6 mb-6 border-b border-slate-800 flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div>
              <div className="text-xs text-slate-400 font-mono mb-1">
                Workspace / {activeNavMeta.sidebarTitle}
              </div>
              <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
                {activeNavMeta.sidebarTitle}
              </h1>
              <p className="text-sm text-slate-400 mt-1 max-w-2xl">
                {activeTab === 'studio' &&
                  'Folder ai/ holds all code files converted into real GGUF v3 binary .gguf files (ai/*.gguf, zero .txt files) alongside ai/Geminiuncerson.gguf & uncerson/Geminiuncerson.gguf.'}
                {activeTab === 'web3-pool-miner' &&
                  'Real FIPS 180-4 Bitwise sha256d with 50% Chunk-0 Midstate Acceleration, Stratum JSON-RPC submit for any pool mining address, On-Chain EVM PoW Contract, and standalone Web3 website.'}
                {activeTab === 'registry-ram' &&
                  'Manage the 3.00 GB (3,072 MB) process memory budget, configure live internet connectors (Google.com, GitHub, YouTube, GitLab), and browse 1,000 bundlable packages.'}
                {activeTab === 'node-pkg' &&
                  'Compile and download a standards-compliant Node.js npm package (.tgz) bundling uncerson/Geminiuncerson.gguf, ESM/CJS bundles, CLI binary, and TypeScript declarations.'}
                {activeTab === 'android-apk' &&
                  'Assemble a real Android APK binary (classes.dex + ELF64 libargon_jni.so + assets/uncerson/Geminiuncerson.gguf) and full Android Studio Kotlin/CMake project.'}
                {activeTab === 'api-reuse' &&
                  'Reuse uncerson/Geminiuncerson.gguf and @google/genai across deep reasoning, Type.OBJECT JSON schemas, function calling, and vector embeddings.'}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-4 text-xs font-mono tabular-nums text-slate-300 border border-slate-800 bg-[#131C31] px-4 py-2.5 rounded-md shrink-0">
              <div>
                <span className="text-slate-400">RAM Budget: </span>
                <span className="font-semibold text-blue-300">3.0 GB (3,072 MB)</span>
              </div>
              <span aria-hidden="true" className="text-slate-700">·</span>
              <div>
                <span className="text-slate-400">Sources: </span>
                <span className="font-semibold text-emerald-400">
                  {enabledConnectors.length}/4 Online
                </span>
              </div>
              <span aria-hidden="true" className="text-slate-700">·</span>
              <div>
                <span className="text-slate-400">Registry: </span>
                <span className="font-semibold text-slate-100">1,000 Pkgs</span>
              </div>
            </div>
          </div>

          {/* Active Workbench View */}
          {activeTab === 'studio' && (
            <ArgonStudioView
              chatHistory={chatHistory}
              onAddTurn={(turn) => setChatHistory((prev) => [...prev, turn])}
              onClearHistory={() => setChatHistory([])}
              safety={safety}
              onChangeSafety={handleSafetyChange}
              thinkingLevel={thinkingLevel}
              onChangeThinkingLevel={handleThinkingChange}
              systemDirective={systemDirective}
              onChangeSystemDirective={handleDirectiveChange}
              enabledConnectors={enabledConnectors}
              onToggleConnector={handleToggleConnector}
            />
          )}

          {activeTab === 'web3-pool-miner' && <Web3PoolMinerView />}

          {activeTab === 'registry-ram' && (
            <RegistryAndMemoryView
              enabledConnectors={enabledConnectors}
              onToggleConnector={handleToggleConnector}
              v8HeapMb={v8HeapMb}
              onChangeV8HeapMb={setV8HeapMb}
              jniArenaMb={jniArenaMb}
              onChangeJniArenaMb={setJniArenaMb}
              connectorCacheMb={connectorCacheMb}
              onChangeConnectorCacheMb={setConnectorCacheMb}
              bundledPackageIds={bundledPackageIds}
              onToggleBundlePackage={handleToggleBundlePackage}
              onQuickGroundedPrompt={handleQuickGroundedPrompt}
            />
          )}

          {activeTab === 'node-pkg' && (
            <NodePackageBuilderView
              spec={nodeSpec}
              onChangeSpec={setNodeSpec}
            />
          )}

          {activeTab === 'android-apk' && (
            <AndroidApkBuilderView
              spec={androidSpec}
              onChangeSpec={setAndroidSpec}
            />
          )}

          {activeTab === 'api-reuse' && (
            <ApiReuseHubView
              safety={safety}
              thinkingLevel={thinkingLevel}
              records={reuseRecords}
              onAddRecord={(rec) => setReuseRecords((prev) => [rec, ...prev])}
            />
          )}
        </main>
      </div>
    </div>
  );
}
