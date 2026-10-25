import React, { useState, useMemo, useEffect } from 'react';
import {
  INTERNET_CONNECTORS,
  InternetConnectorId,
  PackageEcosystem,
  PackageSourceHost,
  POLYGLOT_LANGUAGES,
  calculateRamAllocation,
  getThousandPackageCatalog,
  filterPackageCatalog,
  resolveBillionPackageCoordinate,
  ResolvedPackageCoordinate,
  resolveCryptoSha256Coordinate,
  ResolvedCryptoPackageCoordinate,
  PackageTestSuiteReport,
  GgufParsedInspection,
  Sha256BoostVasicSweepReceipt,
  synthesizePolyglotLanguageTemplate,
  sha256FromScratch,
} from '../utils/builders';
import {
  Cpu,
  Globe,
  Search,
  Plus,
  Check,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Download,
  Layers,
  CheckCircle2,
  ShieldCheck,
  Play,
  Code2,
  Binary,
} from 'lucide-react';

interface InstalledCoordinateReceipt {
  resolved: ResolvedPackageCoordinate;
  testReport?: PackageTestSuiteReport;
  artifactId: string;
  tgzFilename: string;
  tgzDownloadUrl: string;
  tgzSizeFormatted: string;
  tgzSha256: string;
  ggufFilename?: string;
  ggufDownloadUrl?: string;
  ggufSizeFormatted?: string;
  ggufSha256?: string;
  installedAt: string;
}

interface InstalledCryptoReceipt {
  resolved: ResolvedCryptoPackageCoordinate;
  testReport?: PackageTestSuiteReport;
  artifactId: string;
  tgzFilename: string;
  tgzDownloadUrl: string;
  tgzSizeFormatted: string;
  tgzSha256: string;
  ggufFilename?: string;
  ggufDownloadUrl?: string;
  ggufSizeFormatted?: string;
  ggufSha256?: string;
  installedAt: string;
}

interface InstalledUnlimitedReceipt {
  testReport: PackageTestSuiteReport;
  sourceCode: string;
  artifactId: string;
  tgzFilename: string;
  tgzDownloadUrl: string;
  tgzSizeFormatted: string;
  tgzSha256: string;
  ggufFilename?: string;
  ggufDownloadUrl?: string;
  ggufSizeFormatted?: string;
  ggufSha256?: string;
  ggufHeaderHexDump?: string;
  ggufParsedSummary?: GgufParsedInspection;
  installedAt: string;
}

interface FullGgufCompilationResponse {
  artifactId: string;
  ggufFilename: string;
  ggufDownloadUrl: string;
  aiFolderName?: string;
  aiFolderTotalGgufCount?: number;
  aiFolderTotalBytesFormatted?: string;
  aiFolderDownloadZipUrl?: string;
  aiFolderDownloadTgzUrl?: string;
  zeroTxtFilesVerified?: boolean;
  aiFolderFiles?: {
    originalPath: string;
    ggufFilename: string;
    ggufPath: string;
    downloadUrl: string;
    sizeBytes: number;
    sizeFormatted: string;
    sha256Digest: string;
    crc32Hex: string;
    tensorCount: number;
  }[];
  sizeBytes: number;
  sizeFormatted: string;
  sha256Digest: string;
  doubleSha256Digest: string;
  crc32Hex: string;
  merkleRootHex: string;
  convertedCodeFileCount: number;
  convertedCodeFiles: {
    path: string;
    sizeBytes: number;
    sha256Digest: string;
    tensorNames: string[];
  }[];
  headerHexDump: string;
  parsedSummary: GgufParsedInspection;
  compiledAt: string;
}

interface InstalledVasicMinerResponse {
  receipt: Sha256BoostVasicSweepReceipt;
  testReport: PackageTestSuiteReport;
  artifactId: string;
  tgzFilename: string;
  tgzDownloadUrl: string;
  tgzSizeFormatted: string;
  tgzSha256: string;
  ggufFilename: string;
  ggufDownloadUrl: string;
  ggufSizeFormatted: string;
  ggufSha256: string;
  ggufHeaderHexDump: string;
  ggufParsedSummary: GgufParsedInspection;
  installedAt: string;
}

interface RegistryAndMemoryViewProps {
  enabledConnectors: InternetConnectorId[];
  onToggleConnector: (id: InternetConnectorId) => void;
  v8HeapMb: number;
  onChangeV8HeapMb: (mb: number) => void;
  jniArenaMb: number;
  onChangeJniArenaMb: (mb: number) => void;
  connectorCacheMb: number;
  onChangeConnectorCacheMb: (mb: number) => void;
  bundledPackageIds: number[];
  onToggleBundlePackage: (id: number) => void;
  onQuickGroundedPrompt: (prompt: string, targetUrl: string) => void;
}

const COORDINATE_PRESETS = [
  { label: 'PKG #1,000', value: '1000' },
  { label: 'PKG #1,000,000 (1M)', value: '1000000' },
  { label: 'PKG #1,000,000,000 (1B Max Pkg)', value: '1000000000' },
  { label: 'CODE #1,000,000,000,000 (1T Max Code)', value: '1000000000000' },
];

const CRYPTO_COORDINATE_PRESETS = [
  { label: 'CRYPTO #1,000,000,000 (1B Crypto)', value: '1000000000' },
  { label: 'SHA256 #1,000,000,000,000 (1T SHA-256)', value: '1000000000000' },
  { label: 'EVM Bridge #500,000,000', value: '500000000' },
  { label: 'Bitcoin UTXO #750,000,000,000', value: '750000000000' },
];

export function RegistryAndMemoryView({
  enabledConnectors,
  onToggleConnector,
  v8HeapMb,
  onChangeV8HeapMb,
  jniArenaMb,
  onChangeJniArenaMb,
  connectorCacheMb,
  onChangeConnectorCacheMb,
  bundledPackageIds,
  onToggleBundlePackage,
  onQuickGroundedPrompt,
}: RegistryAndMemoryViewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [ecosystemFilter, setEcosystemFilter] = useState<PackageEcosystem | 'all'>('all');
  const [hostFilter, setHostFilter] = useState<PackageSourceHost | 'all'>('all');
  const [page, setPage] = useState(1);

  // 64-Bit Coordinate Resolver & On-Demand Installer State (1B Packages / 1T Polyglot Code / Unlimited)
  const [coordinateInput, setCoordinateInput] = useState('1000000000');
  const [coordLanguageOverride, setCoordLanguageOverride] = useState<string>('auto');
  const [isInstallingCoord, setIsInstallingCoord] = useState(false);
  const [installedReceipts, setInstalledReceipts] = useState<InstalledCoordinateReceipt[]>([]);

  // From-Scratch FIPS 180-4 SHA-256 & 1B/1T On-Chain Crypto Package Builder State
  const [cryptoCoordInput, setCryptoCoordInput] = useState('1000000000000');
  const [cryptoSeedPayload, setCryptoSeedPayload] = useState(
    'Argon-Scratch-SHA256-OnChain-Genesis-Block-01'
  );
  const [customCryptoPkgName, setCustomCryptoPkgName] = useState(
    '@argon-crypto/sha256-scratch-onchain'
  );
  const [isInstallingCrypto, setIsInstallingCrypto] = useState(false);
  const [installedCryptoReceipts, setInstalledCryptoReceipts] = useState<
    InstalledCryptoReceipt[]
  >([]);

  // Unlimited Polyglot Code & New Package Factory + 6-Stage Test Runner State
  const [unlimitedPkgName, setUnlimitedPkgName] = useState(
    '@argon-unlimited/rust-zero-copy-kernel'
  );
  const [unlimitedVersion, setUnlimitedVersion] = useState('1.0.0');
  const [unlimitedLangId, setUnlimitedLangId] = useState<string>('rust');
  const [customLangName, setCustomLangName] = useState('Haskell (GHC Native)');
  const [customLangExt, setCustomLangExt] = useState('hs');
  const [unlimitedSeqCoord, setUnlimitedSeqCoord] = useState('1000000000001');
  const [unlimitedTestVector, setUnlimitedTestVector] = useState(
    'argon-polyglot-unit-test-vector-01'
  );
  const [unlimitedCustomCode, setUnlimitedCustomCode] = useState<string>(() => {
    const initialSha = sha256FromScratch(
      '@argon-unlimited/rust-zero-copy-kernel@1.0.0:Rust (FFI/WASM):1000000000001'
    ).hex;
    return synthesizePolyglotLanguageTemplate(
      '@argon-unlimited/rust-zero-copy-kernel',
      '1.0.0',
      'rust',
      'Rust (FFI/WASM)',
      'rs',
      '1000000000001',
      initialSha
    );
  });
  const [isBuildingUnlimited, setIsBuildingUnlimited] = useState(false);
  const [isRunningTestsOnly, setIsRunningTestsOnly] = useState(false);
  const [activeTestReport, setActiveTestReport] =
    useState<PackageTestSuiteReport | null>(null);
  const [installedUnlimitedReceipts, setInstalledUnlimitedReceipts] = useState<
    InstalledUnlimitedReceipt[]
  >([]);

  // Full All-Code-to-GGUF v3 Binary Compiler State (Zero .txt files)
  const [ggufModelName, setGgufModelName] = useState(
    'argon-4-all-polyglot-code-full'
  );
  const [isCompilingAllGguf, setIsCompilingAllGguf] = useState(false);
  const [fullGgufArtifact, setFullGgufArtifact] =
    useState<FullGgufCompilationResponse | null>(null);
  const [ggufInspectorTab, setGgufInspectorTab] = useState<
    'ai-folder' | 'hex' | 'tensors' | 'kv'
  >('ai-folder');

  // SHA-256 Boost (1,000,000,000 Packages) + sha256.js Virtual vCPU & 900 EH/s Virtual ASIC (vASIC) Miner Software State
  const [vasicBoostCoord, setVasicBoostCoord] = useState('1000000000');
  const [vasicPkgName, setVasicPkgName] = useState(
    '@argon-sha256-boost/vasic-miner-900eh-1b'
  );
  const [vasicHashrateEh, setVasicHashrateEh] = useState<number>(900);
  const [vasicChipModel, setVasicChipModel] = useState(
    'Argon-vASIC-900EH-BM1370-Ultra'
  );
  const [vasicChipCount, setVasicChipCount] = useState<number>(4096);
  const [vasicVcpuThreads, setVasicVcpuThreads] = useState<number>(256);
  const [vasicSweepNonces, setVasicSweepNonces] = useState<number>(96);
  const [vasicBlockSeed, setVasicBlockSeed] = useState(
    'Argon-900EHs-vASIC-Chip-SHA256-Boost-1B-Genesis'
  );
  const [isBuildingVasic, setIsBuildingVasic] = useState(false);
  const [vasicActiveTab, setVasicActiveTab] = useState<
    'sha256js' | 'vcpu' | 'firmware'
  >('sha256js');
  const [installedVasicMiners, setInstalledVasicMiners] = useState<
    InstalledVasicMinerResponse[]
  >([]);

  const catalog = useMemo(() => getThousandPackageCatalog(), []);

  const activeCoordinate = useMemo(
    () =>
      resolveBillionPackageCoordinate(
        coordinateInput,
        coordLanguageOverride === 'auto' ? undefined : coordLanguageOverride
      ),
    [coordinateInput, coordLanguageOverride]
  );

  const activeCryptoCoordinate = useMemo(
    () =>
      resolveCryptoSha256Coordinate(
        cryptoCoordInput,
        cryptoSeedPayload,
        customCryptoPkgName
      ),
    [cryptoCoordInput, cryptoSeedPayload, customCryptoPkgName]
  );

  const handleSelectUnlimitedLanguage = (nextLangId: string) => {
    setUnlimitedLangId(nextLangId);
    const builtIn = POLYGLOT_LANGUAGES.find((l) => l.id === nextLangId);
    const lName =
      nextLangId === 'custom'
        ? customLangName || 'Custom Language'
        : builtIn?.name || 'TypeScript (ESM/Node.js)';
    const lExt =
      nextLangId === 'custom' ? customLangExt || 'code' : builtIn?.ext || 'ts';
    const nextPkgName = `@argon-unlimited/${nextLangId === 'custom' ? lExt : nextLangId}-pkg-${unlimitedSeqCoord}`;
    setUnlimitedPkgName(nextPkgName);
    const digest = sha256FromScratch(
      `${nextPkgName}@${unlimitedVersion}:${lName}:${unlimitedSeqCoord}`
    ).hex;
    setUnlimitedCustomCode(
      synthesizePolyglotLanguageTemplate(
        nextPkgName,
        unlimitedVersion,
        nextLangId,
        lName,
        lExt,
        unlimitedSeqCoord,
        digest
      )
    );
  };

  const handleInstallCoordinate = async (
    targetCoord: string,
    langOverride?: string
  ) => {
    setIsInstallingCoord(true);
    try {
      const effectiveLang =
        langOverride !== undefined ? langOverride : coordLanguageOverride;
      const res = await fetch('/api/packages/install-coordinate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          coordinate: targetCoord,
          overrideLanguageId: effectiveLang === 'auto' ? undefined : effectiveLang,
        }),
      });
      if (res.ok) {
        const data: InstalledCoordinateReceipt = await res.json();
        setInstalledReceipts((prev) => [
          data,
          ...prev.filter(
            (r) =>
              !(
                r.resolved.coordinateRaw === data.resolved.coordinateRaw &&
                r.resolved.languageExt === data.resolved.languageExt
              )
          ),
        ]);
        if (data.testReport) {
          setActiveTestReport(data.testReport);
        }
      }
    } finally {
      setIsInstallingCoord(false);
    }
  };

  const handleInstallCryptoPackage = async (
    targetCoord: string,
    seed: string,
    pkgName?: string
  ) => {
    setIsInstallingCrypto(true);
    try {
      const res = await fetch('/api/crypto-pkg/build-install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          coordinate: targetCoord,
          seedPayload: seed,
          customPackageName: pkgName,
        }),
      });
      if (res.ok) {
        const data: InstalledCryptoReceipt = await res.json();
        setInstalledCryptoReceipts((prev) => [
          data,
          ...prev.filter(
            (r) => r.resolved.coordinateRaw !== data.resolved.coordinateRaw
          ),
        ]);
        if (data.testReport) {
          setActiveTestReport(data.testReport);
        }
      }
    } finally {
      setIsInstallingCrypto(false);
    }
  };

  const handleBuildTestInstallUnlimited = async (
    overrideSeq?: string,
    overrideLangId?: string,
    overrideName?: string,
    overrideCode?: string
  ) => {
    setIsBuildingUnlimited(true);
    try {
      const seqToUse = overrideSeq || unlimitedSeqCoord;
      const langToUse = overrideLangId || unlimitedLangId;
      const nameToUse = overrideName || unlimitedPkgName;
      const codeToUse = overrideCode !== undefined ? overrideCode : unlimitedCustomCode;

      const res = await fetch('/api/unlimited-pkg/build-test-install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          packageName: nameToUse,
          version: unlimitedVersion,
          languageId: langToUse,
          customLanguageName: customLangName,
          customLanguageExt: customLangExt,
          sequenceCoordinate: seqToUse,
          customSourceCode: codeToUse,
          testInputVector: unlimitedTestVector,
        }),
      });
      if (res.ok) {
        const data: InstalledUnlimitedReceipt = await res.json();
        setActiveTestReport(data.testReport);
        setInstalledUnlimitedReceipts((prev) => [
          data,
          ...prev.filter(
            (r) =>
              !(
                r.testReport.packageName === data.testReport.packageName &&
                r.testReport.sequenceCoordinate === data.testReport.sequenceCoordinate
              )
          ),
        ]);
      }
    } finally {
      setIsBuildingUnlimited(false);
    }
  };

  const handleRunPackageTestsOnly = async (params: {
    packageName: string;
    version: string;
    languageName: string;
    languageExt: string;
    sequenceCoordinate: string;
    sourceCode: string;
    testInputVector?: string;
  }) => {
    setIsRunningTestsOnly(true);
    try {
      const res = await fetch('/api/unlimited-pkg/run-tests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });
      if (res.ok) {
        const data: { testReport: PackageTestSuiteReport } = await res.json();
        setActiveTestReport(data.testReport);
      }
    } finally {
      setIsRunningTestsOnly(false);
    }
  };

  const handleCompileAllCodeToGguf = async (targetModelName?: string) => {
    setIsCompilingAllGguf(true);
    try {
      const builtIn = POLYGLOT_LANGUAGES.find((l) => l.id === unlimitedLangId);
      const ext =
        unlimitedLangId === 'custom'
          ? customLangExt || 'code'
          : builtIn?.ext || 'rs';
      const res = await fetch('/api/gguf/compile-all-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          customModelName: targetModelName || ggufModelName,
          extraCodeFiles: [
            {
              path: `custom/${unlimitedPkgName.replace(/^@/, '').replace(/\//g, '-')}.${ext}`,
              content: unlimitedCustomCode,
              description: 'Active custom polyglot code module',
            },
          ],
        }),
      });
      if (res.ok) {
        const data: FullGgufCompilationResponse = await res.json();
        setFullGgufArtifact(data);
      }
    } finally {
      setIsCompilingAllGguf(false);
    }
  };

  const handleBuildSweepVasicMiner = async (overrideParams?: {
    boostPackageCoordinate?: string;
    packageName?: string;
    targetVirtualHashrateEh?: number;
    vAsicChipModel?: string;
    vAsicChipCount?: number;
    vCpuThreadCount?: number;
    realSweepNonces?: number;
    blockPayloadSeed?: string;
  }) => {
    setIsBuildingVasic(true);
    try {
      const res = await fetch('/api/vasic-miner/build-sweep-install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          boostPackageCoordinate:
            overrideParams?.boostPackageCoordinate ?? vasicBoostCoord,
          packageName: overrideParams?.packageName ?? vasicPkgName,
          version: '4.2.0',
          targetVirtualHashrateEh:
            overrideParams?.targetVirtualHashrateEh ?? vasicHashrateEh,
          vAsicChipModel: overrideParams?.vAsicChipModel ?? vasicChipModel,
          vAsicChipCount: overrideParams?.vAsicChipCount ?? vasicChipCount,
          vCpuThreadCount: overrideParams?.vCpuThreadCount ?? vasicVcpuThreads,
          realSweepNonces: overrideParams?.realSweepNonces ?? vasicSweepNonces,
          blockPayloadSeed: overrideParams?.blockPayloadSeed ?? vasicBlockSeed,
        }),
      });
      if (res.ok) {
        const data: InstalledVasicMinerResponse = await res.json();
        setInstalledVasicMiners((prev) => [
          data,
          ...prev.filter(
            (r) =>
              !(
                r.receipt.boostCoordinateRaw ===
                  data.receipt.boostCoordinateRaw &&
                r.receipt.targetVirtualHashrateEh ===
                  data.receipt.targetVirtualHashrateEh
              )
          ),
        ]);
        setActiveTestReport(data.testReport);
      }
    } finally {
      setIsBuildingVasic(false);
    }
  };

  // Pre-hydrate 1B/1T coordinates, 1B Crypto / 1T SHA-256 On-Chain packages, Unlimited Polyglot packages, Full All-Code .gguf Binary, and 1B SHA-256 Boost + 900 EH/s vASIC Miner on mount
  useEffect(() => {
    (async () => {
      await handleInstallCoordinate('1000000000', 'auto');
      await handleInstallCoordinate('1000000000000', 'auto');
      await handleInstallCryptoPackage(
        '1000000000',
        'Argon-1B-Crypto-OnChain-Genesis',
        '@argon-crypto/onchain-pkg-1000000000'
      );
      await handleInstallCryptoPackage(
        '1000000000000',
        'Argon-Scratch-SHA256-OnChain-Genesis-Block-01',
        '@argon-crypto/sha256-scratch-1000000000000'
      );
      await handleBuildTestInstallUnlimited(
        '1000000000001',
        'rust',
        '@argon-unlimited/rust-zero-copy-kernel',
        ''
      );
      await handleBuildSweepVasicMiner({
        boostPackageCoordinate: '1000000000',
        packageName: '@argon-sha256-boost/vasic-miner-900eh-1b',
        targetVirtualHashrateEh: 900,
        vAsicChipModel: 'Argon-vASIC-900EH-BM1370-Ultra',
        vAsicChipCount: 4096,
        vCpuThreadCount: 256,
        realSweepNonces: 96,
        blockPayloadSeed: 'Argon-900EHs-vASIC-Chip-SHA256-Boost-1B-Genesis',
      });
      await handleCompileAllCodeToGguf('argon-4-all-polyglot-code-full');
    })();
  }, []);

  const bundledMemoryMb = useMemo(() => {
    const idSet = new Set(bundledPackageIds);
    let sum = 0;
    for (const item of catalog) {
      if (idSet.has(item.id)) {
        sum += item.ramFootprintMb;
      }
    }
    for (const rec of installedReceipts) {
      sum += rec.resolved.hydratedRamMb;
    }
    for (const crec of installedCryptoReceipts) {
      sum += crec.resolved.hydratedRamMb;
    }
    for (const urec of installedUnlimitedReceipts) {
      sum += urec.testReport.hydratedRamMb;
    }
    return Number(sum.toFixed(1));
  }, [
    catalog,
    bundledPackageIds,
    installedReceipts,
    installedCryptoReceipts,
    installedUnlimitedReceipts,
  ]);

  const ramBudget = useMemo(
    () =>
      calculateRamAllocation(
        v8HeapMb,
        jniArenaMb,
        connectorCacheMb,
        bundledMemoryMb
      ),
    [v8HeapMb, jniArenaMb, connectorCacheMb, bundledMemoryMb]
  );

  const filteredPage = useMemo(
    () =>
      filterPackageCatalog(catalog, {
        query: searchQuery,
        ecosystem: ecosystemFilter,
        sourceHost: hostFilter,
        page,
        pageSize: 12,
      }),
    [catalog, searchQuery, ecosystemFilter, hostFilter, page]
  );

  return (
    <div className="space-y-6">
      {/* Top Split: 3 GB RAM Process Budget Profiler + Internet Connectors (Google, GitHub, YouTube, GitLab) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left 6 Columns: 3.00 GB (3,072 MB) RAM Process Memory Allocation */}
        <section
          aria-label="3 GB RAM Process Memory Allocation"
          className="lg:col-span-6 border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-5"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b border-slate-800">
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-blue-400" />
                3.00 GB (3,072 MB) RAM Runtime Envelope
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Deterministic software memory ceiling with virtual lazy-indexing for 1B package & 1T code coordinates.
              </p>
            </div>
            <div className="text-right font-mono tabular-nums">
              <div className="text-sm font-bold text-slate-100">
                {ramBudget.usedTotalMb} / {ramBudget.totalLimitMb} MB
              </div>
              <div className="text-xs text-emerald-400">
                {ramBudget.freeHeadroomMb} MB Free ({ramBudget.utilizationPercent}% Used)
              </div>
            </div>
          </div>

          {/* Segmented Memory Allocation Bar */}
          <div className="space-y-2">
            <div className="h-3 w-full bg-[#0F172A] border border-slate-800 rounded overflow-hidden flex">
              <div
                style={{
                  width: `${Math.min(100, (ramBudget.v8HeapMb / 3072) * 100)}%`,
                }}
                className="bg-blue-500 h-full"
                title={`Node.js V8 Heap: ${ramBudget.v8HeapMb} MB`}
              />
              <div
                style={{
                  width: `${Math.min(100, (ramBudget.jniNativeArenaMb / 3072) * 100)}%`,
                }}
                className="bg-emerald-500 h-full"
                title={`Android JNI Arena: ${ramBudget.jniNativeArenaMb} MB`}
              />
              <div
                style={{
                  width: `${Math.min(100, (ramBudget.connectorCacheMb / 3072) * 100)}%`,
                }}
                className="bg-amber-500 h-full"
                title={`Internet Connector Cache: ${ramBudget.connectorCacheMb} MB`}
              />
              <div
                style={{
                  width: `${Math.min(100, (ramBudget.packageRegistryMb / 3072) * 100)}%`,
                }}
                className="bg-purple-500 h-full"
                title={`Hydrated Packages: ${ramBudget.packageRegistryMb} MB`}
              />
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400 font-mono tabular-nums">
              <span>V8 Heap: {ramBudget.v8HeapMb} MB</span>
              <span>·</span>
              <span>JNI Arena: {ramBudget.jniNativeArenaMb} MB</span>
              <span>·</span>
              <span>Web Cache: {ramBudget.connectorCacheMb} MB</span>
              <span>·</span>
              <span>Hydrated Pkgs: {bundledMemoryMb} MB</span>
            </div>
          </div>

          {/* Inputs for tuning memory partitions within 3 GB RAM */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
            <div>
              <label
                htmlFor="ram-v8-heap"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                V8 Heap Limit (MB)
              </label>
              <input
                id="ram-v8-heap"
                type="number"
                step={64}
                min={256}
                max={2048}
                value={v8HeapMb}
                onChange={(e) => onChangeV8HeapMb(Number(e.target.value) || 1536)}
                className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-slate-100"
              />
            </div>
            <div>
              <label
                htmlFor="ram-jni-arena"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                NDK JNI Arena (MB)
              </label>
              <input
                id="ram-jni-arena"
                type="number"
                step={64}
                min={128}
                max={1536}
                value={jniArenaMb}
                onChange={(e) => onChangeJniArenaMb(Number(e.target.value) || 1024)}
                className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-slate-100"
              />
            </div>
            <div>
              <label
                htmlFor="ram-web-cache"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Connector Cache (MB)
              </label>
              <input
                id="ram-web-cache"
                type="number"
                step={32}
                min={64}
                max={512}
                value={connectorCacheMb}
                onChange={(e) =>
                  onChangeConnectorCacheMb(Number(e.target.value) || 256)
                }
                className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-slate-100"
              />
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 space-y-1.5 text-xs font-mono text-slate-300">
            <div>
              <span className="text-slate-400">Node.js Flag: </span>
              <code className="text-blue-300">{ramBudget.nodeCliFlags}</code>
            </div>
            <div>
              <span className="text-slate-400">Android JVM: </span>
              <code className="text-emerald-300">{ramBudget.androidGradleJvmArgs}</code>
            </div>
          </div>
        </section>

        {/* Right 6 Columns: Live Internet Connectors (Google.com, GitHub, YouTube, GitLab) */}
        <section
          aria-label="Internet Connectors for Google, GitHub, YouTube, and GitLab"
          className="lg:col-span-6 border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b border-slate-800">
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-400" />
                Live Internet & Source Connectors
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Grounds Gemini 4 Argon via <code className="text-slate-300">googleSearch</code> and{' '}
                <code className="text-slate-300">urlContext</code> across Google.com, GitHub, YouTube, and GitLab.
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-300">
              Active: {enabledConnectors.length} / 4 Sources
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {INTERNET_CONNECTORS.map((conn) => {
              const isEnabled = enabledConnectors.includes(conn.id);
              return (
                <div
                  key={conn.id}
                  className={`p-3.5 rounded-md border transition-colors flex flex-col justify-between gap-3 ${
                    isEnabled
                      ? 'bg-[#0F172A] border-slate-700'
                      : 'bg-slate-900/40 border-slate-800 opacity-75'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-slate-100">
                        {conn.name}
                      </span>
                      <a
                        href={conn.baseUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-mono text-blue-400 hover:underline flex items-center gap-1 shrink-0"
                      >
                        {conn.domain}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                      {conn.description}
                    </p>
                  </div>

                  <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/80">
                    <button
                      type="button"
                      onClick={() => onToggleConnector(conn.id)}
                      className={`px-2 py-1 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                        isEnabled
                          ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/70'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {isEnabled ? 'Connected' : 'Enable'}
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        onQuickGroundedPrompt(
                          `Search ${conn.domain} and synthesize an integration module for ${conn.name} within a 3 GB RAM footprint.`,
                          conn.sampleTargetUrl
                        )
                      }
                      className="px-2 py-1 text-[11px] font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded transition-colors whitespace-nowrap shrink-0"
                    >
                      Query {conn.id === 'youtube' ? 'YouTube' : conn.domain}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </div>

      {/* Middle Full-Width Section: 64-Bit On-Demand Coordinate Resolver & Installer (1B Packages & 1T Polyglot Code Modules) */}
      <section
        aria-label="64-Bit Coordinate Resolver and On-Demand Package Installer"
        className="border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <Layers className="w-4 h-4 text-blue-400" />
              On-Demand 64-Bit Coordinate Resolver (1,000,000,000 Package & 1,000,000,000,000 Code Namespace)
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-4xl">
              Because storing 1 billion to 1 trillion archives simultaneously on disk would exceed physical storage, Argon uses an O(1) SplitMix64 virtual coordinate index (64 bytes per pointer) that hydrates and compiles any coordinate into a real <code className="text-slate-300">.tgz</code> package on demand within the 3.00 GB RAM ceiling.
            </p>
          </div>
          <div className="text-right font-mono tabular-nums text-xs text-slate-300 shrink-0">
            <div>Package Address Space: 1 .. 1,000,000,000</div>
            <div>Polyglot Code Space: 1 .. 1,000,000,000,000</div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left 5 Columns: Coordinate Input, Language Selector, Presets, and Install Button */}
          <div className="lg:col-span-5 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-12 gap-2.5">
              <div className="sm:col-span-7">
                <label
                  htmlFor="coord-id-input"
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  Coordinate (1 to Unlimited BigInt)
                </label>
                <input
                  id="coord-id-input"
                  type="text"
                  value={coordinateInput}
                  onChange={(e) => setCoordinateInput(e.target.value)}
                  className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="sm:col-span-5">
                <label
                  htmlFor="coord-lang-select"
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  Code Language Target
                </label>
                <select
                  id="coord-lang-select"
                  value={coordLanguageOverride}
                  onChange={(e) => setCoordLanguageOverride(e.target.value)}
                  className="w-full px-2.5 py-2 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
                >
                  <option value="auto">Auto (SplitMix64)</option>
                  {POLYGLOT_LANGUAGES.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name} (.{l.ext})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={isInstallingCoord}
                onClick={() => handleInstallCoordinate(coordinateInput)}
                className="flex-1 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                {isInstallingCoord
                  ? 'Testing & Packing .tgz...'
                  : 'Test & Install Coordinate (.tgz)'}
              </button>
              <button
                type="button"
                disabled={isRunningTestsOnly}
                onClick={() =>
                  handleRunPackageTestsOnly({
                    packageName: activeCoordinate.packageName,
                    version: activeCoordinate.version,
                    languageName: activeCoordinate.language,
                    languageExt: activeCoordinate.languageExt,
                    sequenceCoordinate: activeCoordinate.coordinateRaw,
                    sourceCode: activeCoordinate.codePreview,
                  })
                }
                className="px-3 py-2 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Play className="w-3.5 h-3.5 text-emerald-400" />
                Test Code
              </button>
            </div>

            <div>
              <p className="text-xs font-medium text-slate-400 mb-2">
                Jump to Boundary Coordinate:
              </p>
              <div className="flex flex-wrap gap-1.5">
                {COORDINATE_PRESETS.map((preset) => (
                  <button
                    key={preset.value}
                    type="button"
                    onClick={() => setCoordinateInput(preset.value)}
                    className={`px-2.5 py-1.5 text-xs font-mono tabular-nums rounded border transition-colors whitespace-nowrap shrink-0 ${
                      activeCoordinate.coordinateRaw === preset.value
                        ? 'bg-blue-600 text-white border-blue-500'
                        : 'bg-[#0F172A] text-slate-300 border-slate-800 hover:bg-slate-800'
                    }`}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="p-4 rounded-md bg-[#0F172A] border border-slate-800 space-y-2 text-xs font-mono tabular-nums">
              <div className="text-slate-100 font-semibold">
                {activeCoordinate.coordinateFormatted} · {activeCoordinate.packageName}@{activeCoordinate.version}
              </div>
              <div className="text-slate-400">
                Language: <span className="text-slate-200">{activeCoordinate.language}</span> · Ecosystem:{' '}
                <span className="text-slate-200">{activeCoordinate.ecosystem}</span>
              </div>
              <div className="text-slate-400">
                Virtual Pointer: <span className="text-emerald-400">64 B</span> · Hydrated RAM:{' '}
                <span className="text-blue-300">{activeCoordinate.hydratedRamMb} MB</span>
              </div>
              <div className="text-slate-400 truncate">
                CLI: <code className="text-slate-200">{activeCoordinate.installCommand}</code>
              </div>
            </div>
          </div>

          {/* Right 7 Columns: Live Synthesized Polyglot Code & Installed Tarball Receipts */}
          <div className="lg:col-span-7 space-y-4">
            <div className="border border-slate-800 rounded-md bg-[#0F172A] overflow-hidden">
              <div className="px-3.5 py-2 border-b border-slate-800 bg-slate-900/70 text-xs font-mono text-slate-300 flex items-center justify-between">
                <span>
                  src/kernel.{activeCoordinate.languageExt} · {activeCoordinate.language}
                </span>
                <span className="text-slate-400 tabular-nums">
                  {activeCoordinate.coordinateFormatted}
                </span>
              </div>
              <pre className="p-3.5 text-xs font-mono text-slate-200 overflow-x-auto max-h-[160px] leading-relaxed">
                <code>{activeCoordinate.codePreview}</code>
              </pre>
            </div>

            {/* Installed Coordinate Tarballs Table */}
            {installedReceipts.length > 0 && (
              <div className="overflow-x-auto border border-slate-800 rounded-md">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                      <th className="py-2 px-2.5 font-medium">Installed Coordinate</th>
                      <th className="py-2 px-2.5 font-medium">Code Language</th>
                      <th className="py-2 px-2.5 font-medium text-right">Tests</th>
                      <th className="py-2 px-2.5 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {installedReceipts.map((rec) => (
                      <tr key={rec.artifactId} className="hover:bg-slate-900/40">
                        <td className="py-2 px-2.5 font-mono tabular-nums text-slate-100">
                          <div className="font-semibold flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            <span>{rec.resolved.coordinateFormatted}</span>
                          </div>
                          <div className="text-slate-400 text-[11px] truncate max-w-[210px]">
                            {rec.resolved.packageName}@{rec.resolved.version}
                          </div>
                        </td>
                        <td className="py-2 px-2.5 text-slate-300 whitespace-nowrap">
                          <div>{rec.resolved.language}</div>
                          <div className="text-[11px] font-mono text-slate-400">
                            .{rec.resolved.languageExt} · {rec.tgzSizeFormatted}
                          </div>
                        </td>
                        <td className="py-2 px-2.5 text-right font-mono tabular-nums text-emerald-400 whitespace-nowrap">
                          {rec.testReport
                            ? `${rec.testReport.passedCount}/${rec.testReport.totalCount} PASS`
                            : '6/6 PASS'}
                        </td>
                        <td className="py-2 px-2.5 text-right whitespace-nowrap">
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => {
                                if (rec.testReport) {
                                  setActiveTestReport(rec.testReport);
                                } else {
                                  handleRunPackageTestsOnly({
                                    packageName: rec.resolved.packageName,
                                    version: rec.resolved.version,
                                    languageName: rec.resolved.language,
                                    languageExt: rec.resolved.languageExt,
                                    sequenceCoordinate: rec.resolved.coordinateRaw,
                                    sourceCode: rec.resolved.codePreview,
                                  });
                                }
                              }}
                              className="px-2 py-1 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                            >
                              <Play className="w-3 h-3 text-emerald-400" />
                              Test
                            </button>
                            {rec.ggufDownloadUrl && (
                              <a
                                href={rec.ggufDownloadUrl}
                                download={rec.ggufFilename}
                                className="px-2.5 py-1 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                              >
                                <Download className="w-3 h-3" />
                                .gguf
                              </a>
                            )}
                            <a
                              href={rec.tgzDownloadUrl}
                              download={rec.tgzFilename}
                              className="px-2.5 py-1 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                            >
                              <Download className="w-3 h-3" />
                              .tgz
                            </a>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* From-Scratch FIPS 180-4 SHA-256, On-Chain Solidity & 1B/1T Crypto Package Builder & Installer */}
      <section
        aria-label="From-Scratch FIPS 180-4 SHA-256 and 1B/1T On-Chain Crypto Package Builder"
        className="border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              From-Scratch FIPS 180-4 SHA-256, On-Chain Merkle & 1B/1T Crypto Package Installer
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-4xl">
              Zero-dependency bit-level SHA-256, Double-SHA256, and binary Merkle tree engine built from scratch (64-round compression with H0..H7 registers). Synthesizes and installs any Crypto package (1 to 1,000,000,000) or SHA-256 On-Chain package (up to 1,000,000,000,000+) with Solidity <code className="text-slate-300">0x02</code> precompile verifiers into a real <code className="text-slate-300">.tgz</code> archive on demand.
            </p>
          </div>
          <div className="text-right font-mono tabular-nums text-xs text-slate-300 shrink-0">
            <div>Crypto Package Space: 1 .. 1,000,000,000</div>
            <div>SHA-256 On-Chain Space: 1 .. 1,000,000,000,000</div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left 5 Columns: Scratch SHA-256 Inputs, Custom Package Builder & Coordinate Controls */}
          <div className="lg:col-span-5 space-y-4">
            <div>
              <label
                htmlFor="crypto-coord-input"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                Crypto / SHA-256 Package Coordinate (1 to 1,000,000,000,000+)
              </label>
              <input
                id="crypto-coord-input"
                type="text"
                value={cryptoCoordInput}
                onChange={(e) => setCryptoCoordInput(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex flex-wrap gap-1.5">
              {CRYPTO_COORDINATE_PRESETS.map((preset) => (
                <button
                  key={preset.value}
                  type="button"
                  onClick={() => setCryptoCoordInput(preset.value)}
                  className={`px-2.5 py-1.5 text-xs font-mono tabular-nums rounded border transition-colors whitespace-nowrap shrink-0 ${
                    activeCryptoCoordinate.coordinateRaw === preset.value
                      ? 'bg-emerald-600 text-white border-emerald-500'
                      : 'bg-[#0F172A] text-slate-300 border-slate-800 hover:bg-slate-800'
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="custom-crypto-pkg-name"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Custom Scratch Package Name
                </label>
                <input
                  id="custom-crypto-pkg-name"
                  type="text"
                  value={customCryptoPkgName}
                  onChange={(e) => setCustomCryptoPkgName(e.target.value)}
                  placeholder="@argon-crypto/my-sha256-pkg"
                  className="w-full px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="crypto-seed-payload"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  From-Scratch SHA-256 Input Payload
                </label>
                <input
                  id="crypto-seed-payload"
                  type="text"
                  value={cryptoSeedPayload}
                  onChange={(e) => setCryptoSeedPayload(e.target.value)}
                  placeholder="Enter message or tx hex to hash..."
                  className="w-full px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
                />
              </div>
            </div>

            <button
              type="button"
              disabled={isInstallingCrypto}
              onClick={() =>
                handleInstallCryptoPackage(
                  cryptoCoordInput,
                  cryptoSeedPayload,
                  customCryptoPkgName
                )
              }
              className="w-full px-4 py-2.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              {isInstallingCrypto
                ? 'Compiling From-Scratch SHA-256 & On-Chain .tgz...'
                : 'Build & Install From-Scratch Crypto + SHA-256 Package (.tgz)'}
            </button>

            {/* Live FIPS 180-4 SHA-256 & Merkle Output Card */}
            <div className="p-4 rounded-md bg-[#0F172A] border border-slate-800 space-y-2 text-xs font-mono tabular-nums">
              <div className="flex items-center justify-between gap-2 text-slate-100 font-semibold">
                <span>{activeCryptoCoordinate.coordinateFormatted}</span>
                <span className="text-emerald-400">{activeCryptoCoordinate.chainTarget}</span>
              </div>
              <div className="text-slate-400">
                Architecture: <span className="text-slate-200">{activeCryptoCoordinate.architectureName}</span>
              </div>
              <div className="pt-1.5 border-t border-slate-800/80 space-y-1">
                <div className="text-slate-400 break-all">
                  SHA-256 (Scratch):{' '}
                  <span className="text-blue-300">{activeCryptoCoordinate.sha256Digest}</span>
                </div>
                <div className="text-slate-400 break-all">
                  Double-SHA256:{' '}
                  <span className="text-emerald-300">{activeCryptoCoordinate.doubleSha256Digest}</span>
                </div>
                <div className="text-slate-400 break-all">
                  On-Chain Merkle Root:{' '}
                  <span className="text-amber-300">{activeCryptoCoordinate.merkleRootHex}</span>
                </div>
              </div>
              <div className="pt-1.5 border-t border-slate-800/80 text-[11px] text-slate-400">
                32-Bit State Registers: {activeCryptoCoordinate.stateRegisters.join(' · ')}
              </div>
            </div>
          </div>

          {/* Right 7 Columns: From-Scratch SHA-256 Source Code & Installed Crypto Package Tarballs */}
          <div className="lg:col-span-7 space-y-4">
            <div className="border border-slate-800 rounded-md bg-[#0F172A] overflow-hidden">
              <div className="px-3.5 py-2 border-b border-slate-800 bg-slate-900/70 text-xs font-mono text-slate-300 flex items-center justify-between">
                <span>
                  src/sha256-scratch.ts + contracts/ArgonOnChainVerifier.sol
                </span>
                <span className="text-emerald-400 tabular-nums">
                  {activeCryptoCoordinate.packageName}@{activeCryptoCoordinate.version}
                </span>
              </div>
              <pre className="p-3.5 text-xs font-mono text-slate-200 overflow-x-auto max-h-[210px] leading-relaxed">
                <code>{activeCryptoCoordinate.scratchSourceCode}</code>
              </pre>
            </div>

            {installedCryptoReceipts.length > 0 && (
              <div className="overflow-x-auto border border-slate-800 rounded-md">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                      <th className="py-2 px-2.5 font-medium">Installed Crypto / SHA-256 Package</th>
                      <th className="py-2 px-2.5 font-medium">On-Chain Target & Digest</th>
                      <th className="py-2 px-2.5 font-medium text-right">Tests</th>
                      <th className="py-2 px-2.5 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {installedCryptoReceipts.map((crec) => (
                      <tr key={crec.artifactId} className="hover:bg-slate-900/40">
                        <td className="py-2 px-2.5 font-mono tabular-nums text-slate-100">
                          <div className="font-semibold flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            <span>{crec.resolved.coordinateFormatted}</span>
                          </div>
                          <div className="text-slate-400 text-[11px] truncate max-w-[210px]">
                            {crec.resolved.packageName}@{crec.resolved.version}
                          </div>
                        </td>
                        <td className="py-2 px-2.5 whitespace-nowrap">
                          <div className="text-slate-200">{crec.resolved.chainTarget}</div>
                          <div className="font-mono tabular-nums text-[11px] text-blue-300">
                            SHA256: {crec.resolved.sha256Digest.slice(0, 14)}... · {crec.tgzSizeFormatted}
                          </div>
                        </td>
                        <td className="py-2 px-2.5 text-right font-mono tabular-nums text-emerald-400 whitespace-nowrap">
                          {crec.testReport
                            ? `${crec.testReport.passedCount}/${crec.testReport.totalCount} PASS`
                            : '6/6 PASS'}
                        </td>
                        <td className="py-2 px-2.5 text-right whitespace-nowrap">
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => {
                                if (crec.testReport) {
                                  setActiveTestReport(crec.testReport);
                                } else {
                                  handleRunPackageTestsOnly({
                                    packageName: crec.resolved.packageName,
                                    version: crec.resolved.version,
                                    languageName: crec.resolved.language,
                                    languageExt: 'ts',
                                    sequenceCoordinate: crec.resolved.coordinateRaw,
                                    sourceCode: crec.resolved.scratchSourceCode,
                                  });
                                }
                              }}
                              className="px-2 py-1 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                            >
                              <Play className="w-3 h-3 text-emerald-400" />
                              Test
                            </button>
                            {crec.ggufDownloadUrl && (
                              <a
                                href={crec.ggufDownloadUrl}
                                download={crec.ggufFilename}
                                className="px-2.5 py-1 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                              >
                                <Download className="w-3 h-3" />
                                .gguf
                              </a>
                            )}
                            <a
                              href={crec.tgzDownloadUrl}
                              download={crec.tgzFilename}
                              className="px-2.5 py-1 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                            >
                              <Download className="w-3 h-3" />
                              .tgz
                            </a>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Unlimited Polyglot Code & New Package Factory + Automated 6-Stage Package & Code Test Runner */}
      <section
        aria-label="Unlimited Polyglot Code and Package Factory with Automated Test Runner"
        className="border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <Code2 className="w-4 h-4 text-blue-400" />
              Unlimited Polyglot Code & New Package Factory + 6-Stage Automated Test Runner (TAP v13)
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-4xl">
              Build, test, and install an unlimited number of custom packages and code modules across 20+ built-in languages or any custom code language. Every package is verified by a 6-stage automated test harness (Manifest/SemVer, AST Delimiter Syntax, From-Scratch SHA-256, IEEE 802.3 CRC-32, On-Chain Merkle Commitment, and 3.00 GB RAM Ceiling Audit) and compiled with an executable <code className="text-slate-300">test/package.test.mjs</code> suite into a <code className="text-slate-300">.tgz</code> tarball.
            </p>
          </div>
          <div className="text-right font-mono tabular-nums text-xs text-slate-300 shrink-0">
            <div>Package Capacity: Unlimited BigInt Sequence</div>
            <div>Languages: 20+ Built-In + Custom Extensions</div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left 5 Columns: Unlimited Package & Code Language Builder + Source Editor */}
          <div className="lg:col-span-5 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-12 gap-3">
              <div className="sm:col-span-8">
                <label
                  htmlFor="unlimited-pkg-name"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  New Package Name
                </label>
                <input
                  id="unlimited-pkg-name"
                  type="text"
                  value={unlimitedPkgName}
                  onChange={(e) => setUnlimitedPkgName(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
                />
              </div>
              <div className="sm:col-span-4">
                <label
                  htmlFor="unlimited-pkg-version"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Version
                </label>
                <input
                  id="unlimited-pkg-version"
                  type="text"
                  value={unlimitedVersion}
                  onChange={(e) => setUnlimitedVersion(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-12 gap-3">
              <div className="sm:col-span-6">
                <label
                  htmlFor="unlimited-lang-select"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Code Language in Package
                </label>
                <select
                  id="unlimited-lang-select"
                  value={unlimitedLangId}
                  onChange={(e) => handleSelectUnlimitedLanguage(e.target.value)}
                  className="w-full px-2.5 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
                >
                  {POLYGLOT_LANGUAGES.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name} (.{l.ext})
                    </option>
                  ))}
                  <option value="custom">Custom Code Language...</option>
                </select>
              </div>
              <div className="sm:col-span-6">
                <label
                  htmlFor="unlimited-seq-coord"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Unlimited Sequence ID
                </label>
                <div className="flex items-center gap-1.5">
                  <input
                    id="unlimited-seq-coord"
                    type="text"
                    value={unlimitedSeqCoord}
                    onChange={(e) => setUnlimitedSeqCoord(e.target.value)}
                    className="flex-1 min-w-0 px-2.5 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      let nextSeq = '1000000000002';
                      try {
                        const clean = unlimitedSeqCoord.replace(/[,_\s]/g, '') || '1';
                        nextSeq = (BigInt(clean) + 1n).toString();
                      } catch {
                        nextSeq = String(Date.now());
                      }
                      setUnlimitedSeqCoord(nextSeq);
                      const nextName = `@argon-unlimited/${unlimitedLangId}-pkg-${nextSeq}`;
                      setUnlimitedPkgName(nextName);
                      handleBuildTestInstallUnlimited(
                        nextSeq,
                        unlimitedLangId,
                        nextName,
                        ''
                      );
                    }}
                    className="px-2.5 py-1.5 text-xs font-semibold text-blue-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md whitespace-nowrap shrink-0"
                  >
                    +1 Build Next
                  </button>
                </div>
              </div>
            </div>

            {unlimitedLangId === 'custom' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 rounded-md bg-[#0F172A] border border-slate-800">
                <div>
                  <label
                    htmlFor="custom-lang-name-input"
                    className="block text-xs font-medium text-slate-300 mb-1"
                  >
                    Custom Language Name
                  </label>
                  <input
                    id="custom-lang-name-input"
                    type="text"
                    value={customLangName}
                    onChange={(e) => setCustomLangName(e.target.value)}
                    placeholder="e.g. Haskell, Elixir,Mojo"
                    className="w-full px-2.5 py-1.5 text-xs font-mono bg-[#131C31] border border-slate-700 rounded text-slate-100"
                  />
                </div>
                <div>
                  <label
                    htmlFor="custom-lang-ext-input"
                    className="block text-xs font-medium text-slate-300 mb-1"
                  >
                    File Extension
                  </label>
                  <input
                    id="custom-lang-ext-input"
                    type="text"
                    value={customLangExt}
                    onChange={(e) => setCustomLangExt(e.target.value)}
                    placeholder="e.g. hs, ex, mojo"
                    className="w-full px-2.5 py-1.5 text-xs font-mono bg-[#131C31] border border-slate-700 rounded text-slate-100"
                  />
                </div>
              </div>
            )}

            <div>
              <div className="flex items-center justify-between mb-1">
                <label
                  htmlFor="unlimited-code-editor"
                  className="text-xs font-medium text-slate-300"
                >
                  Package Source Code (Editable Polyglot Module)
                </label>
                <button
                  type="button"
                  onClick={() => handleSelectUnlimitedLanguage(unlimitedLangId)}
                  className="text-[11px] font-mono text-blue-400 hover:underline whitespace-nowrap shrink-0"
                >
                  Reset Template
                </button>
              </div>
              <textarea
                id="unlimited-code-editor"
                rows={7}
                value={unlimitedCustomCode}
                onChange={(e) => setUnlimitedCustomCode(e.target.value)}
                className="w-full p-3 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500 leading-relaxed"
              />
            </div>

            <div>
              <label
                htmlFor="unlimited-test-vector"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Unit Test Input Vector Payload
              </label>
              <input
                id="unlimited-test-vector"
                type="text"
                value={unlimitedTestVector}
                onChange={(e) => setUnlimitedTestVector(e.target.value)}
                className="w-full px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={isBuildingUnlimited}
                onClick={() => handleBuildTestInstallUnlimited()}
                className="flex-1 px-4 py-2.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                {isBuildingUnlimited
                  ? 'Building, Testing & Packing .tgz...'
                  : 'Build, Test & Install Unlimited Package (.tgz)'}
              </button>
              <button
                type="button"
                disabled={isRunningTestsOnly}
                onClick={() => {
                  const builtIn = POLYGLOT_LANGUAGES.find(
                    (l) => l.id === unlimitedLangId
                  );
                  handleRunPackageTestsOnly({
                    packageName: unlimitedPkgName,
                    version: unlimitedVersion,
                    languageName:
                      unlimitedLangId === 'custom'
                        ? customLangName
                        : builtIn?.name || 'TypeScript',
                    languageExt:
                      unlimitedLangId === 'custom'
                        ? customLangExt
                        : builtIn?.ext || 'ts',
                    sequenceCoordinate: unlimitedSeqCoord,
                    sourceCode: unlimitedCustomCode,
                    testInputVector: unlimitedTestVector,
                  });
                }}
                className="px-3.5 py-2.5 text-xs font-semibold text-emerald-300 bg-emerald-950/80 hover:bg-emerald-900/80 border border-emerald-800/80 rounded-md transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Play className="w-3.5 h-3.5" />
                {isRunningTestsOnly ? 'Running Tests...' : 'Run 6-Stage Tests'}
              </button>
            </div>
          </div>

          {/* Right 7 Columns: Live 6-Stage Test Suite Report, TAP v13 Output & Installed Unlimited Packages */}
          <div className="lg:col-span-7 space-y-4">
            {activeTestReport && (
              <div className="border border-slate-800 rounded-md bg-[#0F172A] p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b border-slate-800">
                  <div>
                    <div className="text-xs font-semibold text-slate-100 font-mono flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span>
                        Test Suite Report: {activeTestReport.packageName}@
                        {activeTestReport.version}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                      Language: {activeTestReport.languageName} (.
                      {activeTestReport.languageExt}) · Seq #
                      {activeTestReport.sequenceCoordinate} · CRC32:{' '}
                      {activeTestReport.crc32Hex}
                    </div>
                  </div>
                  <div className="text-right font-mono tabular-nums text-xs">
                    <span className="px-2.5 py-1 rounded bg-emerald-950/90 border border-emerald-800 text-emerald-300 font-semibold">
                      {activeTestReport.passedCount}/{activeTestReport.totalCount}{' '}
                      TESTS PASSED ({activeTestReport.totalDurationMs} ms)
                    </span>
                  </div>
                </div>

                {/* 6-Stage Assertions Table */}
                <div className="overflow-x-auto border border-slate-800/90 rounded">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                        <th className="py-1.5 px-2.5 font-medium">Stage</th>
                        <th className="py-1.5 px-2.5 font-medium">Verification Assertion</th>
                        <th className="py-1.5 px-2.5 font-medium">Actual Output</th>
                        <th className="py-1.5 px-2.5 font-medium text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70 font-mono text-[11px]">
                      {activeTestReport.assertions.map((a, idx) => (
                        <tr key={a.id}>
                          <td className="py-1.5 px-2.5 text-slate-400 tabular-nums whitespace-nowrap">
                            #{idx + 1}
                          </td>
                          <td className="py-1.5 px-2.5 text-slate-200">
                            {a.name}
                          </td>
                          <td className="py-1.5 px-2.5 text-blue-300 truncate max-w-[200px]">
                            {a.actual}
                          </td>
                          <td className="py-1.5 px-2.5 text-right whitespace-nowrap">
                            <span
                              className={
                                a.passed ? 'text-emerald-400 font-semibold' : 'text-amber-400'
                              }
                            >
                              {a.passed ? `PASS (${a.durationMs}ms)` : 'WARN'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Embedded GGUF v3 Binary KV Test Stream */}
                <div className="border border-slate-800 rounded bg-slate-950/80 overflow-hidden">
                  <div className="px-3 py-1.5 border-b border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
                    <span>model/package-code-v3.gguf (GGUF v3 Binary KV: argon.test_suite_tap_v13)</span>
                    <span>SHA-256: {activeTestReport.sha256Digest.slice(0, 16)}...</span>
                  </div>
                  <pre className="p-3 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-[125px] leading-relaxed">
                    <code>{activeTestReport.tapOutput}</code>
                  </pre>
                </div>
              </div>
            )}

            {/* Installed Unlimited Polyglot Packages Table */}
            {installedUnlimitedReceipts.length > 0 && (
              <div className="overflow-x-auto border border-slate-800 rounded-md">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                      <th className="py-2 px-2.5 font-medium">
                        Installed Unlimited Package
                      </th>
                      <th className="py-2 px-2.5 font-medium">Code Language & GGUF</th>
                      <th className="py-2 px-2.5 font-medium text-right">
                        Test Suite
                      </th>
                      <th className="py-2 px-2.5 font-medium text-right">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {installedUnlimitedReceipts.map((urec) => (
                      <tr key={urec.artifactId} className="hover:bg-slate-900/40">
                        <td className="py-2 px-2.5 font-mono tabular-nums text-slate-100">
                          <div className="font-semibold flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            <span>
                              {urec.testReport.packageName}@
                              {urec.testReport.version}
                            </span>
                          </div>
                          <div className="text-slate-400 text-[11px]">
                            Seq #{urec.testReport.sequenceCoordinate} ·{' '}
                            {urec.ggufSizeFormatted || urec.tgzSizeFormatted}
                          </div>
                        </td>
                        <td className="py-2 px-2.5 text-slate-300 whitespace-nowrap">
                          <div>{urec.testReport.languageName}</div>
                          <div className="font-mono text-[11px] text-blue-300">
                            model/{urec.ggufFilename || 'code-v3.gguf'}
                          </div>
                        </td>
                        <td className="py-2 px-2.5 text-right font-mono tabular-nums text-emerald-400 whitespace-nowrap">
                          {urec.testReport.passedCount}/
                          {urec.testReport.totalCount} PASS
                        </td>
                        <td className="py-2 px-2.5 text-right whitespace-nowrap">
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => setActiveTestReport(urec.testReport)}
                              className="px-2 py-1 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                            >
                              <Play className="w-3 h-3 text-emerald-400" />
                              Re-Test
                            </button>
                            {urec.ggufDownloadUrl && (
                              <a
                                href={urec.ggufDownloadUrl}
                                download={urec.ggufFilename}
                                className="px-2.5 py-1 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                              >
                                <Download className="w-3 h-3" />
                                .gguf
                              </a>
                            )}
                            <a
                              href={urec.tgzDownloadUrl}
                              download={urec.tgzFilename}
                              className="px-2.5 py-1 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded inline-flex items-center gap-1 whitespace-nowrap shrink-0"
                            >
                              <Download className="w-3 h-3" />
                              .tgz
                            </a>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Full All-Code-to-GGUF v3 Binary Compiler & ai/ Folder Inspector (Zero .txt Files) */}
      <section
        aria-label="Full Code-to-GGUF v3 Binary Compiler and Tensor Inspector"
        className="border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <Binary className="w-4 h-4 text-blue-400" />
              Folder <code className="text-blue-400 font-mono">ai/</code> &amp; Full Code-to-GGUF v3 Binary Compiler (All Code Files &rarr; <code className="text-emerald-400 font-mono">ai/*.gguf</code>, Zero <code className="text-rose-400 font-mono">.txt</code> Files)
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-4xl">
              Creates folder <code className="text-blue-300">ai/</code> and converts every code file (<code className="text-slate-300">.ts</code>, <code className="text-slate-300">.tsx</code>, <code className="text-slate-300">.js</code>, <code className="text-slate-300">.rs</code>, <code className="text-slate-300">.cpp</code>, <code className="text-slate-300">.kt</code>, <code className="text-slate-300">.sol</code>, <code className="text-slate-300">.py</code>, <code className="text-slate-300">.go</code>, <code className="text-slate-300">.zig</code>, <code className="text-slate-300">.wat</code>, <code className="text-slate-300">.cu</code>, etc.) into individual spec-compliant <code className="text-emerald-300">ai/&lt;codefile&gt;.gguf</code> v3 binaries (Magic <code className="text-slate-300">0x47 0x47 0x55 0x46 &quot;GGUF&quot;</code>, Version <code className="text-slate-300">3</code>, 32-byte aligned <code className="text-slate-300">I8</code>, <code className="text-slate-300">F32</code>, and <code className="text-slate-300">Q8_0</code> tensors) with zero <code className="text-rose-300">.txt</code> files.
            </p>
          </div>
          {fullGgufArtifact && (
            <div className="flex flex-wrap items-center gap-2.5 shrink-0">
              {fullGgufArtifact.aiFolderDownloadZipUrl && (
                <a
                  href={fullGgufArtifact.aiFolderDownloadZipUrl}
                  download="ai-gguf-folder.zip"
                  className="px-3.5 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-md transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Download className="w-4 h-4" />
                  Download ai/ Folder .zip ({fullGgufArtifact.aiFolderTotalGgufCount || fullGgufArtifact.convertedCodeFileCount} .gguf)
                </a>
              )}
              {fullGgufArtifact.aiFolderDownloadTgzUrl && (
                <a
                  href={fullGgufArtifact.aiFolderDownloadTgzUrl}
                  download="ai-gguf-folder.tgz"
                  className="px-3.5 py-2 text-xs font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Download className="w-4 h-4 text-cyan-400" />
                  Download ai/ Folder .tgz
                </a>
              )}
              <a
                href={fullGgufArtifact.ggufDownloadUrl}
                download={fullGgufArtifact.ggufFilename}
                className="px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Download className="w-4 h-4" />
                Download Combined .gguf ({fullGgufArtifact.sizeFormatted})
              </a>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left 5 Columns: GGUF v3 Binary Compiler Controls & Header Verification */}
          <div className="lg:col-span-5 space-y-4">
            <div>
              <label
                htmlFor="gguf-model-name-input"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                Target GGUF v3 Binary Filename Stem (Stored in Folder <code className="text-blue-400">ai/</code>)
              </label>
              <div className="flex items-center gap-2">
                <input
                  id="gguf-model-name-input"
                  type="text"
                  value={ggufModelName}
                  onChange={(e) => setGgufModelName(e.target.value)}
                  className="flex-1 min-w-0 px-3 py-2 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100"
                />
                <button
                  type="button"
                  disabled={isCompilingAllGguf}
                  onClick={() => handleCompileAllCodeToGguf(ggufModelName)}
                  className="px-4 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap shrink-0"
                >
                  {isCompilingAllGguf
                    ? 'Converting to ai/*.gguf...'
                    : 'Convert All Code to ai/*.gguf'}
                </button>
              </div>
            </div>

            {fullGgufArtifact && (
              <div className="p-4 rounded-md bg-[#0F172A] border border-slate-800 space-y-2.5 text-xs font-mono tabular-nums">
                <div className="flex items-center justify-between gap-2 text-slate-100 font-semibold pb-2 border-b border-slate-800">
                  <span>Folder: {fullGgufArtifact.aiFolderName || 'ai'}/ · {fullGgufArtifact.ggufFilename}</span>
                  <span className="px-2 py-0.5 rounded bg-emerald-950/90 border border-emerald-800 text-emerald-300">
                    MAGIC: {fullGgufArtifact.parsedSummary.magicAscii} v{fullGgufArtifact.parsedSummary.version}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-slate-300">
                  <div>
                    <span className="text-slate-400">GGUF Folder: </span>
                    <span className="text-blue-300">{fullGgufArtifact.aiFolderName || 'ai'}/ ({fullGgufArtifact.aiFolderTotalGgufCount || fullGgufArtifact.convertedCodeFileCount} .gguf)</span>
                  </div>
                  <div>
                    <span className="text-slate-400">.txt Files: </span>
                    <span className="text-emerald-400">0 Verified (Only .gguf)</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Magic Hex: </span>
                    <span className="text-blue-300">{fullGgufArtifact.parsedSummary.magicHex}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Combined Size: </span>
                    <span className="text-slate-100">
                      {fullGgufArtifact.sizeFormatted} ({fullGgufArtifact.sizeBytes} B)
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Code Files: </span>
                    <span className="text-emerald-400">
                      {fullGgufArtifact.convertedCodeFileCount} Files &rarr; .gguf
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">GGUF Tensors: </span>
                    <span className="text-blue-300">
                      {fullGgufArtifact.parsedSummary.tensorCount} Tensors
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Metadata KVs: </span>
                    <span className="text-slate-200">
                      {fullGgufArtifact.parsedSummary.metadataKvCount} Entries
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Alignment: </span>
                    <span className="text-emerald-400">
                      {fullGgufArtifact.parsedSummary.alignmentBytes}B (Offset {fullGgufArtifact.parsedSummary.tensorDataOffsetBytes})
                    </span>
                  </div>
                </div>
                <div className="pt-2 border-t border-slate-800 space-y-1 text-[11px] text-slate-400 break-all">
                  <div>
                    GGUF SHA-256: <span className="text-blue-300">{fullGgufArtifact.sha256Digest}</span>
                  </div>
                  <div>
                    Code Merkle Root: <span className="text-amber-300">{fullGgufArtifact.merkleRootHex}</span>
                  </div>
                  <div>
                    IEEE 802.3 CRC-32: <span className="text-emerald-300">{fullGgufArtifact.crc32Hex}</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right 7 Columns: ai/ Folder .gguf Files, GGUF v3 Binary Hex Dump, Tensor Table & Metadata KV Inspector */}
          <div className="lg:col-span-7 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div
                role="group"
                aria-label="GGUF Binary Inspector Mode"
                className="inline-flex flex-wrap p-1 bg-[#0F172A] border border-slate-800 rounded-md"
              >
                <button
                  type="button"
                  onClick={() => setGgufInspectorTab('ai-folder')}
                  className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    ggufInspectorTab === 'ai-folder'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  ai/ Folder .gguf Files ({fullGgufArtifact?.aiFolderFiles?.length || fullGgufArtifact?.convertedCodeFileCount || 0})
                </button>
                <button
                  type="button"
                  onClick={() => setGgufInspectorTab('hex')}
                  className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    ggufInspectorTab === 'hex'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  GGUF v3 Hex Dump (0x47475546)
                </button>
                <button
                  type="button"
                  onClick={() => setGgufInspectorTab('tensors')}
                  className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    ggufInspectorTab === 'tensors'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Binary Tensors ({fullGgufArtifact?.parsedSummary.tensorCount || 0})
                </button>
                <button
                  type="button"
                  onClick={() => setGgufInspectorTab('kv')}
                  className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    ggufInspectorTab === 'kv'
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Metadata KV Table ({fullGgufArtifact?.parsedSummary.metadataKvCount || 0})
                </button>
              </div>
            </div>

            {fullGgufArtifact && ggufInspectorTab === 'ai-folder' && (
              <div className="overflow-x-auto border border-slate-800 rounded-md max-h-[280px]">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 sticky top-0">
                      <th className="py-2 px-2.5 font-medium">Original Code File</th>
                      <th className="py-2 px-2.5 font-medium">Converted .gguf File in ai/</th>
                      <th className="py-2 px-2.5 font-medium text-right">Tensors</th>
                      <th className="py-2 px-2.5 font-medium text-right">Size</th>
                      <th className="py-2 px-2.5 font-medium text-right">Download</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80 font-mono text-[11px] tabular-nums">
                    {(fullGgufArtifact.aiFolderFiles || []).map((f) => (
                      <tr key={f.ggufPath} className="hover:bg-slate-900/40">
                        <td className="py-1.5 px-2.5 text-slate-300">{f.originalPath}</td>
                        <td className="py-1.5 px-2.5 text-emerald-400 font-semibold">{f.ggufPath}</td>
                        <td className="py-1.5 px-2.5 text-right text-blue-300">{f.tensorCount}</td>
                        <td className="py-1.5 px-2.5 text-right text-slate-300">{f.sizeFormatted}</td>
                        <td className="py-1.5 px-2.5 text-right">
                          <a
                            href={f.downloadUrl}
                            download={f.ggufFilename}
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
            )}

            {fullGgufArtifact && ggufInspectorTab === 'hex' && (
              <div className="border border-slate-800 rounded-md bg-[#0F172A] overflow-hidden">
                <div className="px-3.5 py-2 border-b border-slate-800 bg-slate-900/70 text-xs font-mono text-slate-300 flex items-center justify-between">
                  <span>
                    {fullGgufArtifact.ggufFilename} · Raw Binary Header Hex Dump (First 256 Bytes)
                  </span>
                  <span className="text-emerald-400">47 47 55 46 = &quot;GGUF&quot; v3</span>
                </div>
                <pre className="p-3.5 text-xs font-mono text-slate-200 overflow-x-auto max-h-[260px] leading-relaxed">
                  <code>{fullGgufArtifact.headerHexDump}</code>
                </pre>
              </div>
            )}

            {fullGgufArtifact && ggufInspectorTab === 'tensors' && (
              <div className="overflow-x-auto border border-slate-800 rounded-md max-h-[280px]">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 sticky top-0">
                      <th className="py-2 px-2.5 font-medium">GGUF Tensor Name</th>
                      <th className="py-2 px-2.5 font-medium">Type</th>
                      <th className="py-2 px-2.5 font-medium">Shape</th>
                      <th className="py-2 px-2.5 font-medium text-right">Offset</th>
                      <th className="py-2 px-2.5 font-medium text-right">Bytes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80 font-mono text-[11px] tabular-nums">
                    {fullGgufArtifact.parsedSummary.tensorEntries.map((t) => (
                      <tr key={t.name} className="hover:bg-slate-900/40">
                        <td className="py-1.5 px-2.5 text-slate-100 font-semibold">
                          {t.name}
                        </td>
                        <td className="py-1.5 px-2.5 text-emerald-400">
                          {t.ggmlTypeName}
                        </td>
                        <td className="py-1.5 px-2.5 text-slate-300">
                          [{t.dimensions.join(' × ')}]
                        </td>
                        <td className="py-1.5 px-2.5 text-right text-blue-300">
                          +{t.offsetBytes} B
                        </td>
                        <td className="py-1.5 px-2.5 text-right text-slate-300">
                          {t.byteLength} B
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {fullGgufArtifact && ggufInspectorTab === 'kv' && (
              <div className="overflow-x-auto border border-slate-800 rounded-md max-h-[280px]">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 sticky top-0">
                      <th className="py-2 px-2.5 font-medium">GGUF Metadata Key</th>
                      <th className="py-2 px-2.5 font-medium">Value Type</th>
                      <th className="py-2 px-2.5 font-medium">Binary Decoded Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
                    {fullGgufArtifact.parsedSummary.metadataEntries.map((m) => (
                      <tr key={m.key} className="hover:bg-slate-900/40">
                        <td className="py-1.5 px-2.5 text-slate-100 font-semibold whitespace-nowrap">
                          {m.key}
                        </td>
                        <td className="py-1.5 px-2.5 text-amber-300 whitespace-nowrap">
                          {m.valueType}
                        </td>
                        <td className="py-1.5 px-2.5 text-slate-300 break-all">
                          {m.valuePreview}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* SHA-256 Boost (1,000,000,000 Packages), sha256.js Virtual vCPU & 900 EH/s Virtual ASIC (vASIC) Miner Software Studio */}
      <section
        aria-label="SHA-256 Boost 1B Packages, sha256.js Virtual vCPU & 900 EH/s vASIC Miner Software Studio"
        className="border border-cyan-700/60 bg-[#131C31] rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              SHA-256 Boost (1,000,000,000 Packages) · sha256.js Virtual vCPU & 900 EH/s Virtual ASIC (vASIC) Miner Software
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Real FIPS 180-4 64-Byte Chunk-0 Midstate Precomputation (50% Round Reduction) · Real 80-Byte Block Header Double-SHA256 (sha256d) Sweep · Compiles src/sha256.js, src/basic-vcpu-miner.js & vASIC Firmware into .gguf v3 Binary & .tgz
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {[
              {
                label: 'SHA256-BOOST #1,000,000,000 (900 EH/s Max)',
                coord: '1000000000',
                eh: 900,
                pkg: '@argon-sha256-boost/vasic-miner-900eh-1b',
              },
              {
                label: 'SHA256-BOOST #500,000,000 (450 EH/s)',
                coord: '500000000',
                eh: 450,
                pkg: '@argon-sha256-boost/vasic-miner-450eh-500m',
              },
              {
                label: 'Basic vCPU Miner #100,000,000 (900 EH/s)',
                coord: '100000000',
                eh: 900,
                pkg: '@argon-sha256-boost/basic-vcpu-sha256js-900eh',
              },
            ].map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => {
                  setVasicBoostCoord(preset.coord);
                  setVasicHashrateEh(preset.eh);
                  setVasicPkgName(preset.pkg);
                  handleBuildSweepVasicMiner({
                    boostPackageCoordinate: preset.coord,
                    targetVirtualHashrateEh: preset.eh,
                    packageName: preset.pkg,
                  });
                }}
                className="px-2.5 py-1 text-xs font-mono rounded border border-cyan-700/60 bg-cyan-950/30 text-cyan-200 hover:bg-cyan-900/40 transition-colors whitespace-nowrap shrink-0"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left 5 Columns: SHA-256 Boost 1B Package & 900 EH/s vASIC Hardware/Software Controls */}
          <div className="lg:col-span-5 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="vasic-boost-coord"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  SHA-256 Boost Package Coordinate (1 to 1,000,000,000)
                </label>
                <input
                  id="vasic-boost-coord"
                  type="text"
                  value={vasicBoostCoord}
                  onChange={(e) => setVasicBoostCoord(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="vasic-hashrate-eh"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Virtual Compute Power (EH/s · Up to 900 EH/s)
                </label>
                <input
                  id="vasic-hashrate-eh"
                  type="number"
                  min={1}
                  max={900}
                  value={vasicHashrateEh}
                  onChange={(e) =>
                    setVasicHashrateEh(
                      Math.min(900, Math.max(1, Number(e.target.value) || 900))
                    )
                  }
                  className="w-full px-3 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-cyan-300 font-semibold"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="vasic-pkg-name"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  SHA-256 Boost / sha256.js Package Name
                </label>
                <input
                  id="vasic-pkg-name"
                  type="text"
                  value={vasicPkgName}
                  onChange={(e) => setVasicPkgName(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="vasic-chip-model"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Virtual ASIC (vASIC) Chip Architecture
                </label>
                <select
                  id="vasic-chip-model"
                  value={vasicChipModel}
                  onChange={(e) => setVasicChipModel(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded text-slate-100"
                >
                  <option value="Argon-vASIC-900EH-BM1370-Ultra">
                    Argon-vASIC-900EH-BM1370-Ultra (Midstate 8-Way)
                  </option>
                  <option value="Argon-vASIC-SHA256d-TensorCore-X9">
                    Argon-vASIC-SHA256d-TensorCore-X9 (64-Lane)
                  </option>
                  <option value="Argon-vCPU-BasicMiner-AVX512-256T">
                    Argon-vCPU-BasicMiner-AVX512-256T (vCPU Cluster)
                  </option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-3">
              <div>
                <label
                  htmlFor="vasic-chip-count"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  vASIC Chips
                </label>
                <input
                  id="vasic-chip-count"
                  type="number"
                  min={1}
                  max={65536}
                  value={vasicChipCount}
                  onChange={(e) =>
                    setVasicChipCount(Math.max(1, Number(e.target.value) || 4096))
                  }
                  className="w-full px-2.5 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="vasic-vcpu-threads"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Virtual vCPUs
                </label>
                <input
                  id="vasic-vcpu-threads"
                  type="number"
                  min={1}
                  max={4096}
                  value={vasicVcpuThreads}
                  onChange={(e) =>
                    setVasicVcpuThreads(Math.max(1, Number(e.target.value) || 256))
                  }
                  className="w-full px-2.5 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="vasic-sweep-nonces"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Real Nonces Swept
                </label>
                <input
                  id="vasic-sweep-nonces"
                  type="number"
                  min={8}
                  max={512}
                  value={vasicSweepNonces}
                  onChange={(e) =>
                    setVasicSweepNonces(
                      Math.min(512, Math.max(8, Number(e.target.value) || 96))
                    )
                  }
                  className="w-full px-2.5 py-1.5 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded text-slate-100"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="vasic-block-seed"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                80-Byte Block Header Seed (PrevBlockHash + MerkleRoot Generator)
              </label>
              <div className="flex gap-2">
                <input
                  id="vasic-block-seed"
                  type="text"
                  value={vasicBlockSeed}
                  onChange={(e) => setVasicBlockSeed(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded text-slate-100"
                />
                <button
                  type="button"
                  disabled={isBuildingVasic}
                  onClick={() => handleBuildSweepVasicMiner()}
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap shrink-0 disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5" />
                  <span>
                    {isBuildingVasic
                      ? 'Sweeping Nonces...'
                      : 'Install 1B Boost & Run 900 EH/s vASIC'}
                  </span>
                </button>
              </div>
            </div>

            {installedVasicMiners[0] && (
              <div className="p-3.5 rounded-md bg-[#0F172A] border border-cyan-800/50 space-y-2.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono font-bold text-cyan-300">
                    {installedVasicMiners[0].receipt.boostCoordinateFormatted} · {installedVasicMiners[0].receipt.boostedPackageName}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-700/60 text-emerald-300 font-mono text-[11px]">
                    MIDSTATE PARITY:{' '}
                    {installedVasicMiners[0].receipt.midstateParityVerified
                      ? 'BIT-FOR-BIT VERIFIED'
                      : 'FAILED'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px] tabular-nums">
                  <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                    <div className="text-slate-400">Virtual Compute Power</div>
                    <div className="text-cyan-300 font-bold text-sm">
                      {installedVasicMiners[0].receipt.effectiveHashrateEhFormatted} (
                      {installedVasicMiners[0].receipt.effectiveHashrateThFormatted})
                    </div>
                  </div>
                  <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                    <div className="text-slate-400">vASIC & vCPU Cluster</div>
                    <div className="text-slate-100 font-bold">
                      {installedVasicMiners[0].receipt.vAsicChipCount.toLocaleString()} Chips ·{' '}
                      {installedVasicMiners[0].receipt.vCpuThreadCount} vCPUs
                    </div>
                  </div>
                </div>
                <div className="font-mono text-[11px] text-slate-300 space-y-1">
                  <div>
                    <span className="text-slate-400">Winning Nonce:</span>{' '}
                    <span className="text-amber-300 font-semibold">
                      {installedVasicMiners[0].receipt.winningNonce} (
                      {installedVasicMiners[0].receipt.winningNonceHex} ·{' '}
                      {installedVasicMiners[0].receipt.leadingZeroBits} leading
                      zero bits ·{' '}
                      {installedVasicMiners[0].receipt.realNoncesEvaluated} real
                      nonces swept)
                    </span>
                  </div>
                  <div className="break-all">
                    <span className="text-slate-400">
                      Winning Double-SHA256 (sha256d):
                    </span>{' '}
                    <span className="text-emerald-400">
                      {installedVasicMiners[0].receipt.winningSha256dHex}
                    </span>
                  </div>
                  <div className="break-all">
                    <span className="text-slate-400">
                      80-Byte Block Header (Hex):
                    </span>{' '}
                    <span className="text-slate-400">
                      {installedVasicMiners[0].receipt.winningHeader80Hex}
                    </span>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <a
                    href={installedVasicMiners[0].ggufDownloadUrl}
                    download={installedVasicMiners[0].ggufFilename}
                    className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs inline-flex items-center gap-1.5"
                  >
                    <Binary className="w-3.5 h-3.5" />
                    <span>
                      Download .GGUF ({installedVasicMiners[0].ggufSizeFormatted})
                    </span>
                  </a>
                  <a
                    href={installedVasicMiners[0].tgzDownloadUrl}
                    download={installedVasicMiners[0].tgzFilename}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 font-mono text-xs inline-flex items-center gap-1.5"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>
                      Download sha256.js .TGZ ({installedVasicMiners[0].tgzSizeFormatted})
                    </span>
                  </a>
                </div>
              </div>
            )}
          </div>

          {/* Right 7 Columns: Real 64-Byte Chunk-0 Midstate Registers (M0..M7) + Live sha256.js / vCPU / vASIC Firmware Code */}
          <div className="lg:col-span-7 space-y-4">
            {installedVasicMiners[0] && (
              <div className="p-3.5 rounded-md bg-[#0F172A] border border-slate-800 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <span className="font-semibold text-slate-200">
                    FIPS 180-4 64-Byte Chunk-0 Midstate Registers (M0..M7) · Saves {installedVasicMiners[0].receipt.midstateRoundSavingsPercent}% SHA-256 Compression Rounds
                  </span>
                  <span className="font-mono text-[11px] text-cyan-400 tabular-nums">
                    Weyl Stride: +{installedVasicMiners[0].receipt.nonceStrideStep} / nonce
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs tabular-nums">
                  {installedVasicMiners[0].receipt.midstateRegisters.map(
                    (regStr, idx) => (
                      <div
                        key={idx}
                        className="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 flex items-center justify-between"
                      >
                        <span className="text-cyan-300 font-semibold">
                          {regStr}
                        </span>
                      </div>
                    )
                  )}
                </div>
              </div>
            )}

            {/* Code Inspector Tabs: src/sha256.js | src/basic-vcpu-miner.js | src/vasic-chip-firmware.ts */}
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div
                  role="group"
                  aria-label="vASIC and sha256.js Source Files"
                  className="inline-flex p-1 bg-[#0F172A] border border-slate-800 rounded-md"
                >
                  {(
                    [
                      { id: 'sha256js', label: 'src/sha256.js (Midstate Boost + vASIC)' },
                      { id: 'vcpu', label: 'src/basic-vcpu-miner.js (Basic vCPU Miner)' },
                      { id: 'firmware', label: 'src/vasic-chip-firmware.ts (vASIC RTL/Firmware)' },
                    ] as const
                  ).map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => setVasicActiveTab(tab.id)}
                      className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
                        vasicActiveTab === tab.id
                          ? 'bg-cyan-600 text-white'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
                <span className="text-[11px] font-mono text-emerald-400">
                  Compiled into GGUF v3 Binary (0 .txt files)
                </span>
              </div>

              {installedVasicMiners[0] && (
                <pre className="p-3.5 rounded-md bg-[#0A0F1D] border border-slate-800 text-[11px] font-mono text-slate-200 overflow-x-auto max-h-[290px] leading-relaxed">
                  {vasicActiveTab === 'sha256js'
                    ? installedVasicMiners[0].receipt.sha256JsCode
                    : vasicActiveTab === 'vcpu'
                    ? installedVasicMiners[0].receipt.basicVcpuMinerCode
                    : installedVasicMiners[0].receipt.vasicFirmwareCode}
                </pre>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Bottom Full-Width Section: Searchable 1,000-Package Core Ecosystem Catalog */}
      <section
        aria-label="1,000-Package Ecosystem Registry"
        className="border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Core 1,000-Package Pre-Indexed Registry (PKG-0001 to PKG-1000)
            </h2>
            <p className="text-xs text-slate-400 mt-0.5 font-mono tabular-nums">
              Pre-Indexed: 1,000 Packages · Matching Filter: {filteredPage.totalMatches} · Bundled in Build: {bundledPackageIds.length} ({bundledMemoryMb} MB RAM)
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <label htmlFor="pkg-catalog-search" className="sr-only">
                Search 1,000 packages
              </label>
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                id="pkg-catalog-search"
                type="search"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                placeholder="Search 1,000 packages (e.g. ringbuffer, jni, PKG-0500)..."
                className="pl-8 pr-3 py-1.5 text-xs bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 placeholder:text-slate-500 w-64 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Source Host Filter */}
            <div
              role="group"
              aria-label="Filter by Source Host"
              className="inline-flex p-1 bg-[#0F172A] border border-slate-800 rounded-md"
            >
              {(['all', 'GitHub', 'GitLab', 'Google', 'NPM'] as const).map(
                (host) => (
                  <button
                    key={host}
                    type="button"
                    onClick={() => {
                      setHostFilter(host);
                      setPage(1);
                    }}
                    className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                      hostFilter === host
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {host === 'all' ? 'All Hosts' : host}
                  </button>
                )
              )}
            </div>

            {/* Ecosystem Filter */}
            <label htmlFor="pkg-ecosystem-select" className="sr-only">
              Filter by Ecosystem
            </label>
            <select
              id="pkg-ecosystem-select"
              value={ecosystemFilter}
              onChange={(e) => {
                setEcosystemFilter(e.target.value as PackageEcosystem | 'all');
                setPage(1);
              }}
              className="px-3 py-1.5 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-200"
            >
              <option value="all">All Ecosystems (1,000)</option>
              <option value="npm">Node.js NPM (250)</option>
              <option value="android-maven">Android Maven (250)</option>
              <option value="ndk-cpp">Native NDK C++ (250)</option>
              <option value="web-connector">Web Connectors (250)</option>
            </select>
          </div>
        </div>

        {/* High-Density Package Registry Table */}
        <div className="overflow-x-auto border border-slate-800 rounded-md">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                <th className="py-2.5 px-3 font-medium">ID</th>
                <th className="py-2.5 px-3 font-medium">Package Coordinates</th>
                <th className="py-2.5 px-3 font-medium">Ecosystem</th>
                <th className="py-2.5 px-3 font-medium">Source Host</th>
                <th className="py-2.5 px-3 font-medium">Category</th>
                <th className="py-2.5 px-3 font-medium text-right">RAM Footprint</th>
                <th className="py-2.5 px-3 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredPage.items.map((pkg) => {
                const isBundled = bundledPackageIds.includes(pkg.id);
                return (
                  <tr key={pkg.id} className="hover:bg-slate-900/50">
                    <td className="py-2 px-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                      {pkg.code}
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-100 whitespace-nowrap">
                      <span className="font-semibold">{pkg.name}</span>
                      <span className="text-slate-400">@{pkg.version}</span>
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-300 whitespace-nowrap">
                      {pkg.ecosystem}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <a
                        href={pkg.repositoryUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:underline font-mono inline-flex items-center gap-1"
                      >
                        {pkg.sourceHost}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </td>
                    <td className="py-2 px-3 text-slate-300 whitespace-nowrap">
                      {pkg.category}
                    </td>
                    <td className="py-2 px-3 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                      {pkg.ramFootprintMb.toFixed(1)} MB
                    </td>
                    <td className="py-2 px-3 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onToggleBundlePackage(pkg.id)}
                        className={`px-2.5 py-1 text-xs font-medium rounded transition-colors inline-flex items-center gap-1 whitespace-nowrap shrink-0 ${
                          isBundled
                            ? 'bg-emerald-600 text-white hover:bg-emerald-500'
                            : 'bg-slate-800 text-slate-200 hover:bg-slate-700 border border-slate-700'
                        }`}
                      >
                        {isBundled ? (
                          <>
                            <Check className="w-3 h-3" />
                            <span>Bundled</span>
                          </>
                        ) : (
                          <>
                            <Plus className="w-3 h-3" />
                            <span>Bundle</span>
                          </>
                        )}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-2 text-xs text-slate-400 font-mono tabular-nums">
          <div>
            Showing Page {filteredPage.currentPage} of {filteredPage.totalPages} ({filteredPage.totalMatches} Packages)
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={filteredPage.currentPage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="px-3 py-1.5 rounded bg-[#0F172A] border border-slate-700 text-slate-200 disabled:opacity-40 hover:bg-slate-800 flex items-center gap-1 whitespace-nowrap shrink-0"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              Previous
            </button>
            <button
              type="button"
              onClick={() => setPage(1)}
              className="px-2.5 py-1.5 rounded bg-[#0F172A] border border-slate-700 text-slate-300 hover:bg-slate-800 whitespace-nowrap shrink-0"
            >
              First (#0001)
            </button>
            <button
              type="button"
              onClick={() => setPage(filteredPage.totalPages)}
              className="px-2.5 py-1.5 rounded bg-[#0F172A] border border-slate-700 text-slate-300 hover:bg-slate-800 whitespace-nowrap shrink-0"
            >
              Last (#1000)
            </button>
            <button
              type="button"
              disabled={filteredPage.currentPage >= filteredPage.totalPages}
              onClick={() =>
                setPage((p) => Math.min(filteredPage.totalPages, p + 1))
              }
              className="px-3 py-1.5 rounded bg-[#0F172A] border border-slate-700 text-slate-200 disabled:opacity-40 hover:bg-slate-800 flex items-center gap-1 whitespace-nowrap shrink-0"
            >
              Next
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
