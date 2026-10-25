import React, { useState, useEffect } from 'react';
import {
  AndroidApkSpec,
  validateAndroidApkSpec,
} from '../utils/builders';
import {
  Smartphone,
  Download,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  FileCode2,
} from 'lucide-react';

interface AndroidFileItem {
  path: string;
  sizeBytes: number;
  sizeFormatted: string;
  description: string;
  isBinary: boolean;
  contentPreview: string;
}

interface AndroidBuildResponse {
  buildId: string;
  applicationId: string;
  appName: string;
  versionName: string;
  versionCode: number;
  apkFilename: string;
  apkDownloadUrl: string;
  apkSizeBytes: number;
  apkSizeFormatted: string;
  apkSha256: string;
  sourceZipFilename: string;
  sourceZipDownloadUrl: string;
  sourceZipSizeFormatted: string;
  sourceZipSha256: string;
  ggufFilename: string;
  ggufDownloadUrl: string;
  ggufSizeFormatted: string;
  ggufSha256: string;
  apkEntries: AndroidFileItem[];
  projectFiles: AndroidFileItem[];
  verificationChecks: {
    check: string;
    passed: boolean;
    detail: string;
  }[];
}

interface AndroidApkBuilderViewProps {
  spec: AndroidApkSpec;
  onChangeSpec: (next: AndroidApkSpec) => void;
}

const ABI_OPTIONS = ['arm64-v8a', 'x86_64', 'armeabi-v7a'];

export function AndroidApkBuilderView({
  spec,
  onChangeSpec,
}: AndroidApkBuilderViewProps) {
  const [buildResult, setBuildResult] = useState<AndroidBuildResponse | null>(null);
  const [inspectorTab, setInspectorTab] = useState<'project' | 'apk'>('project');
  const [selectedFilePath, setSelectedFilePath] = useState<string>('');
  const [isBuilding, setIsBuilding] = useState<boolean>(false);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [copied, setCopied] = useState<boolean>(false);

  const executeApkBuild = async (targetSpec: AndroidApkSpec) => {
    const check = validateAndroidApkSpec(targetSpec);
    if (!check.valid) {
      setValidationErrors(check.errors);
      return;
    }
    setValidationErrors([]);
    setIsBuilding(true);

    try {
      const res = await fetch('/api/android-apk/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(targetSpec),
      });
      const data = await res.json();
      if (!res.ok) {
        setValidationErrors(data.errors || [data.error || 'Failed to assemble Android APK']);
        return;
      }
      setBuildResult(data);
      const currentList =
        inspectorTab === 'project' ? data.projectFiles : data.apkEntries;
      if (currentList && currentList.length > 0) {
        setSelectedFilePath(currentList[0].path);
      }
    } catch (err: any) {
      setValidationErrors([err?.message || 'Network error while assembling Android APK.']);
    } finally {
      setIsBuilding(false);
    }
  };

  useEffect(() => {
    executeApkBuild(spec);
  }, []);

  const handleToggleAbi = (abi: string) => {
    const exists = spec.abiTargets.includes(abi);
    const nextAbis = exists
      ? spec.abiTargets.filter((a) => a !== abi)
      : [...spec.abiTargets, abi];
    onChangeSpec({ ...spec, abiTargets: nextAbis });
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeApkBuild(spec);
  };

  const activeList =
    inspectorTab === 'project'
      ? buildResult?.projectFiles || []
      : buildResult?.apkEntries || [];

  const activeFile =
    activeList.find((f) => f.path === selectedFilePath) || activeList[0] || null;

  const handleCopy = () => {
    if (!activeFile) return;
    navigator.clipboard?.writeText(activeFile.contentPreview);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      {/* Left 5 Columns: Android APK & NDK JNI Build Spec */}
      <section
        aria-label="Native Android APK Specification"
        className="lg:col-span-5 border border-slate-800 bg-[#131C31] rounded-lg p-6"
      >
        <div className="pb-4 mb-5 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-slate-100">
            Native Android APK & NDK Assembler
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Generates a complete Kotlin Jetpack Compose + CMake C++17 JNI Android Studio project and packs a standards-compliant <code className="text-slate-300">.apk</code> binary (<code className="text-slate-300">classes.dex</code> + <code className="text-slate-300">libargon_jni.so</code> + <code className="text-slate-300">MANIFEST.MF</code>).
          </p>
        </div>

        {validationErrors.length > 0 && (
          <div
            role="alert"
            className="mb-5 p-3.5 rounded-md bg-red-950/60 border border-red-800 text-xs text-red-200 space-y-1"
          >
            <div className="flex items-center gap-2 font-semibold text-red-300">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>APK Configuration Validation Failed</span>
            </div>
            <ul className="list-disc list-inside space-y-0.5 pl-1">
              {validationErrors.map((err, idx) => (
                <li key={idx}>{err}</li>
              ))}
            </ul>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="android-app-id"
              className="block text-xs font-medium text-slate-300 mb-1"
            >
              Android Application ID (Package Name)
            </label>
            <input
              id="android-app-id"
              type="text"
              value={spec.applicationId}
              onChange={(e) =>
                onChangeSpec({ ...spec, applicationId: e.target.value })
              }
              placeholder="ai.argon.unfiltered.client"
              className="w-full px-3 py-2 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label
                htmlFor="android-app-name"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                App Display Name
              </label>
              <input
                id="android-app-name"
                type="text"
                value={spec.appName}
                onChange={(e) =>
                  onChangeSpec({ ...spec, appName: e.target.value })
                }
                className="w-full px-3 py-2 text-xs bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label
                htmlFor="android-version-name"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Version Name
              </label>
              <input
                id="android-version-name"
                type="text"
                value={spec.versionName}
                onChange={(e) =>
                  onChangeSpec({ ...spec, versionName: e.target.value })
                }
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label
                htmlFor="android-min-sdk"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Min SDK
              </label>
              <input
                id="android-min-sdk"
                type="number"
                value={spec.minSdk}
                onChange={(e) =>
                  onChangeSpec({
                    ...spec,
                    minSdk: parseInt(e.target.value, 10) || 26,
                  })
                }
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label
                htmlFor="android-target-sdk"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Target SDK
              </label>
              <input
                id="android-target-sdk"
                type="number"
                value={spec.targetSdk}
                onChange={(e) =>
                  onChangeSpec({
                    ...spec,
                    targetSdk: parseInt(e.target.value, 10) || 35,
                  })
                }
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label
                htmlFor="android-version-code"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Version Code
              </label>
              <input
                id="android-version-code"
                type="number"
                value={spec.versionCode}
                onChange={(e) =>
                  onChangeSpec({
                    ...spec,
                    versionCode: parseInt(e.target.value, 10) || 1,
                  })
                }
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="android-backend-url"
              className="block text-xs font-medium text-slate-300 mb-1"
            >
              Gemini 4 Argon Proxy Endpoint URL
            </label>
            <input
              id="android-backend-url"
              type="text"
              value={spec.backendEndpointUrl}
              onChange={(e) =>
                onChangeSpec({ ...spec, backendEndpointUrl: e.target.value })
              }
              className="w-full px-3 py-2 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
            />
          </div>

          <fieldset className="pt-3 border-t border-slate-800">
            <legend className="text-xs font-semibold text-slate-300 mb-2">
              NDK Native C++17 ABI Targets (libargon_jni.so)
            </legend>
            <div className="flex flex-wrap gap-3">
              {ABI_OPTIONS.map((abi) => (
                <label
                  key={abi}
                  className="flex items-center gap-2 text-xs font-mono text-slate-300 cursor-pointer select-none"
                >
                  <input
                    type="checkbox"
                    checked={spec.abiTargets.includes(abi)}
                    onChange={() => handleToggleAbi(abi)}
                    className="rounded border-slate-600 bg-slate-900 text-blue-600"
                  />
                  <span>{abi}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset className="pt-3 border-t border-slate-800 space-y-2">
            <legend className="text-xs font-semibold text-slate-300 mb-1">
              Native Architecture Modules
            </legend>
            <label className="flex items-center gap-2.5 text-xs text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={spec.includeJniNativeCpp}
                onChange={(e) =>
                  onChangeSpec({ ...spec, includeJniNativeCpp: e.target.checked })
                }
                className="rounded border-slate-600 bg-slate-900 text-blue-600"
              />
              <span>Compile NDK C++17 JNI Bridge (argon_jni_bridge.cpp + ELF64 .so)</span>
            </label>
            <label className="flex items-center gap-2.5 text-xs text-slate-300 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={spec.includeStreamingSse}
                onChange={(e) =>
                  onChangeSpec({ ...spec, includeStreamingSse: e.target.checked })
                }
                className="rounded border-slate-600 bg-slate-900 text-blue-600"
              />
              <span>Include OkHttp Server-Sent Events (SSE) Token Streamer</span>
            </label>
          </fieldset>

          <div className="pt-3">
            <button
              type="submit"
              disabled={isBuilding}
              className="w-full py-2.5 px-4 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-md transition-colors flex items-center justify-center gap-2"
            >
              <Smartphone className="w-4 h-4" />
              {isBuilding ? 'Assembling APK & JNI Binaries...' : 'Assemble APK & Project'}
            </button>
          </div>
        </form>
      </section>

      {/* Right 7 Columns: Assembled APK & Android Studio Project Inspector */}
      <section
        aria-label="Assembled Android APK and Source Inspector"
        className="lg:col-span-7 border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-6"
      >
        {buildResult ? (
          <>
            <div className="flex flex-wrap items-start justify-between gap-4 pb-5 border-b border-slate-800">
              <div>
                <h3 className="text-base font-semibold text-slate-100">
                  {buildResult.appName}{' '}
                  <span className="font-mono text-sm text-slate-400">
                    ({buildResult.applicationId} v{buildResult.versionName})
                  </span>
                </h3>
                <p className="text-xs text-slate-400 font-mono tabular-nums mt-1">
                  GGUF v3 Binary: {buildResult.ggufFilename} ({buildResult.ggufSizeFormatted}) · APK Binary: {buildResult.apkFilename} ({buildResult.apkSizeFormatted})
                </p>
                <p className="text-xs text-slate-400 font-mono tabular-nums mt-0.5 break-all">
                  GGUF SHA-256: {buildResult.ggufSha256}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                <a
                  href={buildResult.ggufDownloadUrl}
                  download={buildResult.ggufFilename}
                  className="px-3.5 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download Full .gguf
                </a>
                <a
                  href={buildResult.apkDownloadUrl}
                  download={buildResult.apkFilename}
                  className="px-3.5 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download .apk
                </a>
                <a
                  href={buildResult.sourceZipDownloadUrl}
                  download={buildResult.sourceZipFilename}
                  className="px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download Android Studio .zip
                </a>
              </div>
            </div>

            {/* APK Binary Structure Verification */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 mb-2.5">
                DEX Bytecode, ELF64 JNI & PKZIP Alignment Verification
              </h4>
              <div className="overflow-x-auto border border-slate-800 rounded-md">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                      <th className="py-2 px-3 font-medium">Binary Layer</th>
                      <th className="py-2 px-3 font-medium">Status</th>
                      <th className="py-2 px-3 font-medium">Verification Detail</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {buildResult.verificationChecks.map((v, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 text-slate-200 font-medium">{v.check}</td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1 text-emerald-400 font-mono">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            {v.passed ? 'Nominal' : 'Skipped'}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-400 font-mono tabular-nums">
                          {v.detail}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Segmented Mode Switcher: Project Sources vs Raw APK Entries */}
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div
                  role="group"
                  aria-label="Android Inspector View Mode"
                  className="inline-flex p-1 bg-[#0F172A] border border-slate-800 rounded-md"
                >
                  <button
                    type="button"
                    onClick={() => {
                      setInspectorTab('project');
                      if (buildResult.projectFiles.length > 0) {
                        setSelectedFilePath(buildResult.projectFiles[0].path);
                      }
                    }}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                      inspectorTab === 'project'
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Kotlin & JNI C++ Sources ({buildResult.projectFiles.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setInspectorTab('apk');
                      if (buildResult.apkEntries.length > 0) {
                        setSelectedFilePath(buildResult.apkEntries[0].path);
                      }
                    }}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                      inspectorTab === 'apk'
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Packaged APK Binary Entries ({buildResult.apkEntries.length})
                  </button>
                </div>
              </div>

              <div className="flex flex-wrap gap-1.5 p-1.5 bg-[#0F172A] border border-slate-800 rounded-md">
                {activeList.map((file) => (
                  <button
                    key={file.path}
                    type="button"
                    onClick={() => setSelectedFilePath(file.path)}
                    className={`px-2.5 py-1.5 text-xs font-mono rounded transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 ${
                      activeFile?.path === file.path
                        ? 'bg-blue-600 text-white'
                        : 'text-slate-300 hover:bg-slate-800'
                    }`}
                  >
                    <FileCode2 className="w-3.5 h-3.5" />
                    <span>{file.path}</span>
                    <span className="opacity-75 tabular-nums">({file.sizeFormatted})</span>
                  </button>
                ))}
              </div>

              {activeFile && (
                <div className="border border-slate-800 rounded-md bg-[#0F172A] overflow-hidden">
                  <div className="flex items-center justify-between px-3.5 py-2 border-b border-slate-800 bg-slate-900/70 text-xs">
                    <div className="text-slate-300 font-mono">
                      <span className="font-semibold text-slate-100">{activeFile.path}</span>
                      <span aria-hidden="true"> · </span>
                      <span className="text-slate-400">{activeFile.description}</span>
                    </div>
                    <button
                      type="button"
                      onClick={handleCopy}
                      className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 rounded flex items-center gap-1 transition-colors whitespace-nowrap shrink-0"
                    >
                      {copied ? (
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
                  <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto max-h-[340px] leading-relaxed">
                    <code>{activeFile.contentPreview}</code>
                  </pre>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="py-12 text-center text-sm text-slate-400">
            Assembling Android APK and JNI libraries...
          </div>
        )}
      </section>
    </div>
  );
}
