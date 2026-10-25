import React, { useState, useEffect } from 'react';
import {
  NodePackageSpec,
  validateNodePackageSpec,
} from '../utils/builders';
import {
  Package,
  Download,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  FileCode2,
} from 'lucide-react';

interface NodeBuildResponse {
  buildId: string;
  packageName: string;
  version: string;
  tgzFilename: string;
  tgzDownloadUrl: string;
  tgzSizeBytes: number;
  tgzSizeFormatted: string;
  tgzSha256: string;
  zipFilename: string;
  zipDownloadUrl: string;
  zipSha256: string;
  ggufFilename: string;
  ggufDownloadUrl: string;
  ggufSizeFormatted: string;
  ggufSha256: string;
  files: {
    path: string;
    sizeBytes: number;
    sizeFormatted: string;
    description: string;
    contentPreview: string;
  }[];
  verificationChecks: {
    check: string;
    passed: boolean;
    detail: string;
  }[];
}

interface NodePackageBuilderViewProps {
  spec: NodePackageSpec;
  onChangeSpec: (next: NodePackageSpec) => void;
}

export function NodePackageBuilderView({
  spec,
  onChangeSpec,
}: NodePackageBuilderViewProps) {
  const [buildResult, setBuildResult] = useState<NodeBuildResponse | null>(null);
  const [selectedFilePath, setSelectedFilePath] = useState<string>('src/index.ts');
  const [isBuilding, setIsBuilding] = useState<boolean>(false);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [fileSearch, setFileSearch] = useState<string>('');
  const [copiedFile, setCopiedFile] = useState<boolean>(false);

  const executeServerBuild = async (targetSpec: NodePackageSpec) => {
    const check = validateNodePackageSpec(targetSpec);
    if (!check.valid) {
      setValidationErrors(check.errors);
      return;
    }
    setValidationErrors([]);
    setIsBuilding(true);

    try {
      const res = await fetch('/api/node-pkg/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(targetSpec),
      });
      const data = await res.json();
      if (!res.ok) {
        setValidationErrors(data.errors || [data.error || 'Failed to build Node.js package']);
        return;
      }
      setBuildResult(data);
      if (
        data.files &&
        data.files.length > 0 &&
        !data.files.some((f: any) => f.path === selectedFilePath)
      ) {
        setSelectedFilePath(data.files[0].path);
      }
    } catch (err: any) {
      setValidationErrors([err?.message || 'Network error while building Node.js package.']);
    } finally {
      setIsBuilding(false);
    }
  };

  useEffect(() => {
    executeServerBuild(spec);
  }, []);

  const handleBuildSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeServerBuild(spec);
  };

  const filteredFiles = (buildResult?.files || []).filter((f) =>
    fileSearch.trim()
      ? f.path.toLowerCase().includes(fileSearch.toLowerCase()) ||
        f.description.toLowerCase().includes(fileSearch.toLowerCase())
      : true
  );

  const activeFile =
    (buildResult?.files || []).find((f) => f.path === selectedFilePath) ||
    filteredFiles[0] ||
    null;

  const handleCopyFileContent = () => {
    if (!activeFile) return;
    navigator.clipboard?.writeText(activeFile.contentPreview);
    setCopiedFile(true);
    setTimeout(() => setCopiedFile(false), 1800);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      {/* Left 5 Columns: Node.js Package Specification & Compiler Controls */}
      <section
        aria-label="Node.js Package Configuration"
        className="lg:col-span-5 border border-slate-800 bg-[#131C31] rounded-lg p-6"
      >
        <div className="pb-4 mb-5 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-slate-100">
            Node.js Package Compiler (.tgz)
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Compiles a real, installable POSIX <code className="text-slate-300">ustar</code> + GZIP{' '}
            <code className="text-slate-300">.tgz</code> npm package bundling Gemini 4 Argon (<code className="text-slate-300">gemini-4-argon</code>) with your active safety matrix.
          </p>
        </div>

        {validationErrors.length > 0 && (
          <div
            role="alert"
            className="mb-5 p-3.5 rounded-md bg-red-950/60 border border-red-800 text-xs text-red-200 space-y-1"
          >
            <div className="flex items-center gap-2 font-semibold text-red-300">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>Package Specification Validation Failed</span>
            </div>
            <ul className="list-disc list-inside space-y-0.5 pl-1">
              {validationErrors.map((err, idx) => (
                <li key={idx}>{err}</li>
              ))}
            </ul>
          </div>
        )}

        <form onSubmit={handleBuildSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label
                htmlFor="npm-package-name"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                NPM Package Name
              </label>
              <input
                id="npm-package-name"
                type="text"
                value={spec.packageName}
                onChange={(e) =>
                  onChangeSpec({ ...spec, packageName: e.target.value })
                }
                placeholder="@argon-llm/unfiltered-core"
                className="w-full px-3 py-2 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label
                htmlFor="npm-package-version"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                SemVer Version
              </label>
              <input
                id="npm-package-version"
                type="text"
                value={spec.version}
                onChange={(e) =>
                  onChangeSpec({ ...spec, version: e.target.value })
                }
                placeholder="2.4.0"
                className="w-full px-3 py-2 text-xs font-mono tabular-nums bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="npm-package-description"
              className="block text-xs font-medium text-slate-300 mb-1"
            >
              Package Description
            </label>
            <input
              id="npm-package-description"
              type="text"
              value={spec.description}
              onChange={(e) =>
                onChangeSpec({ ...spec, description: e.target.value })
              }
              className="w-full px-3 py-2 text-xs bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label
                htmlFor="npm-author"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Maintainer / Author
              </label>
              <input
                id="npm-author"
                type="text"
                value={spec.author}
                onChange={(e) =>
                  onChangeSpec({ ...spec, author: e.target.value })
                }
                className="w-full px-3 py-2 text-xs bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label
                htmlFor="npm-license"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                SPDX License
              </label>
              <select
                id="npm-license"
                value={spec.license}
                onChange={(e) =>
                  onChangeSpec({ ...spec, license: e.target.value })
                }
                className="w-full px-3 py-2 text-xs font-mono bg-[#0F172A] border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-blue-500"
              >
                <option value="Apache-2.0">Apache-2.0</option>
                <option value="MIT">MIT</option>
                <option value="BSD-3-Clause">BSD-3-Clause</option>
                <option value="GPL-3.0-only">GPL-3.0-only</option>
              </select>
            </div>
          </div>

          <fieldset className="pt-3 border-t border-slate-800 space-y-2.5">
            <legend className="text-xs font-semibold text-slate-300 mb-1">
              Reusable Gemini 4 Argon Capabilities to Bundle
            </legend>

            {(
              [
                {
                  key: 'includeDualEsmCjs',
                  label: 'Dual ESM (dist/index.mjs) + CommonJS (dist/index.cjs) Exports',
                },
                {
                  key: 'includeCliBinary',
                  label: 'Executable Node.js CLI Binary (bin/argon-cli.mjs)',
                },
                {
                  key: 'includeStreamingClient',
                  label: 'AsyncGenerator Token Streaming (generateContentStream)',
                },
                {
                  key: 'includeEmbeddingsHelper',
                  label: 'Batch Vector Embeddings Pipeline (gemini-embedding-2-preview)',
                },
                {
                  key: 'includeFunctionRouter',
                  label: 'Autonomous Function & Native Tool Router (functionDeclarations)',
                },
              ] as const
            ).map((item) => (
              <label
                key={item.key}
                className="flex items-center gap-2.5 text-xs text-slate-300 cursor-pointer select-none"
              >
                <input
                  type="checkbox"
                  checked={spec[item.key]}
                  onChange={(e) =>
                    onChangeSpec({ ...spec, [item.key]: e.target.checked })
                  }
                  className="rounded border-slate-600 bg-slate-900 text-blue-600 focus:ring-blue-500"
                />
                <span>{item.label}</span>
              </label>
            ))}
          </fieldset>

          <div className="pt-3">
            <button
              type="submit"
              disabled={isBuilding}
              className="w-full py-2.5 px-4 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-md transition-colors flex items-center justify-center gap-2"
            >
              <Package className="w-4 h-4" />
              {isBuilding ? 'Compiling & Packing Tarball...' : 'Compile Tarball (.tgz)'}
            </button>
          </div>
        </form>
      </section>

      {/* Right 7 Columns: Real Compiled Tarball Artifact, Checksums & File Inspector */}
      <section
        aria-label="Compiled Node.js Package Artifact Inspector"
        className="lg:col-span-7 border border-slate-800 bg-[#131C31] rounded-lg p-6 space-y-6"
      >
        {buildResult ? (
          <>
            <div className="flex flex-wrap items-start justify-between gap-4 pb-5 border-b border-slate-800">
              <div>
                <h3 className="text-base font-semibold text-slate-100 font-mono">
                  {buildResult.packageName}@{buildResult.version}
                </h3>
                <p className="text-xs text-slate-400 font-mono tabular-nums mt-1">
                  GGUF v3 Binary: {buildResult.ggufFilename} ({buildResult.ggufSizeFormatted}) · Tarball: {buildResult.tgzFilename} ({buildResult.tgzSizeFormatted})
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
                  href={buildResult.tgzDownloadUrl}
                  download={buildResult.tgzFilename}
                  className="px-3.5 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download .tgz
                </a>
                <a
                  href={buildResult.zipDownloadUrl}
                  download={buildResult.zipFilename}
                  className="px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download .zip
                </a>
              </div>
            </div>

            {/* Binary & Export Verification Checks */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 mb-2.5">
                Server-Side Tarball & Module Verification
              </h4>
              <div className="overflow-x-auto border border-slate-800 rounded-md">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 bg-slate-900/80 text-slate-400">
                      <th className="py-2 px-3 font-medium">Verification Check</th>
                      <th className="py-2 px-3 font-medium">Status</th>
                      <th className="py-2 px-3 font-medium">Diagnostic Detail</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {buildResult.verificationChecks.map((v, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3 text-slate-200 font-medium">{v.check}</td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1 text-emerald-400 font-mono">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            {v.passed ? 'Nominal' : 'Alert'}
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

            {/* Generated Package File Tree & Live Code Viewer */}
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-xs font-semibold text-slate-300">
                  Compiled Package File Tree & Source Inspector
                </h4>
                <div className="flex items-center gap-2">
                  <label htmlFor="node-file-search" className="sr-only">
                    Filter package files
                  </label>
                  <input
                    id="node-file-search"
                    type="search"
                    value={fileSearch}
                    onChange={(e) => setFileSearch(e.target.value)}
                    placeholder="Filter files..."
                    className="px-2.5 py-1 text-xs bg-[#0F172A] border border-slate-700 rounded text-slate-200 placeholder:text-slate-500"
                  />
                </div>
              </div>

              <div className="flex flex-wrap gap-1.5 p-1.5 bg-[#0F172A] border border-slate-800 rounded-md">
                {filteredFiles.map((file) => (
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
                      onClick={handleCopyFileContent}
                      className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 rounded flex items-center gap-1 transition-colors whitespace-nowrap shrink-0"
                    >
                      {copiedFile ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Code</span>
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
            Compiling Node.js package artifact...
          </div>
        )}
      </section>
    </div>
  );
}
