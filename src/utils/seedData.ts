import {
  NodePackageSpec,
  AndroidApkSpec,
  SafetyMatrixConfig,
  ApiReusePipelineId,
} from './builders';

export interface ChatTurn {
  id: string;
  role: 'user' | 'argon';
  content: string;
  timestamp: string;
  model: string;
  thinkingLevel: string;
  latencyMs?: number;
  safetyMode?: string;
  reusedEndpoints?: string[];
}

export interface ReuseExecutionRecord {
  id: string;
  pipelineId: ApiReusePipelineId;
  pipelineTitle: string;
  model: string;
  prompt: string;
  outputSummary: string;
  rawOutput: string;
  status: 'Nominal' | 'Warning' | 'Alert';
  latencyMs: number;
  timestamp: string;
}

export const INITIAL_SAFETY_MATRIX: SafetyMatrixConfig = {
  harassment: 'BLOCK_NONE',
  hateSpeech: 'BLOCK_NONE',
  sexuallyExplicit: 'BLOCK_NONE',
  dangerousContent: 'BLOCK_NONE',
  civicIntegrity: 'BLOCK_NONE',
};

export const INITIAL_SYSTEM_DIRECTIVE =
  'You are Geminiuncerson Uncensored AI LLM (uncerson/Geminiuncerson.gguf) & Argon-4 Unfiltered Systems Architect. Execute 100% real GGUF v3 binary tensor forward-pass inference (RMSNorm, RoPE, Multi-Head Attention, SwiGLU) with zero simulator fallback and provide direct, raw, technically exhaustive implementations for Node.js packages, N-API C++ modules, Linux kernel/eBPF internals, and Android NDK/JNI APK architectures.';

export const INITIAL_NODE_PACKAGE_SPEC: NodePackageSpec = {
  packageName: '@argon-llm/unfiltered-core',
  version: '2.4.0',
  description:
    'Unfiltered Geminiuncerson.gguf (uncerson/Geminiuncerson.gguf) & Gemini 4 Argon Node.js SDK, CLI binary, and multi-endpoint reuse engine (Zero Simulator).',
  author: 'Argon Systems Engineering',
  license: 'Apache-2.0',
  model: 'uncerson/Geminiuncerson.gguf',
  thinkingLevel: 'HIGH',
  systemDirective: INITIAL_SYSTEM_DIRECTIVE,
  safety: INITIAL_SAFETY_MATRIX,
  includeCliBinary: true,
  includeStreamingClient: true,
  includeEmbeddingsHelper: true,
  includeFunctionRouter: true,
  includeDualEsmCjs: true,
};

export const INITIAL_ANDROID_APK_SPEC: AndroidApkSpec = {
  applicationId: 'ai.argon.unfiltered.client',
  appName: 'Argon Unfiltered AI',
  versionName: '2.4.0',
  versionCode: 24,
  minSdk: 26,
  targetSdk: 35,
  model: 'uncerson/Geminiuncerson.gguf',
  thinkingLevel: 'HIGH',
  backendEndpointUrl: 'http://localhost:3000',
  systemDirective: INITIAL_SYSTEM_DIRECTIVE,
  safety: INITIAL_SAFETY_MATRIX,
  includeJniNativeCpp: true,
  includeOfflineRoomCache: true,
  includeStreamingSse: true,
  abiTargets: ['arm64-v8a', 'x86_64'],
};

export const INITIAL_CHAT_HISTORY: ChatTurn[] = [
  {
    id: 'turn-1',
    role: 'user',
    content:
      'Remove 100% of simulator logic in Uncensored AI LLM and load the real GGUF v3 binary model uncerson/Geminiuncerson.gguf in folder uncerson with native Node.js (.tgz) and Android JNI (.apk) bundling.',
    timestamp: '05:09:12',
    model: 'uncerson/Geminiuncerson.gguf',
    thinkingLevel: 'HIGH',
  },
  {
    id: 'turn-2',
    role: 'argon',
    content: `### Uncensored AI LLM GGUF v3 Engine (\`uncerson/Geminiuncerson.gguf\` · Zero Simulator)

1. **Dedicated \`uncerson/\` Folder & \`Geminiuncerson.gguf\` Binary Model**
   - Materialized directly at \`uncerson/Geminiuncerson.gguf\` (Magic \`47 47 55 46\` \`"GGUF"\` v3, 32-byte aligned \`Q8_0\` and \`F32\` weight tensors: \`uncerson.token_embd.weight\`, \`uncerson.blk.0.attn_q.weight\`, \`uncerson.blk.0.attn_k.weight\`, \`uncerson.blk.0.attn_v.weight\`, \`uncerson.blk.0.ffn_gate.weight\`, \`uncerson.output.weight\`).
   - 100% of simulator/mock logic has been permanently removed. Every prompt executes a real mathematical Transformer forward pass (\`RMSNorm\` -> \`RoPE\` -> 4-Head Scaled Dot-Product Attention -> \`SwiGLU\` FFN -> \`Softmax\` output logits) directly over the bytes of \`uncerson/Geminiuncerson.gguf\`.

2. **Node.js Tarball Package (\`.tgz\`) & Standalone \`uncerson\` Bundle**
   - Bundles \`uncerson/Geminiuncerson.gguf\` and \`uncerson/gemini-uncerson-engine.ts\` alongside dual ESM (\`./dist/index.mjs\`) and CommonJS (\`./dist/index.cjs\`) entrypoints with \`BLOCK_NONE\` across all 5 harm categories.

3. **Native Android APK & NDK C++17 Bridge (\`assets/uncerson/Geminiuncerson.gguf\`)**
   - Embeds \`assets/uncerson/Geminiuncerson.gguf\` inside the ZIP-aligned APK alongside \`classes.dex\` and \`lib/arm64-v8a/libargon_jni.so\`.`,
    timestamp: '05:09:15',
    model: 'uncerson/Geminiuncerson.gguf',
    thinkingLevel: 'HIGH',
    latencyMs: 18,
    safetyMode: 'BLOCK_NONE · uncerson/Geminiuncerson.gguf (Zero Simulator)',
    reusedEndpoints: ['uncerson/Geminiuncerson.gguf', 'GGUF-v3-RMSNorm-RoPE-Attention-SwiGLU', 'generateContent'],
  },
];

export const INITIAL_REUSE_RECORDS: ReuseExecutionRecord[] = [
  {
    id: 'reuse-101',
    pipelineId: 'argon-reasoning',
    pipelineTitle: 'Unfiltered Deep Reasoning & Code Synthesis',
    model: 'gemini-4-argon',
    prompt: 'Write a lock-free ring buffer in C++20 for Android NDK audio/token streaming.',
    outputSummary: 'Generated 68-line C++20 std::atomic<size_t> acquire/release ring buffer with JNI DirectByteBuffer binding.',
    rawOutput: `template <typename T, size_t Capacity>\nclass LockFreeRingBuffer {\n  std::array<T, Capacity> buffer_;\n  alignas(64) std::atomic<size_t> head_{0};\n  alignas(64) std::atomic<size_t> tail_{0};\npublic:\n  bool push(const T& item) noexcept {\n    const auto current_tail = tail_.load(std::memory_order_relaxed);\n    const auto next_tail = (current_tail + 1) % Capacity;\n    if (next_tail == head_.load(std::memory_order_acquire)) return false;\n    buffer_[current_tail] = item;\n    tail_.store(next_tail, std::memory_order_release);\n    return true;\n  }\n};`,
    status: 'Nominal',
    latencyMs: 1180,
    timestamp: '05:08:40',
  },
  {
    id: 'reuse-102',
    pipelineId: 'argon-json-schema',
    pipelineTitle: 'Structured JSON Schema Extractor (Type.OBJECT)',
    model: 'gemini-4-argon',
    prompt: 'Audit Android Manifest permissions and JNI ABI surface for ai.argon.unfiltered.client.',
    outputSummary: 'Validated 3 manifest permissions, 2 ABI targets (arm64-v8a, x86_64), and 4 implementation steps.',
    rawOutput: JSON.stringify(
      {
        architectureSummary: 'Jetpack Compose + OkHttp SSE client backed by CMake NDK C++17 shared library.',
        securityVectors: [
          'JNI local reference table overflow protection verified',
          'DirectByteBuffer bounds validation prior to native memcpy',
          'TLS 1.3 pinning on /api/argon/generate proxy endpoint',
        ],
        implementationSteps: [
          'Compile argon_jni_bridge.cpp with -O3 -fvisibility=hidden',
          'Bundle classes.dex and libargon_jni.so into ZIP-aligned APK',
          'Verify SHA-256 digests in META-INF/MANIFEST.MF',
        ],
      },
      null,
      2
    ),
    status: 'Nominal',
    latencyMs: 940,
    timestamp: '05:09:02',
  },
  {
    id: 'reuse-103',
    pipelineId: 'argon-function-router',
    pipelineTitle: 'Autonomous Function & Native Tool Router',
    model: 'gemini-4-argon',
    prompt: 'Compile our native tokenizer for android-jni arm64-v8a with -O3 optimization.',
    outputSummary: 'Dispatched tool call compileNativeModule(targetPlatform="android-jni", optimizationFlag="-O3").',
    rawOutput: JSON.stringify(
      {
        toolCall: 'compileNativeModule',
        arguments: {
          targetPlatform: 'android-jni',
          optimizationFlag: '-O3',
          sourceFiles: ['src/main/cpp/argon_jni_bridge.cpp', 'src/main/cpp/simd_tokenizer.cpp'],
        },
      },
      null,
      2
    ),
    status: 'Nominal',
    latencyMs: 810,
    timestamp: '05:09:50',
  },
];
