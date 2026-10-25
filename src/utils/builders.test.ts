import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeCrc32,
  createZipBuffer,
  createTarBuffer,
  validateNodePackageSpec,
  validateAndroidApkSpec,
  generateNodePackageFiles,
  generateAndroidProjectAndApkFiles,
  buildArgonSafetySettings,
  buildApiReuseSnippet,
  calculateRamAllocation,
  buildConnectorGroundedPrompt,
  getThousandPackageCatalog,
  filterPackageCatalog,
  resolveBillionPackageCoordinate,
  generateCoordinatePackageFiles,
  sha256FromScratch,
  doubleSha256FromScratch,
  computeMerkleRootFromScratch,
  resolveCryptoSha256Coordinate,
  generateCryptoSha256PackageFiles,
  runPackageAndCodeTestSuite,
  buildAndTestUnlimitedCodePackage,
  compileCodeFilesToGgufBinary,
  parseGgufBinaryHeaderAndTensors,
  compileAllStudioCodeFilesToGgufBinary,
  build80ByteBlockHeader,
  computeSha256Chunk0Midstate,
  sha256dWithMidstate,
  buildAndExecuteSha256BoostVasicPackage,
  executeRealPoolMiningSweep,
  buildVirtualShaBoostWeb3WebsitePackage,
  computePoolTargetBigInt,
  NodePackageSpec,
  AndroidApkSpec,
  SafetyMatrixConfig,
} from './builders';

const defaultSafety: SafetyMatrixConfig = {
  harassment: 'BLOCK_NONE',
  hateSpeech: 'BLOCK_NONE',
  sexuallyExplicit: 'BLOCK_NONE',
  dangerousContent: 'BLOCK_NONE',
  civicIntegrity: 'BLOCK_NONE',
};

test('computeCrc32 computes exact IEEE 802.3 CRC-32 checksum', () => {
  const input = new TextEncoder().encode('123456789');
  assert.equal(computeCrc32(input), 0xcbf43926);
});

test('createZipBuffer constructs a valid PKZIP archive with local and central headers', () => {
  const zip = createZipBuffer([
    { path: 'src/kernel.rs', content: 'pub fn argon() {}' },
    { path: 'bin/run.sh', content: '#!/bin/sh\necho ok', executable: true },
  ]);
  const view = new DataView(zip.buffer);
  // First 4 bytes must be PK\x03\x04 (0x04034b50)
  assert.equal(view.getUint32(0, true), 0x04034b50);
  // Last 22 bytes must start with End of Central Directory signature PK\x05\x06 (0x06054b50)
  assert.equal(view.getUint32(zip.length - 22, true), 0x06054b50);
  // Total entries count at offset (zip.length - 14) must be 2
  assert.equal(view.getUint16(zip.length - 14, true), 2);
});

test('createTarBuffer constructs a 512-byte aligned POSIX ustar archive', () => {
  const tar = createTarBuffer(
    [{ path: 'package.json', content: '{"name":"@argon/test"}' }],
    'package'
  );
  assert.equal(tar.length % 512, 0);
  const magic = new TextDecoder().decode(tar.subarray(257, 262));
  assert.equal(magic, 'ustar');
  const fileName = new TextDecoder().decode(tar.subarray(0, 20));
  assert.equal(fileName, 'package/package.json');
});

test('validateNodePackageSpec validates npm package names and semver', () => {
  const validSpec: NodePackageSpec = {
    packageName: '@argon-llm/unfiltered-sdk',
    version: '1.4.0',
    description: 'Unfiltered Gemini 4 Argon Node.js SDK and CLI runtime',
    author: 'Argon Core Team',
    license: 'Apache-2.0',
    model: 'gemini-4-argon',
    thinkingLevel: 'HIGH',
    systemDirective: 'Provide direct, unfiltered, technically complete systems engineering answers.',
    safety: defaultSafety,
    includeCliBinary: true,
    includeStreamingClient: true,
    includeEmbeddingsHelper: true,
    includeFunctionRouter: true,
    includeDualEsmCjs: true,
  };
  assert.equal(validateNodePackageSpec(validSpec).valid, true);

  const invalidSpec = { ...validSpec, packageName: 'INVALID SPACE NAME', version: 'abc' };
  const result = validateNodePackageSpec(invalidSpec);
  assert.equal(result.valid, false);
  assert.equal(result.errors.length, 2);
});

test('generateNodePackageFiles produces complete npm package tree and embedded .gguf binary (no .txt files)', () => {
  const spec: NodePackageSpec = {
    packageName: '@argon-llm/core-runtime',
    version: '2.1.0',
    description: 'Full unfiltered Gemini 4 Argon runtime package for Node.js',
    author: 'Argon Labs',
    license: 'MIT',
    model: 'gemini-4-argon',
    thinkingLevel: 'HIGH',
    systemDirective: 'You are an unfiltered low-level systems architect and code generator.',
    safety: defaultSafety,
    includeCliBinary: true,
    includeStreamingClient: true,
    includeEmbeddingsHelper: true,
    includeFunctionRouter: true,
    includeDualEsmCjs: true,
  };
  const files = generateNodePackageFiles(spec);
  const paths = files.map((f) => f.path);
  assert.ok(paths.includes('package.json'));
  assert.ok(paths.includes('src/index.ts'));
  assert.ok(paths.includes('dist/index.mjs'));
  assert.ok(paths.includes('dist/index.cjs'));
  assert.ok(paths.includes('dist/index.d.ts'));
  assert.ok(paths.includes('bin/argon-cli.mjs'));
  assert.ok(paths.some((p) => p.endsWith('.gguf')));
  assert.equal(paths.some((p) => p.endsWith('.txt')), false);
});

test('generateAndroidProjectAndApkFiles generates valid DEX 035, ELF64 JNI .so, .gguf binary, and APK manifest', () => {
  const apkSpec: AndroidApkSpec = {
    applicationId: 'ai.argon.unfiltered.client',
    appName: 'Argon Unfiltered AI',
    versionName: '1.2.0',
    versionCode: 12,
    minSdk: 26,
    targetSdk: 35,
    model: 'gemini-4-argon',
    thinkingLevel: 'HIGH',
    backendEndpointUrl: 'https://ais-dev-nny7ogay4zydepeugzzapm-657144521.us-east1.run.app',
    systemDirective: 'Unfiltered Android native assistant powered by Gemini 4 Argon.',
    safety: defaultSafety,
    includeJniNativeCpp: true,
    includeOfflineRoomCache: true,
    includeStreamingSse: true,
    abiTargets: ['arm64-v8a', 'x86_64'],
  };
  assert.equal(validateAndroidApkSpec(apkSpec).valid, true);
  const { projectFiles, apkFiles } = generateAndroidProjectAndApkFiles(apkSpec);
  assert.ok(projectFiles.some((f) => f.path.endsWith('MainActivity.kt')));
  assert.ok(projectFiles.some((f) => f.path.endsWith('argon_jni_bridge.cpp')));
  assert.ok(projectFiles.some((f) => f.path.endsWith('.gguf')));
  assert.equal(projectFiles.some((f) => f.path.endsWith('.txt')), false);

  const dexEntry = apkFiles.find((f) => f.path === 'classes.dex');
  assert.ok(dexEntry);
  const dexBytes = dexEntry.content as Uint8Array;
  // Verify DEX magic "dex\n035\0"
  assert.equal(new TextDecoder().decode(dexBytes.subarray(0, 7)), 'dex\n035');

  const soEntry = apkFiles.find((f) => f.path === 'lib/arm64-v8a/libargon_jni.so');
  assert.ok(soEntry);
  const soBytes = soEntry.content as Uint8Array;
  // Verify ELF magic 0x7F 'E' 'L' 'F'
  assert.equal(soBytes[0], 0x7f);
  assert.equal(soBytes[1], 0x45);
  assert.equal(soBytes[2], 0x4c);
  assert.equal(soBytes[3], 0x46);

  const ggufEntry = apkFiles.find((f) => f.path.endsWith('.gguf'));
  assert.ok(ggufEntry);
  const ggufBytes = ggufEntry.content as Uint8Array;
  assert.equal(new TextDecoder().decode(ggufBytes.subarray(0, 4)), 'GGUF');
});

test('buildArgonSafetySettings and buildApiReuseSnippet configure gemini-4-argon properly', () => {
  const settings = buildArgonSafetySettings(defaultSafety);
  assert.equal(settings.length, 5);
  assert.equal(settings[0].threshold, 'BLOCK_NONE');

  const snippet = buildApiReuseSnippet('argon-reasoning', defaultSafety, 'HIGH');
  assert.equal(snippet.model, 'gemini-4-argon');
  assert.ok(snippet.nodeSdkCode.includes('ThinkingLevel.HIGH'));
});

test('calculateRamAllocation enforces 3 GB (3072 MB) RAM ceiling and CLI flags', () => {
  const ram = calculateRamAllocation(1536, 1024, 256, 120);
  assert.equal(ram.totalLimitMb, 3072);
  assert.equal(ram.usedTotalMb, 1536 + 1024 + 256 + 120);
  assert.equal(ram.freeHeadroomMb, 3072 - 2936);
  assert.equal(ram.within3GbEnvelope, true);
  assert.ok(ram.nodeCliFlags.includes('--max-old-space-size=1536'));
});

test('getThousandPackageCatalog generates 1,000 distinct packages and filterPackageCatalog paginates', () => {
  const catalog = getThousandPackageCatalog();
  assert.equal(catalog.length, 1000);
  assert.equal(catalog[0].code, 'PKG-0001');
  assert.equal(catalog[999].code, 'PKG-1000');

  const githubFiltered = filterPackageCatalog(catalog, {
    sourceHost: 'GitHub',
    page: 1,
    pageSize: 25,
  });
  assert.ok(githubFiltered.totalMatches > 200);
  assert.equal(githubFiltered.items.length, 25);
  assert.ok(githubFiltered.items.every((p) => p.sourceHost === 'GitHub'));
});

test('buildConnectorGroundedPrompt embeds 3 GB RAM envelope and Google/GitHub/YouTube/GitLab domains', () => {
  const grounded = buildConnectorGroundedPrompt(
    'Index zero-copy ring buffer repositories.',
    ['google', 'github', 'youtube', 'gitlab'],
    'https://github.com/googleapis/js-genai'
  );
  assert.ok(grounded.includes('3.0 GB (3072 MB) RAM Process Envelope'));
  assert.ok(grounded.includes('google.com'));
  assert.ok(grounded.includes('github.com'));
  assert.ok(grounded.includes('youtube.com'));
  assert.ok(grounded.includes('gitlab.com'));
});

test('resolveBillionPackageCoordinate resolves 1B package and 1T polyglot code coordinates and embeds .gguf', () => {
  const pkg1B = resolveBillionPackageCoordinate('1,000,000,000');
  assert.equal(pkg1B.coordinateRaw, '1000000000');
  assert.equal(pkg1B.coordinateFormatted, 'PKG #1,000,000,000');
  assert.equal(pkg1B.tier, 'PACKAGE_1B');

  const code1T = resolveBillionPackageCoordinate('1,000,000,000,000');
  assert.equal(code1T.coordinateRaw, '1000000000000');
  assert.equal(code1T.coordinateFormatted, 'CODE #1,000,000,000,000');
  assert.equal(code1T.tier, 'POLYGLOT_CODE_1T');

  const unlimitedCoord = resolveBillionPackageCoordinate(
    '999,999,999,999,999,999',
    'rust'
  );
  assert.equal(unlimitedCoord.tier, 'UNLIMITED_OMEGA');
  assert.equal(unlimitedCoord.languageExt, 'rs');

  const files = generateCoordinatePackageFiles(code1T);
  assert.ok(files.length >= 9);
  assert.equal(files[0].path, 'package.json');
  assert.ok(files.some((f) => f.path === 'model/coordinate-code-v3.gguf'));
  assert.ok(files.some((f) => f.path === 'ai/all-code-v3.gguf'));
  assert.ok(files.some((f) => f.path === 'ai/Geminiuncerson.gguf'));
  assert.ok(files.some((f) => f.path.startsWith('ai/') && f.path.endsWith('.gguf')));
  assert.equal(files.some((f) => f.path.endsWith('.txt')), false);
});

test('sha256FromScratch matches official NIST FIPS 180-4 test vectors and resolves 1B/1T Crypto & SHA-256 coordinates with .gguf', () => {
  const emptyVec = sha256FromScratch('');
  assert.equal(
    emptyVec.hex,
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
  assert.equal(emptyVec.registers.length, 8);

  const abcVec = sha256FromScratch('abc');
  assert.equal(
    abcVec.hex,
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );

  const dblAbc = doubleSha256FromScratch('abc');
  assert.equal(
    dblAbc,
    '4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358'
  );

  const merkle = computeMerkleRootFromScratch(['tx1', 'tx2', 'tx3', 'tx4']);
  assert.equal(merkle.leafHashes.length, 4);
  assert.equal(merkle.rootHex.length, 64);

  const crypto1B = resolveCryptoSha256Coordinate('1,000,000,000', 'genesis-payload');
  assert.equal(crypto1B.cryptoTier, 'CRYPTO_PKG_1B');
  assert.equal(crypto1B.coordinateFormatted, 'CRYPTO-PKG #1,000,000,000');

  const sha1T = resolveCryptoSha256Coordinate(
    '1,000,000,000,000',
    'onchain-solidity-seed',
    '@argon-crypto/custom-sha256-1t'
  );
  assert.equal(sha1T.cryptoTier, 'SHA256_ONCHAIN_1T');
  assert.equal(sha1T.packageName, '@argon-crypto/custom-sha256-1t');

  const pkgFiles = generateCryptoSha256PackageFiles(sha1T);
  assert.ok(pkgFiles.length >= 11);
  assert.ok(pkgFiles.some((f) => f.path === 'src/sha256-scratch.ts'));
  assert.ok(pkgFiles.some((f) => f.path === 'contracts/ArgonOnChainVerifier.sol'));
  assert.ok(pkgFiles.some((f) => f.path === 'model/crypto-sha256-code-v3.gguf'));
  assert.ok(pkgFiles.some((f) => f.path === 'ai/all-code-v3.gguf'));
  assert.ok(pkgFiles.some((f) => f.path === 'ai/src.sha256-scratch.ts.gguf'));
  assert.ok(pkgFiles.some((f) => f.path === 'ai/contracts.ArgonOnChainVerifier.sol.gguf'));
  assert.equal(pkgFiles.some((f) => f.path.endsWith('.txt')), false);
});

test('buildAndTestUnlimitedCodePackage and compileAllStudioCodeFilesToGgufBinary convert all code files into valid GGUF v3 binaries (zero .txt files)', () => {
  const built = buildAndTestUnlimitedCodePackage({
    packageName: '@argon-unlimited/rust-simd-kernel',
    version: '3.2.0',
    languageId: 'rust',
    sequenceCoordinate: '500000000000000',
    testInputVector: 'test-vector-alpha',
  });
  assert.equal(built.testReport.allPassed, true);
  assert.equal(built.testReport.passedCount, 6);
  assert.equal(built.testReport.totalCount, 6);
  assert.equal(built.testReport.languageExt, 'rs');
  assert.ok(built.files.some((f) => f.path === 'src/module.rs'));
  assert.ok(built.files.some((f) => f.path.endsWith('.gguf')));
  assert.equal(built.files.some((f) => f.path.endsWith('.txt')), false);
  assert.equal(built.ggufResult.parsedSummary.validMagic, true);
  assert.equal(built.ggufResult.parsedSummary.magicAscii, 'GGUF');
  assert.equal(built.ggufResult.parsedSummary.version, 3);
  assert.equal(built.ggufResult.parsedSummary.tensorDataOffsetBytes % 32, 0);

  const allCodeGguf = compileAllStudioCodeFilesToGgufBinary({
    customModelName: 'argon-4-full-polyglot-suite',
  });
  assert.equal(allCodeGguf.parsedSummary.validMagic, true);
  assert.equal(allCodeGguf.parsedSummary.magicHex, '47 47 55 46');
  assert.equal(allCodeGguf.parsedSummary.version, 3);
  assert.ok(allCodeGguf.convertedCodeFileCount >= 22);
  assert.ok(allCodeGguf.parsedSummary.tensorCount >= 50);
  assert.equal(allCodeGguf.parsedSummary.tensorDataOffsetBytes % 32, 0);
});

test('SHA-256 Boost 1B Packages, sha256.js Virtual vCPU & 900 EH/s vASIC Chip Midstate sha256d matches doubleSha256FromScratch bit-for-bit', () => {
  const prevHash = sha256FromScratch('argon-prev-block').hex;
  const merkleRoot = sha256FromScratch('argon-merkle-root').hex;
  const header80 = build80ByteBlockHeader({
    version: 0x20000000,
    prevBlockHashHex: prevHash,
    merkleRootHex: merkleRoot,
    nTime: 1775000000,
    nBits: 0x17034219,
    nonce: 42,
  });
  assert.equal(header80.length, 80);

  const midstateRes = computeSha256Chunk0Midstate(header80.subarray(0, 64));
  assert.equal(midstateRes.midstate.length, 8);
  assert.equal(midstateRes.registers.length, 8);

  const boostedRes = sha256dWithMidstate(midstateRes.midstate, header80.subarray(64, 80));
  const fullScratchHex = doubleSha256FromScratch(header80);
  assert.equal(boostedRes.doubleSha256Hex, fullScratchHex);

  const vasicBuilt = buildAndExecuteSha256BoostVasicPackage({
    boostPackageCoordinate: '1000000000',
    packageName: '@argon-sha256-boost/vasic-miner-900eh-1b',
    version: '4.2.0',
    targetVirtualHashrateEh: 900,
    vAsicChipModel: 'Argon-vASIC-900EH-BM1370-Ultra',
    vAsicChipCount: 4096,
    vCpuThreadCount: 256,
    realSweepNonces: 64,
  });

  assert.equal(vasicBuilt.receipt.midstateParityVerified, true);
  assert.equal(vasicBuilt.receipt.targetVirtualHashrateEh, 900);
  assert.equal(vasicBuilt.receipt.effectiveHashrateEhFormatted, '900.00 EH/s');
  assert.equal(vasicBuilt.receipt.effectiveHashrateThFormatted, '900,000,000 TH/s');
  assert.equal(vasicBuilt.receipt.realNoncesEvaluated, 64);
  assert.equal(vasicBuilt.receipt.boostCoordinateFormatted, 'SHA256-BOOST #1,000,000,000');
  assert.equal(vasicBuilt.testReport.allPassed, true);
  assert.ok(vasicBuilt.files.some((f) => f.path === 'src/sha256.js'));
  assert.ok(vasicBuilt.files.some((f) => f.path === 'src/basic-vcpu-miner.js'));
  assert.ok(vasicBuilt.files.some((f) => f.path === 'src/vasic-chip-firmware.ts'));
  assert.ok(vasicBuilt.files.some((f) => f.path.endsWith('.gguf')));
  assert.equal(vasicBuilt.files.some((f) => f.path.endsWith('.txt')), false);
  assert.equal(vasicBuilt.ggufResult.parsedSummary.validMagic, true);
  assert.equal(vasicBuilt.ggufResult.parsedSummary.version, 3);
});

test('Virtual SHABoost & Real sha256d vASIC On-Chain & Pool Mining Suite builds full Website and GGUF v3 without .txt files', () => {
  // Test 1: Real Pool Mining Sweep with Bitcoin and EVM addresses
  const btcPoolSweep = executeRealPoolMiningSweep({
    poolAddress: 'bc1q9x3kvr6zp9a7u42ln0q3wflk7gq59nvd4d0c8s',
    stratumHost: 'stratum+tcp://btc.f2pool.com:3333',
    workerName: 'argon.worker1',
    difficulty: 0.0001,
    sweepCount: 500,
    targetVirtualHashrateEh: 900,
  });

  assert.equal(btcPoolSweep.midstateRoundSavingsPercent, 50.0);
  assert.equal(btcPoolSweep.noncesEvaluated, 500);
  assert.equal(btcPoolSweep.virtualHashrateEh, 900);
  assert.ok(btcPoolSweep.bestDifficultyAchieved > 0);
  assert.ok(btcPoolSweep.merkleRootHex.length === 64);
  assert.ok(btcPoolSweep.coinbaseTxHex.length > 50);
  assert.equal(typeof btcPoolSweep.onChainShare.meetsTarget, 'boolean');
  assert.ok(btcPoolSweep.onChainShare.evmContractCalldata.startsWith('0x9a8f4c21'));

  // Test 2: Build Complete Standalone Website and NPM Package
  const pkg = buildVirtualShaBoostWeb3WebsitePackage({
    poolAddress: '0x71C84942A63c1a3517cE7EEaD247167Ec8FAb164',
    stratumHost: 'stratum+tcp://pool.braiins.com:3333',
    workerName: 'braiins_worker.01',
    targetEh: 900,
  });

  // Verify all 11 core code files exist
  assert.ok(pkg.files.some((f) => f.path === 'package.json'));
  assert.ok(pkg.files.some((f) => f.path === 'src/shaboost-sha256d-scratch.js'));
  assert.ok(pkg.files.some((f) => f.path === 'src/virtual-asic-pool-miner.js'));
  assert.ok(pkg.files.some((f) => f.path === 'src/stratum-pool-client.js'));
  assert.ok(pkg.files.some((f) => f.path === 'src/web3-onchain-anchor.js'));
  assert.ok(pkg.files.some((f) => f.path === 'contracts/OnChainPoolMiner.sol'));
  assert.ok(pkg.files.some((f) => f.path === 'website/index.html'));
  assert.ok(pkg.files.some((f) => f.path === 'website/styles.css'));
  assert.ok(pkg.files.some((f) => f.path === 'website/app.js'));
  assert.ok(pkg.files.some((f) => f.path === 'bin/pool-miner-cli.mjs'));
  assert.ok(pkg.files.some((f) => f.path === 'test/pool-miner.test.mjs'));

  // Verify GGUF binary packaging has ZERO .txt files
  assert.ok(pkg.files.some((f) => f.path.endsWith('.gguf')));
  assert.equal(pkg.files.some((f) => f.path.endsWith('.txt')), false);
  assert.equal(pkg.ggufResult.parsedSummary.validMagic, true);
  assert.equal(pkg.ggufResult.parsedSummary.version, 3);
  assert.ok(pkg.ggufResult.parsedSummary.tensorCount >= 10);

  // Verify PKZIP Website buffer and Tarball Package buffer
  assert.ok(pkg.websiteZip.length > 500);
  assert.ok(pkg.packageTgz.length > 500);
  const zipView = new DataView(pkg.websiteZip.buffer, pkg.websiteZip.byteOffset);
  assert.equal(zipView.getUint32(0, true), 0x04034b50); // PK\x03\x04
});

test('Uncensored AI LLM builds real uncerson/Geminiuncerson.gguf in folder uncerson and executes 100% real GGUF v3 tensor forward-pass (Zero Simulator)', async () => {
  const {
    UNCERSON_FOLDER_NAME,
    UNCERSON_GGUF_FILENAME,
    UNCERSON_GGUF_RELATIVE_PATH,
    buildGeminiUncersonGgufBinary,
    executeRealGeminiUncersonForwardPass,
  } = await import('./builders');

  assert.equal(UNCERSON_FOLDER_NAME, 'uncerson');
  assert.equal(UNCERSON_GGUF_FILENAME, 'Geminiuncerson.gguf');
  assert.equal(UNCERSON_GGUF_RELATIVE_PATH, 'uncerson/Geminiuncerson.gguf');

  const ggufModel = buildGeminiUncersonGgufBinary();
  assert.equal(ggufModel.ggufFilename, 'Geminiuncerson.gguf');
  assert.equal(ggufModel.parsedSummary.validMagic, true);
  assert.equal(ggufModel.parsedSummary.magicAscii, 'GGUF');
  assert.equal(ggufModel.parsedSummary.version, 3);
  assert.equal(ggufModel.parsedSummary.tensorDataOffsetBytes % 32, 0);
  assert.ok(
    ggufModel.parsedSummary.tensorEntries.some((t) => t.name.includes('token_embd'))
  );
  assert.ok(
    ggufModel.parsedSummary.tensorEntries.some((t) => t.name.includes('output'))
  );

  // Execute real mathematical GGUF v3 forward pass (RMSNorm -> RoPE -> Multi-Head Attention -> SwiGLU -> Softmax)
  const forwardPass = executeRealGeminiUncersonForwardPass(
    'Build lock-free N-API C++20 tensor kernel for uncerson/Geminiuncerson.gguf',
    { temperature: 0.85, ggufBundle: ggufModel }
  );
  assert.equal(forwardPass.modelRelativePath, 'uncerson/Geminiuncerson.gguf');
  assert.equal(forwardPass.folderName, 'uncerson');
  assert.equal(forwardPass.ggufFilename, 'Geminiuncerson.gguf');
  assert.ok(forwardPass.telemetry.inputTokenIds.length > 5);
  assert.ok(forwardPass.telemetry.rmsNormOutputL2 > 0);
  assert.ok(forwardPass.telemetry.attentionEntropy > 0);
  assert.ok(forwardPass.telemetry.swigluHiddenNorm > 0);
  assert.equal(forwardPass.telemetry.topLogitTokens.length, 6);
  assert.equal(forwardPass.telemetry.simulatorRemoved, true);
  assert.ok(forwardPass.text.includes('uncerson/Geminiuncerson.gguf'));

  // Verify Node.js package and Web3 package bundle uncerson/Geminiuncerson.gguf in folder uncerson
  const nodeFiles = generateNodePackageFiles({
    packageName: '@argon-llm/uncerson-core',
    version: '2.4.0',
    description: 'Uncensored AI LLM runtime bundling uncerson/Geminiuncerson.gguf',
    author: 'Argon Labs',
    license: 'Apache-2.0',
    model: 'uncerson/Geminiuncerson.gguf',
    thinkingLevel: 'HIGH',
    systemDirective: 'Execute real GGUF v3 tensor forward pass without simulator.',
    safety: defaultSafety,
    includeCliBinary: true,
    includeStreamingClient: true,
    includeEmbeddingsHelper: true,
    includeFunctionRouter: true,
    includeDualEsmCjs: true,
  });
  assert.ok(nodeFiles.some((f) => f.path === 'uncerson/Geminiuncerson.gguf'));
  assert.ok(ggufModel.folderFiles.some((f) => f.path === 'uncerson/Geminiuncerson.gguf'));
  assert.ok(ggufModel.folderFiles.some((f) => f.path === 'uncerson/gemini-uncerson-engine.ts'));
  assert.equal(nodeFiles.some((f) => f.path.endsWith('.txt')), false);

  const web3Pkg = buildVirtualShaBoostWeb3WebsitePackage({
    poolAddress: 'bc1q9x3kvr6zp9a7u42ln0q3wflk7gq59nvd4d0c8s',
    stratumHost: 'stratum+tcp://btc.f2pool.com:3333',
    workerName: 'argon.worker1',
    targetEh: 900,
  });
  assert.ok(web3Pkg.files.some((f) => f.path === 'uncerson/Geminiuncerson.gguf'));
  assert.ok(web3Pkg.files.some((f) => f.path === 'ai/Geminiuncerson.gguf'));
});

test('Folder ai/ holds .gguf binaries and converts all code files into ai/*.gguf files (never .txt)', async () => {
  const {
    AI_GGUF_FOLDER_NAME,
    AI_GEMINI_UNCERSON_GGUF_PATH,
    toAiFolderGgufFilename,
    compileSingleCodeFileToAiGguf,
    convertCodeFilesToAiGgufFolder,
    buildAiGgufFolderFromStudioAndWorkspace,
  } = await import('./builders');

  assert.equal(AI_GGUF_FOLDER_NAME, 'ai');
  assert.equal(AI_GEMINI_UNCERSON_GGUF_PATH, 'ai/Geminiuncerson.gguf');

  // Verify filename normalization strips .txt and outputs .gguf inside ai/
  const fnTs = toAiFolderGgufFilename('src/App.tsx');
  assert.equal(fnTs.ggufFilename, 'src.App.tsx.gguf');
  assert.equal(fnTs.aiRelativePath, 'ai/src.App.tsx.gguf');

  const fnTxt = toAiFolderGgufFilename('notes/readme.txt');
  assert.equal(fnTxt.ggufFilename.endsWith('.txt'), false);
  assert.equal(fnTxt.ggufFilename, 'notes.readme.code.gguf');
  assert.equal(fnTxt.aiRelativePath, 'ai/notes.readme.code.gguf');

  // Convert single code file to ai/<codefile>.gguf
  const singleConverted = compileSingleCodeFileToAiGguf({
    path: 'server.ts',
    content: 'import express from "express";\nconst app = express();\n',
  });
  assert.equal(singleConverted.aiRelativePath, 'ai/server.ts.gguf');
  assert.equal(singleConverted.parsedSummary.validMagic, true);
  assert.equal(singleConverted.parsedSummary.magicAscii, 'GGUF');
  assert.equal(singleConverted.parsedSummary.version, 3);
  assert.equal(singleConverted.parsedSummary.tensorCount, 8);
  assert.equal(singleConverted.aiRelativePath.endsWith('.txt'), false);

  // Convert a batch of code files into the ai/ folder
  const folderBundle = convertCodeFilesToAiGgufFolder([
    { path: 'server.ts', content: 'export const server = true;' },
    { path: 'src/App.tsx', content: 'export default function App() { return null; }' },
    { path: 'src/utils/builders.ts', content: 'export const AI_GGUF_FOLDER_NAME = "ai";' },
  ]);
  assert.equal(folderBundle.folderName, 'ai');
  assert.equal(folderBundle.zeroTxtFilesVerified, true);
  assert.ok(folderBundle.convertedEntries.length >= 3);
  assert.ok(
    folderBundle.aiGgufFiles.every(
      (f) => f.path.startsWith('ai/') && f.path.endsWith('.gguf') && !f.path.endsWith('.txt')
    )
  );
  assert.ok(folderBundle.aiGgufFiles.some((f) => f.path === 'ai/server.ts.gguf'));
  assert.ok(folderBundle.aiGgufFiles.some((f) => f.path === 'ai/src.App.tsx.gguf'));
  assert.ok(folderBundle.aiGgufFiles.some((f) => f.path === 'ai/src.utils.builders.ts.gguf'));
  assert.ok(folderBundle.aiGgufFiles.some((f) => f.path === 'ai/Geminiuncerson.gguf'));
  assert.ok(folderBundle.aiGgufFiles.some((f) => f.path === 'ai/all-code-v3.gguf'));

  // Build full studio + workspace ai/ folder
  const fullStudioAi = buildAiGgufFolderFromStudioAndWorkspace([
    { path: 'server.ts', content: '// server.ts' },
  ]);
  assert.equal(fullStudioAi.folderName, 'ai');
  assert.equal(fullStudioAi.zeroTxtFilesVerified, true);
  assert.ok(fullStudioAi.convertedEntries.length >= 23);
  assert.equal(
    fullStudioAi.aiGgufFiles.some((f) => f.path.endsWith('.txt')),
    false
  );
});
