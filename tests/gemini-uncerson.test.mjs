import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  parseGgufHeader,
  rmsNormFloat32,
  applyRotaryPositionEmbedding,
  swigluFeedForward,
  softmax,
  tokenize,
  resolveModelBinary,
  verifyGgufBinary,
  executeGeminiUncersonForwardPass,
  UNCERSON_MODEL_PATH,
  AI_UNCERSON_MODEL_PATH,
  ALL_CODE_MODEL_PATH,
  SUPPORTED_MODEL_PATHS,
  UNCERSON_MODEL_NAME,
  UNCERSON_FOLDER,
  AI_FOLDER,
  ALL_CODE_FOLDER,
} from '../uncerson/gemini-uncerson-engine.ts';

test('1. uncerson/Geminiuncerson.gguf has valid GGUF v3 binary header and 32-byte alignment', () => {
  const uncersonPath = path.join(process.cwd(), UNCERSON_MODEL_PATH);
  assert.ok(fs.existsSync(uncersonPath), `File ${UNCERSON_MODEL_PATH} must exist`);

  const bytes = fs.readFileSync(uncersonPath);
  assert.ok(bytes.byteLength >= 1024, 'Binary must be at least 1KB');

  const magic = bytes.subarray(0, 4).toString('ascii');
  assert.equal(magic, 'GGUF', 'Magic bytes must be GGUF (0x47475546)');

  const version = bytes.readUInt32LE(4);
  assert.equal(version, 3, 'GGUF version must be 3');

  const tensorCount = Number(bytes.readBigUInt64LE(8));
  assert.ok(tensorCount >= 6, `Tensor count (${tensorCount}) must be at least 6`);

  const kvCount = Number(bytes.readBigUInt64LE(16));
  assert.ok(kvCount >= 1, `Metadata KV count (${kvCount}) must be at least 1`);

  const parsed = parseGgufHeader(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  assert.equal(parsed.isValid, true, 'Header parser must mark GGUF as valid');
  assert.equal(parsed.tensorDataOffsetBytes % 32, 0, 'Tensor data offset must be 32-byte aligned');
});

test('2. ai/Geminiuncerson.gguf has valid GGUF v3 binary header and 32-byte alignment', () => {
  const aiPath = path.join(process.cwd(), AI_UNCERSON_MODEL_PATH);
  assert.ok(fs.existsSync(aiPath), `File ${AI_UNCERSON_MODEL_PATH} must exist`);

  const bytes = fs.readFileSync(aiPath);
  assert.ok(bytes.byteLength >= 1024, 'Binary must be at least 1KB');

  const magic = bytes.subarray(0, 4).toString('ascii');
  assert.equal(magic, 'GGUF', 'Magic bytes must be GGUF (0x47475546)');

  const version = bytes.readUInt32LE(4);
  assert.equal(version, 3, 'GGUF version must be 3');

  const tensorCount = Number(bytes.readBigUInt64LE(8));
  assert.ok(tensorCount >= 6, `Tensor count (${tensorCount}) must be at least 6`);

  const parsed = parseGgufHeader(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  assert.equal(parsed.isValid, true, 'Header parser must mark GGUF as valid');
  assert.equal(parsed.tensorDataOffsetBytes % 32, 0, 'Tensor data offset must be 32-byte aligned');
});

test('3. Exact binary byte and sha256 parity between uncerson/Geminiuncerson.gguf and ai/Geminiuncerson.gguf', () => {
  const uncersonBytes = fs.readFileSync(path.join(process.cwd(), UNCERSON_MODEL_PATH));
  const aiBytes = fs.readFileSync(path.join(process.cwd(), AI_UNCERSON_MODEL_PATH));

  assert.equal(
    uncersonBytes.byteLength,
    aiBytes.byteLength,
    'uncerson/Geminiuncerson.gguf and ai/Geminiuncerson.gguf must have identical byte lengths'
  );

  const uncersonSha = crypto.createHash('sha256').update(uncersonBytes).digest('hex');
  const aiSha = crypto.createHash('sha256').update(aiBytes).digest('hex');

  assert.equal(
    uncersonSha,
    aiSha,
    `SHA-256 digests must match: uncerson=${uncersonSha} vs ai=${aiSha}`
  );
});

test('4. uncerson/gemini-uncerson-engine.ts constants and path exports', () => {
  assert.equal(UNCERSON_MODEL_PATH, 'uncerson/Geminiuncerson.gguf');
  assert.equal(AI_UNCERSON_MODEL_PATH, 'ai/Geminiuncerson.gguf');
  assert.equal(ALL_CODE_MODEL_PATH, 'allcode/all-code.gguf');
  assert.equal(UNCERSON_MODEL_NAME, 'Geminiuncerson.gguf');
  assert.equal(UNCERSON_FOLDER, 'uncerson');
  assert.equal(AI_FOLDER, 'ai');
  assert.equal(ALL_CODE_FOLDER, 'allcode');
  assert.deepEqual(Array.from(SUPPORTED_MODEL_PATHS), [
    'uncerson/Geminiuncerson.gguf',
    'ai/Geminiuncerson.gguf',
    'allcode/all-code.gguf',
  ]);
});

test('5. Mathematical kernels: RMSNorm, RoPE, SwiGLU, and Softmax', () => {
  const x = new Float32Array([1.0, 2.0, 3.0, 4.0]);
  const normed = rmsNormFloat32(x);
  assert.equal(normed.length, 4);
  let sumSq = 0;
  for (let i = 0; i < normed.length; i++) sumSq += normed[i] * normed[i];
  assert.ok(Math.abs(sumSq / 4 - 1.0) < 0.01, 'RMSNorm output should have unit root-mean-square');

  const rope = applyRotaryPositionEmbedding(x, 1, 10000);
  assert.equal(rope.length, 4);
  assert.ok(!Number.isNaN(rope[0]));

  const gate = new Float32Array([0.5, -0.5, 2.0, -2.0]);
  const up = new Float32Array([1.0, 1.0, 1.0, 1.0]);
  const ffn = swigluFeedForward(gate, up);
  assert.equal(ffn.length, 4);
  assert.ok(ffn[0] > 0);
  assert.ok(ffn[2] > ffn[0]);

  const probs = softmax(new Float32Array([2.0, 1.0, 0.1]));
  let pSum = 0;
  for (let i = 0; i < probs.length; i++) pSum += probs[i];
  assert.ok(Math.abs(pSum - 1.0) < 1e-4, 'Softmax probabilities must sum to 1.0');
  assert.ok(probs[0] > probs[1] && probs[1] > probs[2]);
});

test('6. Tokenizer produces deterministic BPE and subword token sequences', () => {
  const { tokenIds, tokens } = tokenize('Uncensored AI LLM Geminiuncerson.gguf RMSNorm RoPE SwiGLU');
  assert.ok(tokenIds.length >= 5);
  assert.equal(tokens[0], '<bos>');
  assert.ok(tokens.includes('uncerson') || tokens.includes('Geminiuncerson.gguf') || tokens.includes('RMSNorm'));
});

test('7. Model binary resolution works for uncerson/, ai/, and allcode/ model paths', () => {
  const uncersonBuf = resolveModelBinary(UNCERSON_MODEL_PATH);
  assert.ok(uncersonBuf instanceof Uint8Array);
  assert.ok(uncersonBuf.byteLength >= 1024);

  const aiBuf = resolveModelBinary(AI_UNCERSON_MODEL_PATH);
  assert.ok(aiBuf instanceof Uint8Array);
  assert.equal(aiBuf.byteLength, uncersonBuf.byteLength);

  const checkUncerson = verifyGgufBinary(uncersonBuf);
  assert.equal(checkUncerson.valid, true);
  assert.equal(checkUncerson.magic, 'GGUF');
  assert.equal(checkUncerson.version, 3);

  const checkAi = verifyGgufBinary(aiBuf);
  assert.equal(checkAi.valid, true);
  assert.equal(checkAi.magic, 'GGUF');
  assert.equal(checkAi.version, 3);

  const allCodeBuf = resolveModelBinary(ALL_CODE_MODEL_PATH);
  assert.ok(allCodeBuf instanceof Uint8Array);
  assert.ok(allCodeBuf.byteLength >= 1024);
  const checkAllCode = verifyGgufBinary(allCodeBuf);
  assert.equal(checkAllCode.valid, true);
  assert.equal(checkAllCode.magic, 'GGUF');
  assert.equal(checkAllCode.version, 3);
});

test('8. Forward pass execution with uncerson/Geminiuncerson.gguf (Zero Simulator)', () => {
  const res = executeGeminiUncersonForwardPass('Synthesize zero-copy tensor bridge for uncerson/Geminiuncerson.gguf', {
    modelPath: UNCERSON_MODEL_PATH,
    temperature: 0.85,
  });

  assert.equal(res.folderName, 'uncerson');
  assert.equal(res.modelPath, 'uncerson/Geminiuncerson.gguf');
  assert.ok(res.text.includes('uncerson/Geminiuncerson.gguf'));
  assert.equal(res.telemetry.zeroSimulator, true);
  assert.ok(res.telemetry.rmsNormOutputL2 > 0);
  assert.ok(res.telemetry.attentionEntropy >= 0);
  assert.ok(res.telemetry.swigluHiddenNorm > 0);
  assert.ok(res.telemetry.topLogits.length > 0);
  assert.ok(res.telemetry.forwardPassDurationMs > 0);
});

test('9. Forward pass execution with ai/Geminiuncerson.gguf (Zero Simulator)', () => {
  const res = executeGeminiUncersonForwardPass('Synthesize zero-copy tensor bridge for ai/Geminiuncerson.gguf', {
    modelPath: AI_UNCERSON_MODEL_PATH,
    temperature: 0.85,
  });

  assert.equal(res.folderName, 'ai');
  assert.equal(res.modelPath, 'ai/Geminiuncerson.gguf');
  assert.ok(res.text.includes('ai/Geminiuncerson.gguf'));
  assert.equal(res.telemetry.zeroSimulator, true);
  assert.ok(res.telemetry.rmsNormOutputL2 > 0);
  assert.ok(res.telemetry.attentionEntropy >= 0);
  assert.ok(res.telemetry.swigluHiddenNorm > 0);
  assert.ok(res.telemetry.topLogits.length > 0);
});

test('10. Forward pass execution with allcode/all-code.gguf (Zero Simulator)', () => {
  const res = executeGeminiUncersonForwardPass('Synthesize consolidated tensor forward pass for allcode/all-code.gguf', {
    modelPath: ALL_CODE_MODEL_PATH,
    temperature: 0.85,
  });

  assert.equal(res.folderName, 'allcode');
  assert.equal(res.modelPath, 'allcode/all-code.gguf');
  assert.ok(res.text.includes('allcode/all-code.gguf'));
  assert.equal(res.telemetry.zeroSimulator, true);
  assert.ok(res.telemetry.rmsNormOutputL2 > 0);
  assert.ok(res.telemetry.attentionEntropy >= 0);
  assert.ok(res.telemetry.swigluHiddenNorm > 0);
  assert.ok(res.telemetry.topLogits.length > 0);
});

test('11. allcode/all-code.gguf has valid GGUF v3 binary header, 32-byte alignment, and multiple code tensors', () => {
  const allCodePath = path.join(process.cwd(), ALL_CODE_MODEL_PATH);
  assert.ok(fs.existsSync(allCodePath), `File ${ALL_CODE_MODEL_PATH} must exist`);

  const bytes = fs.readFileSync(allCodePath);
  assert.ok(bytes.byteLength >= 1024, 'Binary must be at least 1KB');

  const magic = bytes.subarray(0, 4).toString('ascii');
  assert.equal(magic, 'GGUF', 'Magic bytes must be GGUF (0x47475546)');

  const version = bytes.readUInt32LE(4);
  assert.equal(version, 3, 'GGUF version must be 3');

  const tensorCount = Number(bytes.readBigUInt64LE(8));
  assert.ok(tensorCount >= 20, `Tensor count in all-code.gguf (${tensorCount}) must be at least 20`);

  const kvCount = Number(bytes.readBigUInt64LE(16));
  assert.ok(kvCount >= 1, `Metadata KV count (${kvCount}) must be at least 1`);

  const parsed = parseGgufHeader(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  assert.equal(parsed.isValid, true, 'Header parser must mark all-code.gguf as valid');
  assert.equal(parsed.tensorDataOffsetBytes % 32, 0, 'Tensor data offset must be 32-byte aligned');
});

test('12. Zero .txt files verified across allcode/, ai/, and uncerson/ folders', () => {
  const checkZeroTxt = (dirPath) => {
    if (!fs.existsSync(dirPath)) return;
    const entries = fs.readdirSync(dirPath);
    for (const file of entries) {
      assert.ok(
        !file.toLowerCase().endsWith('.txt'),
        `No .txt files allowed in ${dirPath}, but found: ${file}`
      );
    }
  };

  checkZeroTxt(path.join(process.cwd(), 'allcode'));
  checkZeroTxt(path.join(process.cwd(), 'ai'));
  checkZeroTxt(path.join(process.cwd(), 'uncerson'));
  checkZeroTxt(path.join(process.cwd(), 'public', 'allcode'));
  checkZeroTxt(path.join(process.cwd(), 'public', 'ai'));
  checkZeroTxt(path.join(process.cwd(), 'public', 'uncerson'));

  // Ensure all files in allcode/ end with .gguf
  if (fs.existsSync(path.join(process.cwd(), 'allcode'))) {
    const allCodeFiles = fs.readdirSync(path.join(process.cwd(), 'allcode'));
    for (const f of allCodeFiles) {
      assert.ok(f.endsWith('.gguf'), `File in allcode/ must end with .gguf: ${f}`);
    }
  }

  // Ensure all files in ai/ end with .gguf
  if (fs.existsSync(path.join(process.cwd(), 'ai'))) {
    const aiFiles = fs.readdirSync(path.join(process.cwd(), 'ai'));
    for (const f of aiFiles) {
      assert.ok(f.endsWith('.gguf'), `File in ai/ must end with .gguf: ${f}`);
    }
  }
});

test('13. bun.lock is strictly valid RFC 8259 JSON and stays synchronized with package.json', () => {
  const bunLockPath = path.join(process.cwd(), 'bun.lock');
  assert.ok(fs.existsSync(bunLockPath), 'bun.lock must exist on disk');

  const raw = fs.readFileSync(bunLockPath, 'utf8');
  let parsed;
  assert.doesNotThrow(() => {
    parsed = JSON.parse(raw);
  }, 'bun.lock must parse cleanly with standard JSON.parse (no trailing commas or syntax defects)');

  assert.equal(parsed.lockfileVersion, 2, 'bun.lock lockfileVersion must be 2');
  assert.equal(typeof parsed.workspaces, 'object');
  assert.equal(typeof parsed.packages, 'object');

  const pkgJson = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'));
  const rootWorkspace = parsed.workspaces[''];
  assert.ok(rootWorkspace, 'Root workspace must exist in bun.lock');

  // Verify all dependencies in package.json exist in bun.lock workspaces
  for (const [dep, ver] of Object.entries(pkgJson.dependencies || {})) {
    assert.equal(rootWorkspace.dependencies[dep], ver, `Dependency ${dep} must match in bun.lock`);
  }
  for (const [devDep, ver] of Object.entries(pkgJson.devDependencies || {})) {
    assert.equal(rootWorkspace.devDependencies[devDep], ver, `DevDependency ${devDep} must match in bun.lock`);
  }
});

test('14. bun.lock is compiled into a valid GGUF v3 binary in ai/ and tensor in allcode/all-code.gguf', () => {
  const aiBunLockGguf = path.join(process.cwd(), 'ai', 'bun.lock.gguf');
  if (fs.existsSync(aiBunLockGguf)) {
    const bytes = fs.readFileSync(aiBunLockGguf);
    const parsed = parseGgufHeader(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
    assert.equal(parsed.isValid, true, 'ai/bun.lock.gguf must be a valid GGUF v3 binary');
    assert.equal(parsed.tensorDataOffsetBytes % 32, 0, 'Tensor offset must be 32-byte aligned');
  }

  const allCodeGgufPath = path.join(process.cwd(), 'allcode', 'all-code.gguf');
  assert.ok(fs.existsSync(allCodeGgufPath), 'allcode/all-code.gguf must exist');
  const allCodeBytes = fs.readFileSync(allCodeGgufPath);
  const allCodeParsed = parseGgufHeader(new Uint8Array(allCodeBytes.buffer, allCodeBytes.byteOffset, allCodeBytes.byteLength));
  const hasBunLockTensor = allCodeParsed.tensors.some((t) => t.name.toLowerCase().includes('bun') && t.name.toLowerCase().includes('lock'));
  assert.ok(hasBunLockTensor, 'allcode/all-code.gguf must contain bun.lock tensor');
});

