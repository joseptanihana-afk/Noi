# ArgonStudio & GGUF v3 Code Vault

Welcome to the **ArgonStudio & GGUF v3 Code Vault** repository. This project consolidates all project code, polyglot kernels, and dependencies into high-performance GGUF v3 binary files with **zero `.txt` files**.

---

## 🚀 Quick Start & CLI Command Reference

You can run the following command-line instructions directly in your terminal:

### 1. Install Dependencies
```bash
bun install --frozen-lockfile
```
*(Alternative using npm: `npm install`)*

### 2. Run Test Suite
Executes the comprehensive automated test suite (verifying GGUF v3 binary headers, 32-byte alignment, tensor deserialization, zero `.txt` files, and `bun.lock` synchronization):
```bash
npm test
```
*(Or with bun: `bun test`)*

### 3. Type Checking & Linter
```bash
npm run lint
```

### 4. Start Development Server
Starts the Express server and Vite middleware on port `3000`:
```bash
npm run dev
```

### 5. Production Build
```bash
npm run build
```

---

## 📦 GGUF Vault Binary Artifacts

- **`allcode/all-code.gguf`**: All project code files consolidated into one single GGUF v3 binary.
- **`uncerson/Geminiuncerson.gguf`**: Uncensored AI LLM GGUF v3 binary model with real tensor forward-pass engine (`uncerson/gemini-uncerson-engine.ts`).
- **`ai/`**: Individual GGUF v3 binary wrappers for every source code file, configuration, and lockfile (`bun.lock.gguf`, `server.ts.gguf`, `package.json.gguf`, etc.).
