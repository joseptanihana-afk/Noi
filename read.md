# ArgonStudio & GGUF v3 Code Vault

Welcome to the **ArgonStudio & GGUF v3 Code Vault** repository. This project encapsulates workspace code, dependencies, and polyglot kernels into spec-compliant GGUF v3 binary files with **zero `.txt` files**.

---

## Quick Start Commands

Run these commands in your terminal to install dependencies, run tests, lint, and start the development server.

### 1. Install Dependencies
```bash
bun install --frozen-lockfile
```
*(Or alternatively: `npm install`)*

### 2. Run Test Suite
Runs the complete test suite verifying GGUF v3 binary headers, 32-byte alignment, tensor deserialization, zero `.txt` files, and `bun.lock` synchronization:
```bash
npm test
```
*(Or with Bun: `bun test`)*

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

## Project GGUF Vault Structure

- **`allcode/all-code.gguf`**: All project code files consolidated into a single GGUF v3 binary.
- **`uncerson/Geminiuncerson.gguf`**: Real uncensored GGUF v3 binary model with 100% mathematical forward-pass engine (`uncerson/gemini-uncerson-engine.ts`).
- **`ai/`**: Individual GGUF v3 binary wrappers for every source code file, configuration, and lockfile (`bun.lock.gguf`, `server.ts.gguf`, etc.).
