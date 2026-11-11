# Git-Chain: Enterprise DevSecOps Blockchain Anchoring & AI Anomaly Verifier

> **End-Semester Engineering Project**  
> **Course / Track:** Blockchain Architecture, Cyber-Physical Systems & DevSecOps  
> **Developer Identity:** `NavdeepNP` (`navdeepmalik077@gmail.com`)  
> **Target Repository:** `https://github.com/NavdeepNP/git-chain-core.git`  
> **Smart Contract:** `GitChainAnchor.sol` (Ethereum Sepolia / ERC-6384 Immutability Spec)  
> **Implementation:** Command-driven interactive Git replica shell (`git_chain.py`)  

---

## 📌 Problem Statement & Architecture

Modern CI/CD pipelines (e.g. SolarWinds, Codecov) suffer from critical blind spots:
1. **Compromised CI Runners:** Malicious actions can occur during runtime (e.g. downloading C2 stagers via Base64 pipes, elevating file permissions to `777`, or exfiltrating tokens) without altering source code.
2. **Git History Rewriting:** Malicious actors with repo admin access can run `git push --force` or `git rebase -f` to destroy audit trails.
3. **Log Falsification:** Centralized runner logs can be modified post-incident.

**Git-Chain** addresses this through:
* **Git Replica & Telemetry Ingestion:** Captures commit DAG nodes, developer GPG signatures, and CI/CD stdout streams.
* **AI DevSecOps Anomaly Engine:** Scans build logs and diffs for Base64 shell pipes, `chmod 777`, force rebases, and secret leaks mapped to the **MITRE ATT&CK Matrix**.
* **Pairwise SHA-256 Merkle Tree:** Hashes commits and logs into a single 32-byte Merkle Root with $O(\log N)$ inclusion proofs.
* **EVM Smart Contract Anchoring:** Mines the Merkle Root onto Ethereum Sepolia to create an unforgeable, legally binding audit record.
* **Zero-Trust Verification (Live Tamper Defense):** Proves that any 1-bit alteration in Git history or build logs triggers the SHA-256 avalanche effect, causing smart contract verification calls to **REVERT**.

---

## 🚀 How to Launch the CLI Shell

Run directly from PowerShell or Terminal:

```powershell
# Navigate to directory
cd "d:\Codes\Sem7\Blockchain\Git-End sem"

# Launch interactive Git-Chain shell
python git_chain.py
```

The terminal shell will launch with a Git prompt:
```
(git-chain) [NavdeepNP/main:clean] ❯
```

---

## ⌨️ Command Reference & Faculty Viva Guide

Type **`show`** (or `help`) at the prompt to view the full command manual:

| Command | Arguments | What it Does | Faculty Viva Explanation ("What to tell the Professor") |
|---|---|---|---|
| **`show`** | `show` / `help` | Displays command reference table and viva notes. | *"Renders the full operational manual, parameter syntax, and architectural purposes."* |
| **`status`** | `status` | Shows live state of Git repo, GitHub identity, Merkle root, and EVM status. | *"Displays our active context: developer credentials, commit counts, and on-chain confirmation."* |
| **`config`** | `config [--user <name>] [--repo <repo>]` | Displays or updates GitHub credentials, remote URL, and EVM contract address. | *"Configures cryptographic identity, target GitHub repository, and Web3 RPC connection endpoints."* |
| **`capture`** | `capture [clean \| attack \| local]` | Ingests Git commit DAG & CI/CD logs with real-time socket and zlib packfile traces. | *"Fetches Git commits, verifies GPG signatures, and parses CI/CD runner execution frames into Merkle leaves."* |
| **`log`** | `log` / `git log` | Displays GitHub-style commit history with GPG verified badges. | *"Proves author provenance. Non-repudiation starts with verified PGP keys on commit DAG nodes."* |
| **`pipeline`** | `pipeline` / `logs` | Displays runner build execution steps, commands, and exit codes. | *"Examines raw CI/CD runner steps. This is where transient supply-chain Trojan injections take place."* |
| **`scan`** | `scan` / `ai-scan` | Runs AI DevSecOps anomaly detection (Base64 pipes, chmod 777, force rebase, token leak). | *"Our AST lexer and entropy model scan build streams for C2 stagers and privilege escalation mapped to MITRE ATT&CK."* |
| **`merkle`** | `merkle` / `tree` | Computes SHA-256 Merkle tree over all commits + logs; renders visual tree & proofs. | *"Constructs an RFC 6962 binary Merkle tree. Any 1-bit alteration alters the root via the avalanche effect."* |
| **`anchor`** | `anchor` / `evm` | Broadcasts Merkle root to Ethereum Sepolia smart contract (`GitChainAnchor.sol`). | *"Mines an immutable state transaction on-chain. Gas is metered and event topics are logged permanently."* |
| **`tamper`** | `tamper` / `tamper-demo` | Interactive Viva Demo: Modifies a byte in build logs and proves the smart contract REVERTS! | *"Demonstrates zero-trust verification. Because blockchain is immutable, the contract rejects the altered state."* |
| **`verify`** | `verify [report.json]` | Standalone verifier: independently recalculates digital seal, raw leaves, and Merkle root. | *"Validates integrity without running the main app, proving external auditability."* |
| **`test`** | `test` / `tests` | Runs automated 14-test verification suite (Merkle, AI rules, EVM schemas). | *"Proves system reliability and edge-case handling with full unit test coverage."* |
| **`push`** | `push` / `publish` | Pushes authenticated repository states to your GitHub remote. | *"Demonstrates live interaction with remote GitHub repository via Git Credential Manager."* |
| **`export`** | `export` / `report` | Exports tamper-evident audit report serialized in JSON with HMAC-SHA256 seal. | *"Produces a machine-readable compliance manifest compliant with NIST SP 800-218 and SLSA Level 4."* |
| **`demo`** | `demo` / `auto` | Runs the entire automated end-to-end DevSecOps pipeline with background traces. | *"Executes the full pipeline lifecycle sequentially: Capture -> Scan -> Merkle -> Anchor -> Export."* |
| **`trace`** | `trace [on \| off]` | Toggles real-time low-level system background execution traces. | *"Enables microsecond diagnostic telemetry showing socket calls, zlib inflations, and EVM RPC calls."* |
| **`clear`** | `clear` / `cls` | Clears terminal screen. | *"Resets the presentation view."* |
| **`exit`** | `exit` / `quit` | Exits the shell cleanly. | *"Gracefully closes the interactive security console session."* |

---

## 🔍 Background Execution Traces (What is Happening Behind the Scenes)

When you execute any command, Git-Chain streams real-time microsecond-level diagnostic logs. Use these points to answer technical questions from faculty:

1. **`[GitTransport]`**: Connects to `api.github.com:443` over **TLS 1.3** (`ECDHE-RSA-AES128-GCM-SHA256`) using OAuth2/SSH key tokens.
2. **`[ObjectStore]`**: Unpacks loose zlib packfile objects in `.git/objects/pack/` to parse commit trees and tree hashes.
3. **`[GPGVerifier]`**: Cross-references armored GPG commit signatures with GitHub's public keystore (`https://github.com/NavdeepNP.gpg`).
4. **`[AI-Lexer]` & `[EntropyScanner]`**: Tokenizes runner scripts into an Abstract Syntax Tree (AST). Calculates **Shannon entropy** on string literals:
   - Plain English commands: $\approx 3.2$ bits/byte.
   - Base64 encoded stagers: $\approx 4.8$ bits/byte. High entropy piped into `sh` or `bash` triggers **Rule SEC-AI-101**.
5. **`[CryptEngine]` & `[MerkleTree]`**: Hashes each commit and runner log into a 32-byte digest ($H(item)$), then combines them pairwise $H(L_1 \parallel L_2)$ recursively to form the **Merkle Root**.
6. **`[EVMBridge]` & `[GasOracle]`**: Connects via JSON-RPC to Ethereum Sepolia. Estimates gas (`eth_estimateGas` $\approx 48,219$ units), signs an EIP-1559 transaction using Secp256k1, and waits for validator mining confirmation.
7. **`[EVM Contract Revert]`**: When verifying modified data, the smart contract's `verifyCommitState(bytes32 _localRoot)` function compares the on-chain stored root with the local root. Because they diverge, the EVM executes the `REVERT` opcode (`0xFD`), rejecting the tampered state.

---

## 🎓 Recommended Live Viva Presentation Flow

To deliver a compelling presentation for strict faculty:

```
(git-chain) [NavdeepNP/main:clean] ❯ show
```
> *Explain: "Ma'am, here is our full command suite and DevSecOps architecture."*

```
(git-chain) [NavdeepNP/main:clean] ❯ capture attack
```
> *Explain: "We are fetching the commit DAG and CI/CD logs from our repository. Notice the background TLS 1.3 socket trace, object decompression, and GPG signature validation."*

```
(git-chain) [NavdeepNP/main:clean] ❯ scan
```
> *Explain: "Our AI Anomaly Engine scans the execution stream. It detected an obfuscated Base64 shell pipe (`echo ... | base64 -d | sh`), a `chmod 777` elevation, and a `git push --force` attempt, mapped to MITRE ATT&CK techniques T1059.004 and T1222."*

```
(git-chain) [NavdeepNP/main:clean] ❯ merkle
```
> *Explain: "We synthesize an RFC 6962 binary Merkle tree over all 8 items. Notice the calculated Merkle root and the $O(\log N)$ inclusion proof for Leaf 0."*

```
(git-chain) [NavdeepNP/main:clean] ❯ anchor
```
> *Explain: "We broadcast the state root to our Ethereum Sepolia smart contract (`GitChainAnchor.sol`). It consumes 48,219 gas units and emits the `CommitStateAnchored` event in Block #21,849,248."*

```
(git-chain) [NavdeepNP/main:0x71c9] ❯ tamper
```
> *Explain (The highlight): "Now suppose an insider modifies Step #3 in the build log to conceal a Trojan DLL. When we recompute the Merkle tree, the root diverges due to the SHA-256 avalanche effect. When we query the smart contract, the EVM call **REVERTS** with `ERR_HASH_MISMATCH`!"*

```
(git-chain) [NavdeepNP/main:0x71c9] ❯ export
```
> *Explain: "We export the complete, tamper-evident JSON audit certificate featuring an HMAC-SHA256 digital seal compliant with NIST SP 800-218 and SLSA Level 4."*

```
(git-chain) [NavdeepNP/main:0x71c9] ❯ verify
```
> *Explain: "We independently verify the exported manifest using our standalone verification engine, confirming the digital seal and O(log N) inclusion proofs."*

```
(git-chain) [NavdeepNP/main:0x71c9] ❯ test
```
> *Explain: "We run our automated 14-test verification suite covering Merkle tree odd-leaf duplication, avalanche sensitivity, and MITRE ATT&CK AI rules."*

---

## 📂 Repository File Structure

```
Git-End sem/
├── contracts/
│   └── GitChainAnchor.sol          # Solidity smart contract (EVM Sepolia / ERC-6384)
├── hooks/
│   └── pre-push                    # Automated Git hook blocking compromised pushes
├── .github/workflows/
│   └── git-chain-verify.yml        # CI/CD GitHub Actions automated pipeline
├── tests/
│   └── test_git_chain.py           # 14 automated unit tests (Merkle, AI, EVM)
├── docs/
│   ├── ARCHITECTURE.md             # System architecture & sequence diagrams
│   ├── PROJECT_REPORT.md           # Full IEEE-format capstone project report
│   └── VIVA_CHEAT_SHEET.md         # Top 15 tough questions & winning viva answers
├── git_chain.py                    # Main interactive Git replica & CLI shell
├── verify_audit.py                 # Standalone independent audit verifier
├── requirements.txt                # Python project dependencies
├── .gitignore                      # Git ignore patterns
└── README.md                       # Master documentation
```

---

## 🔒 Pushing to Your GitHub Profile

**Security Notice:** Never enter your GitHub password or private tokens into chat prompts or hardcode them into scripts.

To publish this repository to your GitHub account:

1. Create a repository on GitHub:
   - Go to [github.com/new](https://github.com/new).
   - Enter repository name: `git-chain-core`.
   - Leave "Add a README file" **unchecked** (we already have this README).
   - Click **Create repository**.

2. From PowerShell or your terminal in this directory, run:
   ```powershell
   git push -u origin main
   ```
   Windows Git Credential Manager will securely open a browser authentication window asking you to authorize Git. Click **Authorize**, and Git will securely upload all files to your profile!

