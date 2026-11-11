# Git-Chain: Viva Defense & Faculty Examination Cheat Sheet

> **Quick-Reference Guide for Defending Your End-Semester Capstone Project**  
> *Targeted for strict faculty, external examiners, and blockchain/security evaluators.*

---

## 🎯 Top 15 Tough Viva Questions & Winning Answers

### Q1: "Why did you use Blockchain? Why not just store the logs in an encrypted PostgreSQL or AWS CloudWatch database?"
> **Winning Answer:**  
> *"Ma'am, centralized databases—even encrypted ones—have a single point of failure: the root administrator or Database Administrator (DBA). In breaches like SolarWinds or Capital One, attackers compromised administrative credentials and altered or deleted database audit rows without leaving a forensic trace.  
> A public blockchain like Ethereum is decentralized and Byzantine fault-tolerant. Once a block is mined, no administrator, AWS engineer, or company CEO can edit or delete that state. It provides mathematical non-repudiation and external third-party trust."*

---

### Q2: "Storing data on Ethereum is notoriously expensive. How can your system scale to thousands of commits and gigabytes of logs?"
> **Winning Answer:**  
> *"We do not store raw logs or commits on-chain. Storing 1 MB on Ethereum would cost thousands of dollars.  
> Instead, Git-Chain uses **off-chain computation with on-chain anchoring**. We compress millions of bytes of Git commit trees and runner stdout logs into a single 32-byte cryptographic SHA-256 Merkle Root. On-chain, we write exactly one `bytes32` value (`SSTORE`), which consumes a constant $O(1)$ ~48,000 gas units (~$1.20 USD equivalent at 20 Gwei), whether the repository has 10 commits or 10 million commits."*

---

### Q3: "What is a Merkle Tree, and why did you choose it over a simple hash chain like a linked list?"
> **Winning Answer:**  
> *"A Merkle Tree is a binary tree where every leaf is the cryptographic hash of a data block, and every non-leaf node is the hash of its children.  
> In a linear hash chain, proving that a specific build log line existed requires scanning all $O(N)$ elements from beginning to end. With a binary Merkle Tree, we can generate an **Inclusion Proof in $O(\log N)$ time and space**. For 1,000,000 logs, a proof requires only 20 hashes! Furthermore, Merkle trees allow us to prove authenticity to an auditor without revealing confidential source code in other branches."*

---

### Q4: "What happens if an attacker with repo admin access runs `git push --force` or `git rebase`?"
> **Winning Answer:**  
> *"Git by itself allows non-fast-forward history overwriting if the user has admin permissions. However, Git-Chain anchors the Merkle root of the previous state to the smart contract at an immutable block height.  
> If an attacker forces a rebase, the commit parents and SHA hashes change, altering the Merkle root. When the pipeline or auditor executes `verifyCommitState(localRoot)`, the contract immediately detects the divergence and flags a **STATE_CORRUPTED** alert. The attacker cannot rewrite Ethereum blocks."*

---

### Q5: "What if a developer's private key or GitHub personal access token is stolen?"
> **Winning Answer:**  
> *"We implement Defense-in-Depth across two independent security layers:  
> 1. Even if an attacker gains commit privileges, our **AI Anomaly Detection Engine** tokenizes the CI/CD execution stream. If the attacker injects a Base64 reverse shell pipe or alters permissions (`chmod 777`), the pipeline blocks the build before it can be signed.  
> 2. On-chain anchoring requires authorization from a dedicated Security Officer address (or multi-signature wallet) on the smart contract, separating commit permissions from release anchoring permissions."*

---

### Q6: "Explain the Avalanche Effect in SHA-256."
> **Winning Answer:**  
> *"The avalanche effect is a fundamental property of cryptographic hash functions where flipping a single bit in the input causes an average of 50% of the output bits to change randomly. In our system, if an attacker changes even one character in a build log step (e.g., from `exit: 0` to `exit: 1`), the leaf hash changes completely, cascading up parent nodes and changing the Merkle Root. The probability of an accidental collision is $\frac{1}{2^{256}}$, which is mathematically negligible."*

---

### Q7: "Show me how your AI engine works. Is it just regex, or does it do AST analysis?"
> **Winning Answer:**  
> *"Our engine combines two layers:  
> 1. **AST Tokenization & Shannon Entropy Scanning:** It measures string entropy. Plain text commands have an entropy around 3.2 bits/byte, whereas Base64-encoded payloads have an entropy exceeding 4.8 bits/byte. High entropy piped into shell interpreters (`| sh` or `| bash`) triggers Rule SEC-AI-101.  
> 2. **Heuristic Rule Matrix:** Mapped directly to the MITRE ATT&CK DevSecOps framework, detecting privilege escalation (`T1222.002`), shell stagers (`T1059.004`), credential exfiltration (`T1552.001`), and destructive Git history rewrites (`T1565.001`)."*

---

### Q8: "What standard or RFC does your Merkle implementation follow?"
> **Winning Answer:**  
> *"Our implementation strictly follows **RFC 6962** (Certificate Transparency). Specifically:  
> 1. Leaves are prepended with canonical serialization headers.  
> 2. Pairwise hashing is performed deterministically.  
> 3. When an odd number of leaf nodes exists at any level, the final node is duplicated to maintain binary tree symmetry."*

---

### Q9: "Where is your actual Solidity contract deployed, and what events does it emit?"
> **Winning Answer:**  
> *"Our smart contract is `contracts/GitChainAnchor.sol`. It is deployed on Ethereum Sepolia testnet at address `0x71C94824b278f2B5481B27fBE801e0d37e2A3dB4`. It emits the `CommitStateAnchored(bytes32 indexed merkleRoot, bytes32 indexed repositoryDigest, address indexed anchorer, uint256 blockTimestamp)` event, enabling off-chain indexers and The Graph subgraphs to listen for state changes in real time."*

---

### Q10: "If I take your exported JSON audit file home, how can I be sure nobody tampered with it?"
> **Winning Answer:**  
> *"The JSON artifact contains an embedded `tamper_evident_seal`. We use RFC 8785 JSON Canonicalization to sort keys and compute an HMAC/SHA-256 digital signature over the entire document.  
> We have provided an independent, zero-dependency verifier script: `python verify_audit.py <file.json>`. It independently recalculates the digital seal, recomputes the Merkle tree from the raw commit data, and verifies the logarithmic proof path. If even a single comma or letter is changed, verification fails."*

---

### Q11: "What are SLSA and NIST SP 800-218 mentioned in your project?"
> **Winning Answer:**  
> *"**SLSA** stands for *Supply-chain Levels for Software Artifacts*, created by Google and the OpenSSF to prevent tampering from source to release. Git-Chain achieves SLSA Level 4 by providing non-falsifiable provenance.  
> **NIST SP 800-218** is the United States *Secure Software Development Framework (SSDF)*, which mandates verifiable audit trails, integrity verification, and tamper protection across the entire SDLC."*

---

### Q12: "How does Git-Chain prevent replay attacks on the smart contract?"
> **Winning Answer:**  
> *"In `GitChainAnchor.sol`, we maintain a historical mapping `rootHistory[merkleRoot]`. Before recording any anchor, the contract executes:  
> `require(!rootHistory[_merkleRoot].exists, 'GitChain: Merkle root already anchored');`  
> This ensures that an old, superseded state root cannot be replayed by an adversary to roll back the system to an older version."*

---

### Q13: "What is the time complexity of verifying a leaf in your Merkle Tree?"
> **Winning Answer:**  
> *"The height of a balanced binary Merkle tree with $N$ leaves is $h = \lceil \log_2 N \rceil$.  
> Therefore, generating and verifying an inclusion proof requires exactly $h$ hash operations, giving a strict computational complexity of **$O(\log N)$**."*

---

### Q14: "How does this integrate into real developer workflows without manual intervention?"
> **Winning Answer:**  
> *"We provide two automated integration paths:  
> 1. **Client-side:** A `.git/hooks/pre-push` hook that automatically intercepts any `git push` on developer workstations, scanning for vulnerabilities and preventing compromised code from reaching the remote repository.  
> 2. **Server-side:** A GitHub Actions workflow (`.github/workflows/git-chain-verify.yml`) that automatically triggers on every pull request, executing test suites, computing the Merkle Root, and generating audit reports in the cloud."*

---

### Q15: "What are your project's future enhancements?"
> **Winning Answer:**  
> *"Future enhancements include:  
> 1. Migrating to Layer-2 zk-Rollups (such as Arbitrum or zkSync) to reduce gas anchoring costs by another 95%.  
> 2. Implementing Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge (zk-SNARKs) so developers can cryptographically prove pipeline test passage without disclosing build log outputs to third-party auditors."*
