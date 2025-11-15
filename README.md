# **How to Teach Python to Read Solidity Code: Feature Engineering for Blockchain Security**

Smart contract security has become one of the most critical problems in modern computing. Billions of dollars now flow through decentralized applications, yet the average Solidity contract is still handwritten, under-reviewed, and often deployed without meaningful automated analysis.

Static analyzers exist, Slither, Mythril, Scribble, but they are massive, complex systems built by security professionals. What if you want something simpler? Something you can understand, modify, and extend yourself? Something you can integrate into custom pipelines or research experiments?

In this article, we build exactly that:
**a Python-based feature extraction system that reads Solidity code and transforms it into structured security signals.**

This is not about building a full auditor. Instead, it’s about understanding **how Python can learn to “read” Solidity**, identify risky patterns, and produce features that can power heuristic scoring or machine learning.

---

# Why Feature Engineering Matters in Smart Contract Security

Before you can detect vulnerabilities, classify risky code, or train an AI model to audit contracts, you need one thing:

**Signal.**

Classic vulnerabilities such as reentrancy, oracle manipulation, delegatecall misuse, and access-control bugs leave detectable fingerprints in code. These fingerprints become **features**.

Examples:

| Vulnerability           | Possible Feature                                                  |
| ----------------------- | ----------------------------------------------------------------- |
| Reentrancy              | Presence of `call{value:}` or external calls before state updates |
| Access control bug      | Setter functions lacking `require(msg.sender == owner)`           |
| Oracle manipulation     | Public state mutation without checks                              |
| Delegatecall injection  | Literal use of `delegatecall` or proxy patterns                   |
| Expanded attack surface | High count of `public` / `payable` functions                      |
| Gas griefing            | Loops over dynamic arrays / mappings                              |

Most real auditors use mental models:

> “This contract uses delegatecall. That’s dangerous unless this is a proxy.”
> “This function writes to storage but is publicly accessible.”

We can encode these intuitions into Python.

---

# Step 1: Reading Solidity Code With Python

The simplest possible interpreter for Solidity is just:

```python
from pathlib import Path

def read_source(path):
    return Path(path).read_text(encoding="utf-8")
```

But this raw text means nothing yet.
We need to transform it into *features*.

---

# Step 2: Extracting Low-Level Features (Regex Signals)

Regex is surprisingly effective for identifying dangerous low-level constructs.
Each of these is a security smell:

### **Dangerous Opcodes**

* `delegatecall`
* `call.value`
* `tx.origin`
* `selfdestruct`

### **Attack-Surface Indicators**

* number of `payable` functions
* number of `public` functions
* number of lines (complexity proxy)

Let’s build a feature extractor:

```python
import re
import hashlib
from pathlib import Path

RISKY_KEYWORDS = [
    "delegatecall",
    "call.value",
    "tx.origin",
    "selfdestruct",
    "block.timestamp",
]

def extract_features_from_text(source: str):
    lines = source.splitlines()
    n_lines = len(lines)

    n_payable = len(re.findall(r"\bpayable\b", source))
    n_public = len(re.findall(r"\bpublic\b", source))

    features = {
        "n_lines": n_lines,
        "n_payable": n_payable,
        "n_public": n_public,
    }

    for kw in RISKY_KEYWORDS:
        features[f"has_{kw.replace('.', '_')}"] = 1 if kw in source else 0

    return features
```

This already detects:

* large contracts
* payable-heavy contracts
* `delegatecall` → proxy or exploit
* `tx.origin` → broken access control
* value transfer patterns

You’re now performing the same early-stage static analysis as many formal tools.

---

# Step 3: Turning Features Into Risk Scores

Instead of immediately applying machine learning, we start with a heuristic scoring engine that mirrors how human auditors think.

Example scoring logic:

```python
def compute_risk(features):
    score = 0

    if features["has_delegatecall"]:
        score += 50
    if features["has_tx_origin"]:
        score += 40
    if features["has_call_value"]:
        score += 30

    if features["n_payable"] > 3:
        score += 25
    elif features["n_payable"] > 0:
        score += 5

    if features["n_lines"] > 300:
        score += 15
    elif features["n_lines"] > 100:
        score += 5

    score = min(100, score)

    if score <= 20:
        level = "Low"
    elif score <= 60:
        level = "Medium"
    else:
        level = "High"

    return score, level
```

This allows Python to:

* identify highly dangerous contracts
* classify contracts into risk buckets
* detect unsafe code without running it

---

# Step 4: Extracting Traceability via Source Hashing

Each contract is hashed:

```python
def hash_source(source):
    return hashlib.sha256(source.encode()).hexdigest()
```

This gives you a **unique fingerprint** for each Solidity file.
It allows:

* caching analyses
* tracking versions
* linking risk results to a specific source
* storing assessments in a database or blockchain

---

# Step 5: Running the Analyzer (CLI)

A final CLI glues everything together:

```bash
python src/cli.py --file data/examples/high_risk_delegatecall.sol
```

Produces:

```json
{
  "source_hash": "…",
  "features": { … },
  "risk_score": 90,
  "risk_level": "High"
}
```

This is a complete static-analysis pipeline.

---

# Step 6: The Fun Part, Testing Real Vulnerable Contracts

Feed Python various Solidity snippets and watch the signals react.

## Delegatecall Vulnerability

```solidity
target.delegatecall(data);
```

Python flags:

```
has_delegatecall = 1
```

Risk score spikes.

---

## Broken Access Control

```solidity
require(tx.origin == owner);
```

Python flags:

```
has_tx_origin = 1
```

Immediate medium/high risk.

---

## Reentrancy Pattern

```solidity
(bool ok, ) = msg.sender.call{value: amount}("");
```

Regex doesn’t catch this yet, so we extend the pattern:

```python
if "call{value:" in source.replace(" ", ""):
    features["has_reentrancy_pattern"] = 1
```

Python now detects reentrancy fingerprints.

---

# Step 7: Toward Machine Learning

Once you extract features, the next step is obvious:

### Train a model.

1. Build a dataset:

   * Label each `.sol` file as low/medium/high risk
   * Extract features programmatically
2. Train:

   ```python
   RandomForestClassifier().fit(X, y)
   ```
3. Predict risk automatically.

This turns Python into an AI-powered lightweight auditor.

---

# Step 8: Toward Full AST Parsing (Advanced)

Regex = fast and simple
AST = accurate and powerful

Future upgrades:

* Use **Slither** programmatically
* Use **solidity-parser-antlr** for Python
* Extract:

  * function graph
  * call graph
  * state mutation patterns
  * protected/unprotected setters
  * role-based access control detection

This is how professional auditing tools work internally.

---

# Final Thoughts

Teaching Python to “read” Solidity is easier than you think, but more powerful than it appears. With just:

* raw text
* some regex
* simple heuristics
* proper feature engineering

you can build a functioning static analyzer capable of flagging dangerous patterns before deployment.

This project is the perfect foundation for:

* blockchain ML research
* educational security tooling
* automated CI security pipelines
* smart contract QA systems
* future open-source security tools

Python doesn’t just read Solidity,
**it learns to understand it.**
