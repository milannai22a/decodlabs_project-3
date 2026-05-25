[README_project3_phishing_analyzer.md](https://github.com/user-attachments/files/28210395/README_project3_phishing_analyzer.md)
# 🛡️ Phishing Awareness Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Terminal](https://img.shields.io/badge/Runs_In-Terminal-black?style=for-the-badge&logo=gnometerminal)
![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=for-the-badge)
![DecodeLabs](https://img.shields.io/badge/DecodeLabs-Project_3-red?style=for-the-badge)
![Cyber Security](https://img.shields.io/badge/Domain-Cyber_Security-darkred?style=for-the-badge)

A terminal-based **Phishing Awareness Analysis Tool** built entirely with Python's built-in libraries. Analyze emails and messages to detect phishing attempts, identify red flags, flag suspicious links, and make triage decisions — all from the command line.

> **DecodeLabs | Industrial Training Kit | Batch 2026**
> *"The modern cybersecurity perimeter is no longer the network firewall. It is the user."*

---

## 📌 Table of Contents

- [About](#about)
- [Features](#features)
- [Requirements](#requirements)
- [How to Run](#how-to-run)
- [Menu Options](#menu-options)
- [How It Works](#how-it-works)
- [Sample Output](#sample-output)
- [Project Structure](#project-structure)
- [License](#license)

---

## 📖 About

This project is **Project 3** of the DecodeLabs Cyber Security Industrial Training Kit (Batch 2026). The task is to act as a **Cybersecurity Analyst** and build a tool that can:

- Analyze sample emails or messages to identify phishing attempts
- Identify suspicious links and keywords
- List red flags found in phishing messages
- Explain why a message is unsafe

Built with **zero external libraries** — only Python's built-in `re`, `os`, and `time` modules.

---

## ✨ Features

- ✅ **Full Message Analyzer** — Paste any email and get an instant phishing verdict
- ✅ **Risk Score** — 0–100 phishing risk score with Weak / Suspicious / Malicious rating
- ✅ **11 Red Flag Categories** — Urgency, Authority, Fear, Greed, Sensitive requests, and more
- ✅ **Suspicious Link Detection** — Flags HTTP, IP addresses, URL shorteners, typosquatting, bad TLDs
- ✅ **Brand Impersonation Detection** — Checks for PayPal, Amazon, Microsoft, Google, and more
- ✅ **Email Header Analysis** — Detects sender-domain mismatches and display name spoofing
- ✅ **Domain / Link Inspector** — Inspect a URL for subdomain traps, typosquatting, and more
- ✅ **Triage Decision Tree** — Interactive yes/no walkthrough to classify any email
- ✅ **5 Built-in Sample Emails** — Practice on real-world phishing scenarios from the kit
- ✅ **Red Flags Reference Guide** — All 11 red flags with explanations, attack types, and channels
- ✅ **No pip installs** — Runs on any Python 3 installation out of the box

---

## ⚙️ Requirements

- Python 3.x only
- No external packages needed

```bash
python --version
# Should show Python 3.x
```

---

## ▶️ How to Run

1. **Clone or download the repository:**
   ```bash
   git clone https://github.com/milannai22a/Decodlabs_project-3.git
   cd Decodlabs_project-3
   ```

2. **Run the script:**
   ```bash
   python phishing_analyzer.py
   ```

3. **Use the menu** to analyze, practice, or inspect.

---

## 🗂️ Menu Options

| Option | Feature | Description |
|---|---|---|
| `[1]` | Analyze a Message | Paste a real email — get full phishing report |
| `[2]` | Sample Emails | Practice on 5 real-world phishing scenarios |
| `[3]` | Triage Decision Tree | Interactive yes/no checklist for any email |
| `[4]` | Domain Inspector | Inspect any URL for spoofing patterns |
| `[5]` | Red Flags Guide | All 11 red flags with explanations |
| `[0]` | Exit | Exit the tool |

---

## ⚙️ How It Works

The analyzer checks messages across **8 detection categories**:

| Category | What It Checks |
|---|---|
| Urgency Keywords | "Act now", "expires in 24 hours", "immediate action" |
| Authority Keywords | "CEO", "IT department", "HR", "government" |
| Fear Keywords | "suspended", "compromised", "legal action", "locked" |
| Greed Keywords | "you have won", "prize", "claim now", "lottery" |
| Sensitive Requests | "password", "OTP", "credit card", "CVV", "PIN" |
| Suspicious Links | HTTP, IP addresses, URL shorteners, bad TLDs, typosquatting |
| Brand Impersonation | PayPal, Amazon, Microsoft, Google, Apple, SBI, etc. |
| Header Analysis | Sender-domain mismatch, display name spoofing, fake FW: chains |

**Verdict Scale:**

| Score | Verdict |
|---|---|
| 0 – 34 | 🟢 Likely Safe |
| 35 – 69 | 🟡 Suspicious |
| 70 – 100 | 🔴 Malicious |

**Triage Actions (from the DecodeLabs kit):**
- 🟢 Safe → Close
- 🟡 Suspicious → Warn User
- 🔴 Malicious → Block Domain & Escalate

---

## 🖥️ Sample Output

```
════════════════════════════════════════════════════════════
  🛡  DecodeLabs  |  Cyber Security  |  Batch 2026
════════════════════════════════════════════════════════════
       PROJECT 3 : Phishing Awareness Analyzer
════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────
  📊  ANALYSIS RESULTS
────────────────────────────────────────────────────────────

  Verdict  :  🔴 MALICIOUS
  Score    :  85 / 100
  Summary  :  High phishing risk. Do NOT click links or provide info. Report immediately.

  ACTION: Block Domain → Escalate to Security Team → Do NOT delete (preserve evidence)

────────────────────────────────────────────────────────────

  🚩 Total Red Flags Found: 9

  ── Header / Sender Red Flags ──
     ⚠  Display name mismatch: Name looks official but email domain doesn't match

  ── Urgency / Pressure Keywords ──
     ⚠  'urgent' — Creates artificial time pressure
     ⚠  'immediately' — Creates artificial time pressure

  ── Fear / Threat Keywords ──
     ⚠  'suspended' — Exploits fear to bypass logical thinking

  ── Suspicious Link Indicators ──
     🚨  http://bit.ly/paypal-verify-now
          Reason: URL shortener detected
```

---

## 📁 Project Structure

```
Decodlabs_project-3/
│
├── phishing_analyzer.py    # Main Python script — all logic here
└── README.md               # This file
```

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

> Made with ❤️ by [milannai22a](https://github.com/milannai22a) | DecodeLabs Cyber Security — Batch 2026
>
> *"Your journey to becoming a professional security expert begins with the very first Phish you catch today."*
