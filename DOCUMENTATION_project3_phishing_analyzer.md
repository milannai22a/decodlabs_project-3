# 📘 Documentation — Phishing Awareness Analyzer

> **Author:** [milannai22a](https://github.com/milannai22a)
> **Program:** DecodeLabs Industrial Training Kit — Batch 2026
> **Domain:** Cyber Security
> **Project:** Project 3 — Phishing Awareness Analysis
> **Type:** Command-Line Application
> **Language:** Python 3.x (built-in libraries only)

---

## 📋 Table of Contents

1. [Project Overview](#1-project-overview)
2. [Objectives](#2-objectives)
3. [Background — Why Phishing Matters](#3-background--why-phishing-matters)
4. [Technology Used](#4-technology-used)
5. [Project Structure](#5-project-structure)
6. [How to Run](#6-how-to-run)
7. [Program Flow](#7-program-flow)
8. [Module Breakdown](#8-module-breakdown)
9. [Detection Engine — How Analysis Works](#9-detection-engine--how-analysis-works)
10. [Risk Scoring System](#10-risk-scoring-system)
11. [Triage Decision System](#11-triage-decision-system)
12. [Red Flags Reference (All 11)](#12-red-flags-reference-all-11)
13. [Phishing Types Covered](#13-phishing-types-covered)
14. [Attack Channels Covered](#14-attack-channels-covered)
15. [Built-in Libraries Used](#15-built-in-libraries-used)
16. [Sample Terminal Output](#16-sample-terminal-output)
17. [Test Scenarios](#17-test-scenarios)
18. [Known Limitations](#18-known-limitations)
19. [Future Improvements](#19-future-improvements)

---

## 1. Project Overview

The **Phishing Awareness Analyzer** is a terminal-based Python application developed as part of the **DecodeLabs Cyber Security Industrial Training Kit, Batch 2026**. It acts as a digital threat identification system that allows a user to analyze emails or messages and determine whether they are safe, suspicious, or malicious phishing attempts.

The tool covers the full lifecycle of phishing analysis described in the DecodeLabs Project 3 training kit:
- The **Input (The Bait)** — Delivery method and technical disguise
- The **Process (The Psychology)** — Cognitive triggers and red flags
- The **Output (The Defense)** — Triage decisions and actions

Built using **only Python's standard library** — no pip installs required.

---

## 2. Objectives

- Analyze sample emails or messages to identify phishing attempts
- Identify suspicious links and keywords within messages
- List all red flags detected in a phishing message
- Explain specifically why each element makes the message unsafe
- Provide a triage verdict: Safe → Close, Suspicious → Warn, Malicious → Block & Escalate
- Demonstrate threat analysis, cyber attack awareness, and security thinking

---

## 3. Background — Why Phishing Matters

Phishing exploits the gap between technical security controls and human behavior. Key facts from the DecodeLabs training kit:

- **80%** of security breaches involve phishing
- In a controlled red-team simulation, **40% of employees** fell for a simulated phishing campaign
- It takes an average of **82 seconds** from the start of a campaign for an attacker to get their first click
- Technical firewalls cannot compensate for human error — the user IS the perimeter

The modern threat landscape has moved beyond mass spam to highly precise, AI-driven psychological exploits. This tool helps train users to recognize those tactics.

---

## 4. Technology Used

| Item | Detail |
|---|---|
| Language | Python 3.x |
| Interface | Terminal / Command Line |
| Libraries | `re` (regex), `os` (clear screen), `time` (animation) |
| Dependencies | None — no `pip install` required |
| Platform | Windows, macOS, Linux |

---

## 5. Project Structure

```
Decodlabs_project-3/
│
├── phishing_analyzer.py    # Main script — all logic lives here
└── README.md               # Project readme
```

All detection logic, display helpers, sample messages, triage engine, domain inspector, and menus are contained in a single file: `phishing_analyzer.py`.

---

## 6. How to Run

### Step 1 — Verify Python is installed
```bash
python --version
# Python 3.x required
```

### Step 2 — Clone the repository
```bash
git clone https://github.com/milannai22a/Decodlabs_project-3.git
cd Decodlabs_project-3
```

### Step 3 — Run the script
```bash
python phishing_analyzer.py
```

### Step 4 — Use the interactive menu
```
  [1]  Analyze a Message / Email
  [2]  Practice with Sample Phishing Emails
  [3]  Interactive Triage Decision Tree
  [4]  Domain / Link Inspector
  [5]  Red Flags Reference Guide
  [0]  Exit
```

---

## 7. Program Flow

```
START
  │
  ▼
Display Banner + Main Menu
  │
  ├─[1]─ Get Sender, Subject, Body from user input
  │         │
  │         ▼
  │       Run analyze_message(sender, subject, body)
  │         │
  │         ▼
  │       Run 8 detection checks → calculate score → verdict
  │         │
  │         ▼
  │       Display full red flag report + triage action
  │
  ├─[2]─ Show 5 sample phishing emails
  │         │
  │         ▼
  │       User selects one → auto-run analysis → display results
  │
  ├─[3]─ Triage Decision Tree
  │         │
  │         ▼
  │       10 yes/no questions → score → verdict + action
  │
  ├─[4]─ Domain Inspector
  │         │
  │         ▼
  │       User enters URL → check for HTTP, IP, shorteners,
  │       typosquatting, subdomain traps, TLD abuse
  │
  ├─[5]─ Red Flags Guide
  │         │
  │         ▼
  │       Display all 11 red flags + phishing types + channels
  │
  └─[0]─ Exit
```

---

## 8. Module Breakdown

| Function | Purpose |
|---|---|
| `analyze_message()` | Main orchestrator — runs all 8 checks, calculates score, returns full results |
| `check_keywords()` | Scans text for a given list of keywords, returns all matches |
| `find_urls()` | Extracts all URLs from text using regex |
| `check_suspicious_links()` | Tests extracted URLs against suspicious patterns |
| `check_brand_impersonation()` | Checks if well-known brands are mentioned (potential spoofing) |
| `check_email_header()` | Analyses sender address and subject for display name mismatch, free domains, ALL CAPS, FW: |
| `calculate_risk_score()` | Weighted scoring across all 8 categories, capped at 100 |
| `get_verdict()` | Maps score to Safe / Suspicious / Malicious label + explanation |
| `triage_action()` | Returns the correct action based on verdict |
| `run_triage()` | Interactive yes/no decision tree, 10 questions |
| `check_domain_spoof()` | Deep-inspects a single URL for all domain manipulation tactics |
| `run_sample_analysis()` | Loads pre-built phishing email samples for practice |
| `show_red_flags_guide()` | Displays all 11 red flags and attack channel reference |
| `display_results()` | Formats and prints the full analysis report to the terminal |

---

## 9. Detection Engine — How Analysis Works

The analyzer checks a message across **8 detection categories**:

### Category 1: Urgency Keywords
Psychological pressure tactics that force fast decisions.
```
"urgent", "act now", "expires in", "within 24 hours",
"immediately", "action required", "click now", "last warning"
```

### Category 2: Authority Keywords
Impersonating trusted figures to demand compliance without question.
```
"ceo", "it department", "hr department", "administrator",
"government", "bank", "security team", "legal department"
```

### Category 3: Fear Keywords
Threats designed to trigger a fight-or-flight response.
```
"suspended", "compromised", "unauthorized access",
"legal action", "account closed", "security breach", "hacked"
```

### Category 4: Greed Keywords
Promises of unearned rewards to lower the victim's guard.
```
"you have won", "prize", "lottery", "claim now",
"cash prize", "unclaimed funds", "lucky winner"
```

### Category 5: Sensitive Information Requests
Direct asks for credentials or financial data.
```
"password", "pin", "otp", "credit card", "cvv",
"bank account", "security question", "billing information"
```

### Category 6: Suspicious Link Patterns
URLs are scanned with regex against:
- HTTP (non-HTTPS) connections
- URL shorteners (bit.ly, tinyurl, goo.gl)
- Raw IP addresses (e.g. `http://192.168.1.1`)
- @ symbol in URL (browser ignores everything before @)
- Suspicious TLDs (.xyz, .tk, .ml, .ga)
- Typosquatting patterns (paypa1, amaz0n, micros0ft)
- Subdomain traps (secure-login.com appearing as subdomain)

### Category 7: Brand Impersonation
Checks for 20+ brand names including PayPal, Amazon, Microsoft, Google, Apple, Netflix, Facebook, SBI, HDFC, ICICI, and more.

### Category 8: Email Header Analysis
- Free email domain (gmail/yahoo) used for official-looking sender
- Display name vs actual email domain mismatch
- ALL CAPS subject lines (pressure tactic)
- FW:/FWD: fake forwarded chain in subject

---

## 10. Risk Scoring System

Each category contributes a weighted maximum to the total score (capped at 100):

| Category | Points Per Match | Max Contribution |
|---|---|---|
| Urgency Keywords | 10 each | 20 |
| Authority Keywords | 8 each | 16 |
| Fear Keywords | 10 each | 20 |
| Greed Keywords | 8 each | 16 |
| Sensitive Requests | 12 each | 24 |
| Suspicious Links | 15 each | 30 |
| Brand Impersonation | 10 each | 20 |
| Header Red Flags | 8 each | 16 |

**Verdict Scale:**

| Score Range | Verdict | Triage Action |
|---|---|---|
| 0 – 34 | 🟢 Likely Safe | Close — no action needed |
| 35 – 69 | 🟡 Suspicious | Warn User — verify via phone |
| 70 – 100 | 🔴 Malicious | Block Domain & Escalate |

---

## 11. Triage Decision System

The interactive triage walks through **10 yes/no questions** derived directly from the DecodeLabs training kit:

1. Does the sender domain match the brand it claims to be from?
2. Does the email ask you to click a link or open an attachment?
3. Does the subject use URGENT / ACTION REQUIRED / WARNING?
4. Does it ask for password, OTP, credit card, or personal details?
5. Does it demand secrecy or bypass of normal procedures?
6. Is the sender using a free email domain (gmail, yahoo) for official use?
7. Are there spelling mistakes or odd writing style?
8. Does hovering/inspecting a link show a different domain?
9. Did the email arrive unexpectedly with no prior context?
10. Does it promise rewards or money you weren't expecting?

Each "risky" answer adds 10 points to the triage score → same verdict scale applies.

**The Golden Rule: Pause → Verify → Report**
- **Pause** — Recognize the cognitive trigger (Urgency/Fear/Authority). Apply the Five-Minute Rule.
- **Verify** — Confirm via a secondary, out-of-band channel (call the sender on a known number).
- **Report** — Use internal reporting. Do not just delete — reporting lets security purge it from all inboxes.

---

## 12. Red Flags Reference (All 11)

| # | Red Flag | Description |
|---|---|---|
| 1 | Sender-Domain Mismatch | Display name looks official but actual email domain doesn't match |
| 2 | Fake Forwarded Chains | FW: threads with pasted headers and odd timestamps |
| 3 | Browser-in-the-Browser (BitB) | Fake SSO pop-ups that can't be dragged outside the browser |
| 4 | Dangerous Attachments | Uncommon extensions (.iso, .js, .scr) or HTML smuggling |
| 5 | Urgent Bypass Requests | Demands to bypass normal procurement/security procedures |
| 6 | Requests for Sensitive Info | Unexpected prompts for MFA codes, passwords, payment details |
| 7 | Activity Alerts | Alarmist sign-in warnings pointing directly to a login page |
| 8 | MFA Fatigue | Multiple unprompted authenticator push notifications |
| 9 | Security Callback Scams (TOAD) | Email with only a phone number urging a call for a fake charge |
| 10 | QR Code Prompts | Unsolicited QR codes demanding a scan to secure your account |
| 11 | Deepfake Live-Meeting Fraud | Audio/video impersonation during a call demanding payment changes |

---

## 13. Phishing Types Covered

| Type | Description |
|---|---|
| **Mass Phishing** | Generic lures mimicking ubiquitous brands (Amazon, PayPal). High volume, ~1% engagement. |
| **Spear Phishing** | Contextual precision using OSINT (LinkedIn) to reference project names and colleagues. |
| **Whaling** | Targeting C-Suite executives for high-value wire transfers or M&A documents. |
| **BEC (Business Email Compromise)** | Impersonating executives to request urgent wire transfers. |

---

## 14. Attack Channels Covered

| Channel | How It Works |
|---|---|
| **Email** | Classic phishing via inbox — most common vector |
| **Smishing** | Malicious links via SMS disguised as package deliveries or bank alerts |
| **Vishing** | Live calls using caller ID spoofing to impersonate IT support or government |
| **Quishing** | Malicious QR codes on physical posters or digital PDFs — bypasses URL filters |
| **SEO Poisoning** | Malicious lookalike websites ranked above legitimate login portals |

---

## 15. Built-in Libraries Used

| Library | Why Used |
|---|---|
| `re` | Regular expressions for URL extraction and pattern matching |
| `os` | `os.system()` to clear the terminal screen cross-platform |
| `time` | `time.sleep()` for brief analysis animation delay |

No external packages required. Works on any Python 3 installation.

---

## 16. Sample Terminal Output

```
════════════════════════════════════════════════════════════
  🛡  DecodeLabs  |  Cyber Security  |  Batch 2026
════════════════════════════════════════════════════════════
       PROJECT 3 : Phishing Awareness Analyzer
════════════════════════════════════════════════════════════

  MAIN MENU

  [1]  Analyze a Message / Email
  [2]  Practice with Sample Phishing Emails
  [3]  Interactive Triage Decision Tree
  [4]  Domain / Link Inspector
  [5]  Red Flags Reference Guide
  [0]  Exit

────────────────────────────────────────────────────────────
  📊  ANALYSIS RESULTS
────────────────────────────────────────────────────────────

  Verdict  :  🔴 MALICIOUS
  Score    :  85 / 100
  Summary  :  High phishing risk. Do NOT click or provide info.

  ACTION: Block Domain → Escalate to Security Team

  🚩 Total Red Flags Found: 9

  ── Header / Sender Red Flags ──
     ⚠  Display name mismatch detected

  ── Urgency Keywords ──
     ⚠  'urgent' — Creates artificial time pressure
     ⚠  'immediately' — Creates artificial time pressure

  ── Fear Keywords ──
     ⚠  'suspended' — Exploits fear

  ── Sensitive Information Requests ──
     ⚠  'password' — Requesting confidential data

  ── Suspicious Link Indicators ──
     🚨  http://bit.ly/paypal-verify-now
          Reason: URL shortener — real destination hidden

  💡 GOLDEN RULE: Pause → Verify → Report
```

---

## 17. Test Scenarios

5 built-in sample emails are included for practice:

| # | Scenario | Type | Expected Verdict |
|---|---|---|---|
| 1 | CEO Wire Transfer (Lost Wallet) | BEC / Whaling | 🔴 Malicious |
| 2 | PayPal Account Suspended | Mass Phishing | 🔴 Malicious |
| 3 | IT Dept Password Expiry | Spear Phishing | 🔴 Malicious |
| 4 | Amazon Prize Winner | Greed Scam | 🔴 Malicious |
| 5 | Q3 Project Update from Sarah | Legitimate Email | 🟢 Likely Safe |

---

## 18. Known Limitations

- Does not perform live DNS lookups or WHOIS queries (no network access)
- Cannot inspect actual email headers from .eml files (text input only)
- Keyword matching is case-insensitive string search — not semantic NLP
- Domain spoofing detection works on text patterns, not live certificate checks
- Does not store or log analysis results to a file

---

## 19. Future Improvements

- Export analysis report to a `.txt` or `.json` file
- Add a batch mode to analyze multiple messages from a `.txt` file
- Integrate with Python's `email` module to parse real `.eml` files
- Add entropy-based URL analysis for obfuscated links
- Detect homoglyph / Unicode character substitution in domain names
- Add color output using the built-in `curses` module or ANSI codes
- Track and display historical analysis session stats

---

*Documentation last updated: May 2026*
*DecodeLabs | Cyber Security Industrial Training | Batch 2026*
