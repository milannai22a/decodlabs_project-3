"""
=============================================================
  DecodeLabs - Cyber Security Project 3
  Phishing Awareness Analysis Tool
  Batch: 2026 | Powered by DecodeLabs
=============================================================
  A terminal-based tool to analyze emails/messages
  and identify phishing attempts, red flags,
  suspicious links, and keywords.
=============================================================
"""

import re
import os
import time


# ─────────────────────────────────────────────
#  DISPLAY HELPERS
# ─────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def divider(char="─", length=60):
    print(char * length)


def banner():
    clear()
    divider("═")
    print("  🛡  DecodeLabs  |  Cyber Security  |  Batch 2026")
    divider("═")
    print("       PROJECT 3 : Phishing Awareness Analyzer")
    divider("─")
    print("  Analyze emails/messages for phishing indicators,")
    print("  red flags, suspicious links & unsafe keywords.")
    divider("═")
    print()


def section(title):
    print()
    divider()
    print(f"  {title}")
    divider()


def pause():
    input("\n  Press ENTER to continue...")


# ─────────────────────────────────────────────
#  PHISHING DETECTION DATA
# ─────────────────────────────────────────────

# Urgency / psychological trigger keywords
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "account suspended",
    "verify now", "limited time", "expires in", "action required",
    "your account will be", "within 24 hours", "click now",
    "respond immediately", "last warning", "final notice",
    "don't delay", "today only", "time sensitive"
]

# Authority / impersonation keywords
AUTHORITY_KEYWORDS = [
    "ceo", "it department", "helpdesk", "hr department",
    "payroll", "management", "administrator", "support team",
    "official notice", "government", "irs", "bank", "security team",
    "customer service", "compliance team", "legal department"
]

# Fear / threat keywords
FEAR_KEYWORDS = [
    "suspended", "terminated", "illegal activity", "unauthorized access",
    "locked", "compromised", "hacked", "fraud detected",
    "legal action", "lawsuit", "arrested", "penalty",
    "account closed", "virus detected", "security breach"
]

# Greed / reward keywords
GREED_KEYWORDS = [
    "you have won", "congratulations", "prize", "reward",
    "free gift", "claim now", "lottery", "winner",
    "unclaimed funds", "inheritance", "exclusive offer",
    "selected for", "lucky winner", "cash prize"
]

# Sensitive data request keywords
SENSITIVE_KEYWORDS = [
    "password", "pin", "social security", "credit card",
    "bank account", "otp", "one time password", "cvv",
    "date of birth", "mother's maiden", "security question",
    "confirm your identity", "verify your details",
    "update your payment", "billing information"
]

# Suspicious link / domain patterns
SUSPICIOUS_LINK_PATTERNS = [
    r"http://",                        # HTTP instead of HTTPS
    r"bit\.ly", r"tinyurl", r"goo\.gl",  # URL shorteners
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Raw IP address
    r"@",                              # @ in URL (subdomain trick)
    r"secure.*login", r"login.*secure",
    r"verify.*account", r"account.*verify",
    r"update.*billing", r"billing.*update",
    r"\.xyz", r"\.tk", r"\.ml", r"\.ga",  # Suspicious TLDs
    r"paypa1", r"amaz0n", r"micros0ft",  # Typosquatting
    r"support.*-.*login", r"login.*-.*support",
]

# Common brand impersonation targets
BRAND_IMPERSONATION = [
    "paypal", "amazon", "microsoft", "google", "apple",
    "netflix", "facebook", "instagram", "whatsapp", "twitter",
    "linkedin", "dropbox", "zoom", "github", "chatgpt",
    "hdfc", "sbi", "icici", "axis bank", "ubi"
]


# ─────────────────────────────────────────────
#  ANALYSIS ENGINE
# ─────────────────────────────────────────────

def find_urls(text):
    """Extract all URLs from the message text."""
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(url_pattern, text, re.IGNORECASE)


def check_keywords(text, keyword_list):
    """Return all matching keywords from a given category list."""
    text_lower = text.lower()
    found = []
    for kw in keyword_list:
        if kw.lower() in text_lower:
            found.append(kw)
    return found


def check_suspicious_links(text):
    """Check extracted URLs against suspicious patterns."""
    urls = find_urls(text)
    flagged = []
    for url in urls:
        for pattern in SUSPICIOUS_LINK_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                flagged.append((url, pattern))
                break
    return urls, flagged


def check_brand_impersonation(text):
    """Check if any well-known brand names are mentioned."""
    text_lower = text.lower()
    found = []
    for brand in BRAND_IMPERSONATION:
        if brand in text_lower:
            found.append(brand)
    return found


def check_email_header(sender, subject):
    """Analyze sender address and subject line for red flags."""
    red_flags = []

    # Check sender domain vs display name
    if sender:
        # Suspicious free email domains pretending to be official
        free_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
        for domain in free_domains:
            if domain in sender.lower():
                red_flags.append(
                    f"Official-looking sender using free email domain: {domain}"
                )
                break

        # Check for display name mismatch pattern
        if "<" in sender and ">" in sender:
            display = sender[:sender.index("<")].strip().lower()
            email_part = sender[sender.index("<")+1:sender.index(">")].lower()
            if any(brand in display for brand in BRAND_IMPERSONATION):
                if not any(brand in email_part for brand in BRAND_IMPERSONATION):
                    red_flags.append(
                        f"Display name mismatch: Name looks official but email domain doesn't match"
                    )

    # Check subject for red flags
    if subject:
        subj_lower = subject.lower()
        if any(kw in subj_lower for kw in ["urgent", "action required", "verify", "suspended", "warning"]):
            red_flags.append("Subject line uses urgency/fear language")
        if subject.upper() == subject and len(subject) > 5:
            red_flags.append("Subject line is in ALL CAPS (pressure tactic)")
        if "fw:" in subj_lower or "fwd:" in subj_lower:
            red_flags.append("Fake forwarded chain detected in subject (FW:/FWD:)")

    return red_flags


def calculate_risk_score(results):
    """
    Calculate a phishing risk score from 0–100.
    Each category contributes weighted points.
    """
    score = 0

    score += min(len(results["urgency"]) * 10, 20)
    score += min(len(results["authority"]) * 8, 16)
    score += min(len(results["fear"]) * 10, 20)
    score += min(len(results["greed"]) * 8, 16)
    score += min(len(results["sensitive"]) * 12, 24)
    score += min(len(results["flagged_links"]) * 15, 30)
    score += min(len(results["impersonated_brands"]) * 10, 20)
    score += min(len(results["header_flags"]) * 8, 16)

    return min(score, 100)


def get_verdict(score):
    """Return verdict label and explanation based on score."""
    if score >= 70:
        return "🔴 MALICIOUS", "High phishing risk. Do NOT click links or provide info. Report immediately."
    elif score >= 35:
        return "🟡 SUSPICIOUS", "Moderate risk detected. Verify through official channels before acting."
    else:
        return "🟢 LIKELY SAFE", "Low phishing indicators. Always stay cautious."


def triage_action(verdict_label):
    """Return the triage action based on verdict."""
    if "MALICIOUS" in verdict_label:
        return "ACTION: Block Domain → Escalate to Security Team → Do NOT delete (preserve evidence)"
    elif "SUSPICIOUS" in verdict_label:
        return "ACTION: Warn User → Verify via out-of-band channel (call the sender directly)"
    else:
        return "ACTION: Close → No action needed. Continue monitoring."


def analyze_message(sender, subject, body):
    """Run full phishing analysis on the provided message."""

    full_text = f"{sender} {subject} {body}"

    results = {}
    results["urgency"]            = check_keywords(full_text, URGENCY_KEYWORDS)
    results["authority"]          = check_keywords(full_text, AUTHORITY_KEYWORDS)
    results["fear"]               = check_keywords(full_text, FEAR_KEYWORDS)
    results["greed"]              = check_keywords(full_text, GREED_KEYWORDS)
    results["sensitive"]          = check_keywords(full_text, SENSITIVE_KEYWORDS)
    results["all_urls"], results["flagged_links"] = check_suspicious_links(full_text)
    results["impersonated_brands"]= check_brand_impersonation(full_text)
    results["header_flags"]       = check_email_header(sender, subject)

    score = calculate_risk_score(results)
    verdict, explanation = get_verdict(score)
    action = triage_action(verdict)

    results["score"]       = score
    results["verdict"]     = verdict
    results["explanation"] = explanation
    results["action"]      = action

    return results


# ─────────────────────────────────────────────
#  DISPLAY RESULTS
# ─────────────────────────────────────────────

def display_results(results, sender, subject):

    section("📊  ANALYSIS RESULTS")

    # ── VERDICT ──
    print(f"\n  Verdict  :  {results['verdict']}")
    print(f"  Score    :  {results['score']} / 100")
    print(f"  Summary  :  {results['explanation']}")
    print(f"\n  {results['action']}")

    divider()

    # ── RED FLAGS FOUND ──
    total_flags = (
        len(results["urgency"]) +
        len(results["fear"]) +
        len(results["authority"]) +
        len(results["greed"]) +
        len(results["sensitive"]) +
        len(results["flagged_links"]) +
        len(results["header_flags"])
    )

    print(f"\n  🚩 Total Red Flags Found: {total_flags}")

    if results["header_flags"]:
        print("\n  ── Header / Sender Red Flags ──")
        for flag in results["header_flags"]:
            print(f"     ⚠  {flag}")

    if results["urgency"]:
        print("\n  ── Urgency / Pressure Keywords ──")
        for kw in results["urgency"]:
            print(f"     ⚠  '{kw}' — Creates artificial time pressure")

    if results["fear"]:
        print("\n  ── Fear / Threat Keywords ──")
        for kw in results["fear"]:
            print(f"     ⚠  '{kw}' — Exploits fear to bypass logical thinking")

    if results["authority"]:
        print("\n  ── Authority / Impersonation Keywords ──")
        for kw in results["authority"]:
            print(f"     ⚠  '{kw}' — Impersonates trusted authority figure")

    if results["greed"]:
        print("\n  ── Greed / Reward Keywords ──")
        for kw in results["greed"]:
            print(f"     ⚠  '{kw}' — Promises unearned rewards")

    if results["sensitive"]:
        print("\n  ── Sensitive Information Requests ──")
        for kw in results["sensitive"]:
            print(f"     ⚠  '{kw}' — Requesting confidential data")

    # ── LINKS ──
    if results["all_urls"]:
        print(f"\n  ── URLs Found ({len(results['all_urls'])}) ──")
        for url in results["all_urls"]:
            print(f"     🔗  {url}")

    if results["flagged_links"]:
        print(f"\n  ── Suspicious Link Indicators ({len(results['flagged_links'])}) ──")
        for url, reason in results["flagged_links"]:
            print(f"     🚨  {url}")
            print(f"          Reason: matches suspicious pattern → {reason}")

    # ── BRAND IMPERSONATION ──
    if results["impersonated_brands"]:
        print("\n  ── Brand Impersonation Detected ──")
        for brand in results["impersonated_brands"]:
            print(f"     🎭  '{brand.title()}' — May be spoofed to appear legitimate")

    if total_flags == 0 and not results["flagged_links"]:
        print("\n  ✅  No significant phishing indicators detected in this message.")

    divider()

    # ── GOLDEN RULE REMINDER ──
    print("\n  💡 GOLDEN RULE: Pause → Verify → Report")
    print("     Recognize the trigger (Urgency/Fear/Authority)")
    print("     Verify via a second channel (call the sender directly)")
    print("     Report — do not just delete the message")

    divider()


# ─────────────────────────────────────────────
#  INPUT COLLECTION
# ─────────────────────────────────────────────

def get_multiline_input(prompt):
    """
    Collect multiline input from the user.
    User types their message and enters a blank line to finish.
    """
    print(f"\n  {prompt}")
    print("  (Press ENTER on a blank line when done)")
    print()
    lines = []
    while True:
        line = input("  > ")
        if line.strip() == "":
            break
        lines.append(line)
    return "\n".join(lines)


def get_message_input():
    """Collect sender, subject and body from the user."""

    section("📨  ENTER THE SUSPICIOUS MESSAGE / EMAIL")

    print()
    sender  = input("  Sender / From (e.g. CEO Name <hacker@gmail.com>): ").strip()
    subject = input("  Subject Line                                     : ").strip()
    body    = get_multiline_input("Paste the message body below:")

    return sender, subject, body


# ─────────────────────────────────────────────
#  SAMPLE PHISHING MESSAGES (for demo/practice)
# ─────────────────────────────────────────────

SAMPLE_MESSAGES = [
    {
        "name": "BEC – Lost Wallet (CEO Wire Transfer)",
        "sender": "CEO Name <ceo.urgent@executive-update.com>",
        "subject": "IMMEDIATE ACTION REQUIRED: Transfer Authorization",
        "body": (
            "URGENT: Process the attached wire transfer instruction immediately. "
            "I lost my wallet at the airport. Need you to wire transfer funds for "
            "my flight before close of business today. This is critical and must "
            "remain STRICTLY CONFIDENTIAL. Do not discuss with anyone. "
            "Bypass standard procedure. Thank you."
        )
    },
    {
        "name": "Mass Phishing – PayPal Account Suspended",
        "sender": "PayPal Support <support@paypa1-secure.com>",
        "subject": "Urgent: Your Account Has Been Suspended",
        "body": (
            "Dear Customer, your PayPal account has been suspended due to "
            "unauthorized access. Verify your identity immediately to avoid "
            "permanent termination. Click here to confirm your details and "
            "update your password and credit card information: "
            "http://bit.ly/paypal-verify-now. Act now — account will be closed "
            "within 24 hours."
        )
    },
    {
        "name": "IT Department – Fake Password Reset",
        "sender": "IT Security <itsupport@logins-updates.com>",
        "subject": "FW: Urgent: Your Account Security Alert",
        "body": (
            "Dear Employee, your Microsoft 365 password expires in 24 hours. "
            "You must click the link below to reset your password immediately or "
            "you will be locked out of all company systems. "
            "Visit: http://microsoft-password-reset.login-update.com "
            "Enter your current password, OTP, and employee ID to verify your identity."
        )
    },
    {
        "name": "Prize Scam – Lucky Winner",
        "sender": "Amazon Rewards <winner@amaz0n-prize.xyz>",
        "subject": "Congratulations! You Have Won an Amazon Gift Card",
        "body": (
            "Congratulations! You have been selected as our lucky winner this month. "
            "You have won a $500 Amazon gift card. Claim your prize now before it expires. "
            "This is a limited time offer. Click here to claim: http://amaz0n-rewards.tk/claim "
            "Please provide your date of birth, credit card number, and CVV to verify "
            "your identity and process your reward."
        )
    },
    {
        "name": "Legitimate Email – Project Update (Safe)",
        "sender": "Sarah Lee <sarah.lee@company.com>",
        "subject": "Q3 Project Status Update – Non-Urgent",
        "body": (
            "Hi Team, please review the attached project status for Q3 at your "
            "earliest convenience. No immediate action is required. "
            "The document is available on our internal SharePoint. Thanks, Sarah."
        )
    }
]


def run_sample_analysis():
    """Let the user pick and analyze a pre-loaded sample phishing message."""

    section("🧪  SAMPLE MESSAGES — PRACTICE ANALYSIS")
    print()
    for i, sample in enumerate(SAMPLE_MESSAGES, 1):
        print(f"  [{i}] {sample['name']}")
    print(f"  [0] Back to Main Menu")
    print()

    choice = input("  Select a sample (0–5): ").strip()

    if choice == "0":
        return

    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(SAMPLE_MESSAGES):
        print("\n  Invalid choice.")
        pause()
        return

    sample = SAMPLE_MESSAGES[int(choice) - 1]

    section(f"📧  ANALYZING: {sample['name']}")
    print(f"\n  Sender  : {sample['sender']}")
    print(f"  Subject : {sample['subject']}")
    print(f"  Body    :\n")
    for line in sample["body"].split(". "):
        print(f"    {line.strip()}.")
    print()

    print("  Analyzing...")
    time.sleep(1)

    results = analyze_message(sample["sender"], sample["subject"], sample["body"])
    display_results(results, sample["sender"], sample["subject"])
    pause()


# ─────────────────────────────────────────────
#  RED FLAGS REFERENCE GUIDE
# ─────────────────────────────────────────────

def show_red_flags_guide():
    """Display the full red flags reference based on the DecodeLabs PDF."""

    section("🚩  RED FLAGS REFERENCE GUIDE")

    flags = [
        ("1",  "Sender-Domain Mismatch",
         "Display name looks official but the actual email domain doesn't match."),
        ("2",  "Fake Forwarded Chains",
         "FW: threads with pasted headers and odd timestamps of conversations you never joined."),
        ("3",  "Browser-in-the-Browser (BitB)",
         "Fake SSO pop-ups that cannot be dragged outside the main browser window."),
        ("4",  "Dangerous Attachments",
         "Uncommon extensions (.iso, .js, .scr) or HTML smuggling links as fake documents."),
        ("5",  "Urgent Bypass Requests",
         "Demands for secrecy or instructions to bypass normal procurement/security procedures."),
        ("6",  "Requests for Sensitive Info",
         "Unexpected prompts for MFA codes, passwords, or payment details over email."),
        ("7",  "Activity Alerts",
         "Alarmist sign-in warnings pointing to a login page instead of advising manual navigation."),
        ("8",  "MFA Fatigue",
         "Multiple unprompted authenticator push notifications designed to wear you down."),
        ("9",  "Security Callback Scams (TOAD)",
         "Emails with only a phone number urging you to call Support for a fake subscription charge."),
        ("10", "QR Code Prompts",
         "Unsolicited QR codes demanding a scan to secure your account — bypasses URL filters."),
        ("11", "Deepfake Live-Meeting Fraud",
         "Audio/video impersonation of an executive during a call demanding vendor payment changes."),
    ]

    print()
    for num, title, desc in flags:
        print(f"  Red Flag #{num}: {title}")
        print(f"  → {desc}")
        print()

    divider()
    print("\n  📌 PHISHING TYPES:")
    print("  Mass Phishing  — Generic lures (Amazon, PayPal). High volume, ~1% engagement.")
    print("  Spear Phishing — Contextual precision using OSINT (LinkedIn, internal jargon).")
    print("  Whaling        — Targeting C-Suite executives for wire transfers or M&A data.")
    print()
    print("  📌 ATTACK CHANNELS:")
    print("  Smishing   — Malicious links via SMS disguised as bank alerts or deliveries.")
    print("  Vishing    — Live calls with caller ID spoofing to impersonate IT/government.")
    print("  Quishing   — Malicious QR codes on posters or PDFs bypassing URL filters.")
    print("  SEO Poison — Search results manipulated to show malicious lookalike sites.")

    divider()
    pause()


# ─────────────────────────────────────────────
#  DOMAIN SPOOF CHECKER
# ─────────────────────────────────────────────

def check_domain_spoof():
    """Check a domain for typosquatting / lookalike patterns."""

    section("🌐  DOMAIN / LINK INSPECTOR")

    print()
    url = input("  Enter a URL or domain to inspect: ").strip()

    if not url:
        print("  No input provided.")
        pause()
        return

    print()
    divider()
    print("  INSPECTION RESULTS")
    divider()

    issues_found = False

    # Check for HTTP
    if url.startswith("http://"):
        print("  ⚠  Uses HTTP (not HTTPS) — connection is unencrypted and unverified.")
        issues_found = True

    # Check for raw IP
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        print("  🚨 Raw IP address used instead of a domain name — major red flag.")
        issues_found = True

    # Check for URL shorteners
    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "rebrand.ly"]
    for s in shorteners:
        if s in url.lower():
            print(f"  ⚠  URL shortener detected: '{s}' — real destination is hidden.")
            issues_found = True
            break

    # Check for suspicious TLDs
    bad_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq"]
    for tld in bad_tlds:
        if url.lower().endswith(tld) or f"{tld}/" in url.lower():
            print(f"  ⚠  Suspicious top-level domain: '{tld}' — commonly used in phishing.")
            issues_found = True
            break

    # Check for typosquatting (digits replacing letters)
    typos = {"0": "o", "1": "i", "1": "l", "3": "e", "@": "a"}
    for digit, letter in typos.items():
        if digit in url.lower():
            print(f"  ⚠  Possible typosquatting: '{digit}' may replace '{letter}' in a legitimate brand name.")
            issues_found = True
            break

    # Subdomain trap — multiple dots before TLD
    domain_part = url.replace("https://", "").replace("http://", "").split("/")[0]
    parts = domain_part.split(".")
    if len(parts) > 3:
        print(f"  ⚠  Nested subdomain detected: '{domain_part}'")
        print(f"      True root domain: '{parts[-2]}.{parts[-1]}' — read URLs right to left!")
        issues_found = True

    # Brand in subdomain but not real domain
    for brand in BRAND_IMPERSONATION:
        if brand in domain_part.lower():
            root = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain_part
            if brand not in root.lower():
                print(f"  🚨 '{brand.title()}' appears in subdomain but NOT in the root domain.")
                print(f"      Root domain: {root} — this is a subdomain trap!")
                issues_found = True
                break

    # Check for @ in URL
    if "@" in url:
        print("  🚨 '@' symbol in URL — everything before @ is ignored by the browser. Classic trick.")
        issues_found = True

    if not issues_found:
        print("  ✅  No obvious spoofing patterns detected.")
        print("      Always verify the root domain (read right to left after the last dot before /).")

    divider()
    pause()


# ─────────────────────────────────────────────
#  TRIAGE DECISION TREE
# ─────────────────────────────────────────────

def run_triage():
    """
    Interactive triage — walks the user through a decision tree
    to determine if an email is Safe, Suspicious, or Malicious.
    """

    section("🌳  PHISHING TRIAGE DECISION TREE")

    print("\n  Answer YES (y) or NO (n) to each question.\n")
    divider()

    score = 0

    questions = [
        ("Does the sender domain match the brand/company name it claims to be from?", False),
        ("Does the email ask you to click a link or open an attachment?",              True),
        ("Does the subject line use words like URGENT, ACTION REQUIRED, or WARNING?",  True),
        ("Does the email ask for a password, OTP, credit card, or personal details?",  True),
        ("Does it demand secrecy or ask you to bypass normal procedures?",             True),
        ("Is the sender using a free email domain (gmail, yahoo) for an official req?",True),
        ("Are there spelling mistakes or an odd writing style for the alleged sender?", True),
        ("Does hovering or inspecting a link show a different domain than displayed?",  True),
        ("Did the email arrive unexpectedly, with no prior conversation context?",      True),
        ("Does it promise rewards, prizes, or money you weren't expecting?",           True),
    ]

    for question, risky_if_yes in questions:
        print(f"\n  Q: {question}")
        answer = input("     Your answer (y/n): ").strip().lower()
        if answer == "y" and risky_if_yes:
            score += 10
        elif answer == "n" and not risky_if_yes:
            score += 10  # "No" to domain match = bad sign

    print()
    divider()
    print("  TRIAGE RESULT")
    divider()
    print(f"\n  Triage Score : {score} / 100")

    verdict, explanation = get_verdict(score)
    action = triage_action(verdict)

    print(f"  Verdict      : {verdict}")
    print(f"  {explanation}")
    print(f"\n  {action}")

    divider()
    print("\n  💡 Remember: Pause → Verify → Report")
    print("     Never just delete a suspected phishing email.")
    print("     Report it so the security team can purge it from all inboxes.")
    divider()
    pause()


# ─────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────

def main_menu():
    while True:
        banner()
        print("  MAIN MENU")
        print()
        print("  [1]  Analyze a Message / Email")
        print("  [2]  Practice with Sample Phishing Emails")
        print("  [3]  Interactive Triage Decision Tree")
        print("  [4]  Domain / Link Inspector")
        print("  [5]  Red Flags Reference Guide")
        print("  [0]  Exit")
        print()
        divider()
        choice = input("  Enter your choice: ").strip()

        if choice == "1":
            sender, subject, body = get_message_input()
            if not body.strip():
                print("\n  No message body provided. Please enter some text.")
                pause()
            else:
                print("\n  Analyzing...")
                time.sleep(1)
                results = analyze_message(sender, subject, body)
                display_results(results, sender, subject)
                pause()

        elif choice == "2":
            run_sample_analysis()

        elif choice == "3":
            run_triage()

        elif choice == "4":
            check_domain_spoof()

        elif choice == "5":
            show_red_flags_guide()

        elif choice == "0":
            clear()
            divider("═")
            print("  DecodeLabs | Cyber Security Project 3 | Batch 2026")
            print("  Stay vigilant. Pause. Verify. Report.")
            divider("═")
            print()
            break

        else:
            print("\n  Invalid choice. Please enter 0–5.")
            time.sleep(1)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    main_menu()
