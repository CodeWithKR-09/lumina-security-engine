# 🛡️ Lumina Security Engine

> **The Privacy-First Offline Dark Pattern & Threat Sandbox**  
> *Built for HackDay 1.0 — Theme: "Tech for a Better Tomorrow"*

## 🚀 Overview
**Lumina Security Engine** is a high-performance, 100% privacy-first Progressive Web App (PWA) designed to protect consumers from deceptive web practices, psychological manipulation (dark patterns), and hidden credential phishing. 

Unlike traditional security tools that require uploading sensitive personal data or URLs to cloud-based servers, Lumina executes its heuristic threat analysis entirely on-device. It evaluates websites and images locally to ensure zero data leakage.

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

### Scenario 2: Malicious Sandbox Trigger
Demonstrate Lumina's ability to catch zero-day phishing attempts, credential harvesting, and dark patterns using a controlled local simulation.
1. Create a new file on your computer named `malicious-test.html`.
2. Copy and paste the following simulation code into the file:

    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Account Verification</title>
        <style>.hidden-trap { display: none; }</style>
    </head>
    <body>
        <h1>⚠️ URGENT ACTION REQUIRED: Account Suspended!</h1>
        <p>Verify your identity immediately to prevent permanent account closure.</p>
        
        <div>⏰ Limited time offer expires in: 01:59 countdown timer!</div>

        <form action="/login-verify">
            <input type="password" placeholder="Enter your password" required>
            <button type="submit">Verify Now</button>
        </form>

        <div class="hidden-trap recurring-billing-fee">
            By clicking verify you agree to a hidden recurring-billing-fee.
        </div>
    </body>
    </html>
    ```

3. Serve this file locally (e.g., using VS Code Live Server, Python's `http.server`, or `npx serve`).
4. Paste the local URL (e.g., `http://127.0.0.1:5500/malicious-test.html`) into the Lumina URL portal.
5. Click **Run Security Scan**.
6. **Expected Result:** The engine will instantly flag the urgency keywords, artificial countdown timer, hidden subscription trap, and unverified password form. The UI will shift to a **Critical Danger** state, detailing the exact detected indicators.

### Scenario 3: Offline Screenshot OCR Analysis
Showcase the on-device WebAssembly text extraction for users who cannot copy-paste URLs (e.g., SMS phishing or image-based scams).
1. Take a screenshot of the rendered `malicious-test.html` page (or any image containing manipulative terms like "subscribe," "monthly fee," and "urgent").
2. Switch to the **Screenshot OCR** tab in the Lumina dashboard.
3. Drag and drop the screenshot into the upload zone.
4. Click **Run Security Scan**.
5. **Expected Result:** The browser-based Tesseract.js engine will extract the text entirely offline and run the heuristic ruleset against the raw text, catching the text-based dark patterns without network requests.

---
*Designed and developed by Kamalesh Ramu S V for HackDay 1.0.*