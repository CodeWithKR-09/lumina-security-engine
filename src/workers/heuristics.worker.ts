const URGENCY_PHRASES = [
  /delete(?:d)? in \d+ (?:minute|hour|day)s?/i,
  /act fast/i,
  /expires in/i,
  /limited time offer/i,
  /before it's too late/i,
];

const SOCIAL_PROOF_PHRASES = [
  /\d+ people are (?:looking|viewing) at this/i,
  /high demand/i,
  /selling out fast/i,
  /only \d+ left in stock/i,
];

const DISCLAIMER_PHRASES = [
  /automatically renews/i,
  /recurring (?:charge|payment|billing)/i,
  /cancel anytime/i,
  /billed monthly/i,
];

// Basic regex for HTML parsing
const HIDDEN_INPUT_REGEX = /<input[^>]*type=["']?(?:hidden|password)["']?[^>]*>/gi;
const HIDDEN_STYLE_REGEX = /<input[^>]*style=["'][^"']*(?:display:\s*none|visibility:\s*hidden)[^"']*["'][^>]*>/gi;
const IFRAME_REGEX = /<iframe[^>]*src=["']([^"']+)["'][^>]*>/gi;
const SCRIPT_REGEX = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;

const TRUSTED_PROCESSORS = ["stripe.com", "paypal.com", "adyen.com", "braintreegateway.com", "authorize.net"];
const MALICIOUS_CDNS = ["coinhive.com", "minero.cc", "cryptoloot.pro", "jsecoin.com"];

export type ReportFinding = {
  type: 'urgency' | 'social_proof' | 'disclaimer' | 'hidden_input' | 'suspicious_payment' | 'malicious_script';
  message: string;
  snippet?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
};

function analyzeOCR(text: string): ReportFinding[] {
  const findings: ReportFinding[] = [];

  for (const regex of URGENCY_PHRASES) {
    const match = text.match(regex);
    if (match) {
      findings.push({
        type: 'urgency',
        message: 'Artificial urgency detected. May be used to rush a decision.',
        snippet: match[0],
        severity: 'medium',
      });
    }
  }

  for (const regex of SOCIAL_PROOF_PHRASES) {
    const match = text.match(regex);
    if (match) {
      findings.push({
        type: 'social_proof',
        message: 'Fake or manipulative social proof detected.',
        snippet: match[0],
        severity: 'low',
      });
    }
  }

  for (const regex of DISCLAIMER_PHRASES) {
    const match = text.match(regex);
    if (match) {
      findings.push({
        type: 'disclaimer',
        message: 'Hidden subscription or recurring charge disclaimer found.',
        snippet: match[0],
        severity: 'high',
      });
    }
  }

  return findings;
}

function analyzeHTML(html: string): ReportFinding[] {
  const findings: ReportFinding[] = [];

  // Check for hidden inputs
  const hiddenMatches = [...html.matchAll(HIDDEN_INPUT_REGEX), ...html.matchAll(HIDDEN_STYLE_REGEX)];
  if (hiddenMatches.length > 0) {
    findings.push({
      type: 'hidden_input',
      message: `Found ${hiddenMatches.length} hidden input field(s). Could be credential stealing or tracking.`,
      severity: 'medium',
    });
  }

  // Check iframes for payment gateways
  const iframeMatches = [...html.matchAll(IFRAME_REGEX)];
  for (const match of iframeMatches) {
    const src = match[1];
    if (src && !src.startsWith('/') && !TRUSTED_PROCESSORS.some(domain => src.includes(domain))) {
      findings.push({
        type: 'suspicious_payment',
        message: `Suspicious iframe source detected: ${src}. May be a fake payment gateway.`,
        snippet: src,
        severity: 'high',
      });
    }
  }

  // Check scripts for cryptojacking or known malicious domains
  const scriptMatches = [...html.matchAll(SCRIPT_REGEX)];
  for (const match of scriptMatches) {
    const src = match[1];
    if (src && MALICIOUS_CDNS.some(domain => src.includes(domain))) {
      findings.push({
        type: 'malicious_script',
        message: `Malicious script source detected: ${src}. Known cryptojacker or malware.`,
        snippet: src,
        severity: 'critical',
      });
    }
  }

  // Also run text analysis on the raw HTML just in case
  const textFindings = analyzeOCR(html);
  
  return [...findings, ...textFindings];
}

self.onmessage = (e: MessageEvent) => {
  const { type, payload } = e.data as { type: 'ocr' | 'html', payload: string };
  
  let findings: ReportFinding[] = [];
  if (type === 'ocr') {
    findings = analyzeOCR(payload);
  } else if (type === 'html') {
    findings = analyzeHTML(payload);
  }
  
  self.postMessage({ type: 'report', findings });
};
