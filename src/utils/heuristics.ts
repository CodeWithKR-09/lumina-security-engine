export interface ScanFinding {
    id: string;
    title: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    category: 'domain' | 'credential' | 'dark_pattern' | 'scam_nlp' | 'malicious_code';
}

export interface ScanResult {
    score: number;
    level: 'Safe' | 'Suspicious' | 'Critical Danger' | 'Webpage Not Found';
    available?: boolean;
    availabilityReason?: string;
    summary: string;
    flags: string[];
    detailedFindings?: ScanFinding[];
}

export function createNotFoundResult(targetUrl: string, reason: string): ScanResult {
    return {
        score: 0,
        level: 'Webpage Not Found',
        available: false,
        availabilityReason: reason,
        summary: `Target webpage not found or host is unreachable (${reason}). Threat analysis cannot verify an unhosted or non-existent destination.`,
        flags: [
            `Target destination status: ${reason}`,
            'No live DOM structure or active server response available to analyze',
            'Security status: Unverified (Destination offline or 404)'
        ],
        detailedFindings: [
            {
                id: 'page-not-found',
                title: 'Webpage Not Found / Server Offline',
                description: reason || 'The requested URL returned HTTP 404 or domain does not resolve.',
                severity: 'medium',
                category: 'domain'
            }
        ]
    };
}

// Reputable legitimate domains that should not trigger false positives
const TRUSTED_DOMAINS = [
    'google.com',
    'youtube.com',
    'github.com',
    'wikipedia.org',
    'microsoft.com',
    'apple.com',
    'amazon.com',
    'cloudflare.com',
    'stackoverflow.com',
    'mozilla.org',
    'iana.org',
    'linkedin.com',
    'reddit.com',
    'twitter.com',
    'x.com',
    'netflix.com',
    'spotify.com',
    'nytimes.com',
    'cnn.com',
    'bbc.com',
    'facebook.com',
    'instagram.com',
    'yahoo.com',
    'bing.com',
    'w3.org'
];

// High-value brands frequently targeted by phishing campaigns
const PHISHED_BRANDS = [
    'paypal',
    'apple',
    'microsoft',
    'google',
    'netflix',
    'amazon',
    'chase',
    'wellsfargo',
    'bankofamerica',
    'binance',
    'coinbase',
    'metamask',
    'steam',
    'discord',
    'telegram',
    'facebook',
    'instagram',
    'roblox',
    'citibank',
    'barclays'
];

// High-risk top-level domains frequently abused for disposable phishing campaigns
const HIGH_RISK_TLDS = [
    '.xyz', '.top', '.buzz', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.icu', '.cam', '.click', '.surf', '.stream', '.bid', '.country',
    '.club', '.work', '.date', '.racing', '.kim', '.party', '.science'
];

// Common free hosting/tunnel domains often abused to host fake login pages
const SUSPICIOUS_HOSTS = [
    'ngrok.io',
    'ngrok-free.app',
    'glitch.me',
    '000webhostapp.com',
    'firebaseapp.com',
    'pages.dev',
    'duckdns.org',
    'localtunnel.me',
    'serveo.net'
];

// Known cryptomining CDNs / domains
const CRYPTOMINER_SIGNATURES = [
    'coinhive', 'cryptoloot', 'minero.cc', 'jsecoin', 'coin-have', 'webminepool'
];

/**
 * Normalizes a URL and extracts its hostname safely
 */
function parseUrlDetails(rawUrl: string): { hostname: string; protocol: string; pathname: string; isValid: boolean } {
    if (!rawUrl || typeof rawUrl !== 'string') {
        return { hostname: '', protocol: '', pathname: '', isValid: false };
    }

    let urlToParse = rawUrl.trim();
    if (!/^https?:\/\//i.test(urlToParse)) {
        urlToParse = `https://${urlToParse}`;
    }

    try {
        const parsed = new URL(urlToParse);
        return {
            hostname: parsed.hostname.toLowerCase(),
            protocol: parsed.protocol.toLowerCase(),
            pathname: parsed.pathname.toLowerCase(),
            isValid: true
        };
    } catch {
        // Fallback simple extraction if standard URL parsing fails
        const cleaned = rawUrl.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
        return {
            hostname: cleaned,
            protocol: rawUrl.startsWith('http://') ? 'http:' : 'https:',
            pathname: '',
            isValid: Boolean(cleaned)
        };
    }
}

/**
 * Checks if a hostname matches or is a subdomain of a trusted domain
 */
function isTrustedDomain(hostname: string): boolean {
    return TRUSTED_DOMAINS.some(trusted => 
        hostname === trusted || hostname.endsWith(`.${trusted}`)
    );
}

/**
 * Analyzes target URL for domain-level threat signals
 */
function evaluateUrlThreats(rawUrl: string, findings: ScanFinding[]): number {
    let score = 0;
    const { hostname, protocol, pathname, isValid } = parseUrlDetails(rawUrl);

    if (!isValid || !hostname) return 0;

    // 1. Check if trusted domain
    if (isTrustedDomain(hostname)) {
        return 0; // Trusted authority
    }

    // 2. Direct Raw IP Address Check (e.g., http://192.168.1.1/login or http://45.33.22.11)
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
    if (isIpHost) {
        score += 45;
        findings.push({
            id: 'raw-ip-hostname',
            title: 'Raw IP Address Hostname',
            description: `Target uses raw IP (${hostname}) instead of a registered domain name, common in phishing and botnet command servers.`,
            severity: 'critical',
            category: 'domain'
        });
    }

    // 3. Brand Impersonation / Typosquatting
    // Checks if a major brand appears in the domain or path when hosted on an unverified domain
    for (const brand of PHISHED_BRANDS) {
        const brandInHost = hostname.includes(brand);
        const brandInPath = pathname.includes(brand);

        if (brandInHost || brandInPath) {
            score += 50;
            findings.push({
                id: `brand-impersonation-${brand}`,
                title: `High-Risk Brand Impersonation (${brand.toUpperCase()})`,
                description: `Domain or path contains '${brand}' but is not the official ${brand} domain. Classic credential phishing indicator.`,
                severity: 'critical',
                category: 'domain'
            });
            break;
        }
    }

    // 4. High-Risk Phishing TLD Check
    const hasHighRiskTld = HIGH_RISK_TLDS.some(tld => hostname.endsWith(tld));
    if (hasHighRiskTld) {
        score += 25;
        findings.push({
            id: 'suspicious-tld',
            title: 'High-Risk Phishing TLD',
            description: `Domain uses a top-level domain frequently associated with disposable phishing campaigns.`,
            severity: 'medium',
            category: 'domain'
        });
    }

    // 5. Excessive Subdomain / Hyphen Masking (e.g. login.secure.account.paypal.com.attacker.xyz)
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const subdomains = hostname.split('.');
    if (subdomains.length >= 4 || hyphenCount >= 3) {
        score += 25;
        findings.push({
            id: 'deceptive-domain-structure',
            title: 'Deceptive Domain Masking',
            description: 'Domain contains multiple subdomains or excessive hyphens, commonly used to trick users on mobile screens.',
            severity: 'medium',
            category: 'domain'
        });
    }

    // 6. Suspicious Free Subdomain Host
    const isFreeHost = SUSPICIOUS_HOSTS.some(h => hostname.endsWith(h));
    if (isFreeHost) {
        score += 30;
        findings.push({
            id: 'free-tunnel-host',
            title: 'Abused Free Hosting / Tunneling Host',
            description: 'Target is hosted on a free subdomain/tunneling service frequently leveraged for quick-turnaround credential phishing.',
            severity: 'high',
            category: 'domain'
        });
    }

    // 7. Insecure HTTP for potentially sensitive page
    if (protocol === 'http:' && (hostname.includes('login') || hostname.includes('verify') || hostname.includes('bank') || hostname.includes('secure'))) {
        score += 35;
        findings.push({
            id: 'insecure-http-auth',
            title: 'Unencrypted Authentication Link',
            description: 'Sensitive security or login keywords hosted over unencrypted HTTP protocol.',
            severity: 'high',
            category: 'domain'
        });
    }

    return score;
}

/**
 * Main Content & Threat Analyzer
 */
export function analyzeContent(content: string, type: 'html' | 'text', targetUrl?: string): ScanResult {
    const findings: ScanFinding[] = [];
    let cumulativeScore = 0;

    const lowerContent = content ? content.toLowerCase() : '';
    const { hostname } = parseUrlDetails(targetUrl || '');
    const isWhitelisted = isTrustedDomain(hostname);

    // If URL is provided, perform URL intelligence checks
    if (targetUrl) {
        cumulativeScore += evaluateUrlThreats(targetUrl, findings);
    }

    // ==========================================
    // 1. NLP Scam, Urgency & Fear Tactics
    // ==========================================
    const urgencyPatterns = [
        {
            regex: /(?:urgent|immediate)\s+(?:action|attention|verification)\s+required/i,
            title: 'Critical Phishing Urgency Demand',
            desc: 'Demands immediate action to create panic and bypass critical thinking.',
            points: 35
        },
        {
            regex: /account\s+(?:has\s+been\s+)?(?:suspended|locked|restricted|disabled|blocked|frozen|terminated)/i,
            title: 'Account Suspension Threat',
            desc: 'Claims your account is suspended or locked to induce panic credential submission.',
            points: 40
        },
        {
            regex: /verify\s+(?:your\s+)?(?:identity|account|credentials|billing|password)\s+(?:immediately|now|within\s+\d+|to\s+avoid)/i,
            title: 'Immediate Verification Phishing Trap',
            desc: 'Coerces user to enter sensitive verification details under threat of penalty.',
            points: 35
        },
        {
            regex: /unauthorized\s+(?:access|login|activity|transaction)\s+(?:detected|alert)/i,
            title: 'Fake Unauthorized Activity Alert',
            desc: 'Spoofs a bank or service security notification to prompt fake login resolution.',
            points: 35
        },
        {
            regex: /unusual\s+(?:sign-in|activity)\s+detected/i,
            title: 'Security Alert Impersonation',
            desc: 'Impersonates an authentication security warning.',
            points: 30
        },
        {
            regex: /failure\s+to\s+(?:verify|respond|update)\s+will\s+result\s+in/i,
            title: 'Coercive Consequences Warning',
            desc: 'Explicit blackmail or penalty threats to force immediate compliance.',
            points: 30
        }
    ];

    for (const pattern of urgencyPatterns) {
        if (pattern.regex.test(content)) {
            cumulativeScore += pattern.points;
            findings.push({
                id: `urgency-${pattern.points}`,
                title: pattern.title,
                description: pattern.desc,
                severity: 'high',
                category: 'scam_nlp'
            });
            break; // Record primary urgency finding
        }
    }

    // ==========================================
    // 2. Tech Support Scareware Scams
    // ==========================================
    const scarewarePatterns = [
        {
            regex: /(?:windows|apple|microsoft)\s+(?:defender|security|firewall)\s+alert/i,
            title: 'Tech Support Brand Impersonation',
            desc: 'Falsely displays OS or security company branding to frighten user.',
            points: 50
        },
        {
            regex: /(?:computer|system|device|phone)\s+(?:has\s+been\s+)?(?:infected|compromised|blocked|locked)/i,
            title: 'Fake Virus / System Infection Warning',
            desc: 'Bogus infection dialog designed to coerce calling a fraudulent call center.',
            points: 45
        },
        {
            regex: /call\s+(?:toll[- ]?free|support|customer\s+care|help\s*desk|microsoft|apple)\s+(?:now|immediately|\+?1?[-\s]?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4})/i,
            title: 'Fraudulent Support Hotline Prompt',
            desc: 'Prompts immediate phone contact to a fake tech support call center.',
            points: 50
        }
    ];

    for (const pattern of scarewarePatterns) {
        if (pattern.regex.test(content)) {
            cumulativeScore += pattern.points;
            findings.push({
                id: 'scareware-alert',
                title: pattern.title,
                description: pattern.desc,
                severity: 'critical',
                category: 'scam_nlp'
            });
            break;
        }
    }

    // ==========================================
    // 3. Prize, Lottery & Crypto Scams
    // ==========================================
    const prizePatterns = [
        {
            regex: /(?:congratulations|claim)\s+(?:you(?:'ve|\s+have)\s+won|your\s+prize|free\s+gift|iphone)/i,
            title: 'Prize / Lottery Scam Hook',
            desc: 'Claims unearned prize or gift winnings to bait user into entering credit card for shipping.',
            points: 35
        },
        {
            regex: /crypto\s+giveaway|double\s+your\s+(?:btc|eth|crypto|bitcoin)|send\s+\d+\s+get\s+\d+/i,
            title: 'Fraudulent Crypto Doubler / Giveaway',
            desc: 'Classic cryptocurrency doubler fraud requesting token transfers.',
            points: 55
        },
        {
            regex: /connect\s+(?:your\s+)?wallet\s+to\s+claim\s+(?:airdrop|reward|tokens)/i,
            title: 'Malicious Web3 Wallet Drainer Prompt',
            desc: 'Prompts wallet connection for a fake airdrop, typically containing draining scripts.',
            points: 45
        }
    ];

    for (const pattern of prizePatterns) {
        if (pattern.regex.test(content)) {
            cumulativeScore += pattern.points;
            findings.push({
                id: 'prize-crypto-scam',
                title: pattern.title,
                description: pattern.desc,
                severity: 'high',
                category: 'scam_nlp'
            });
            break;
        }
    }

    // ==========================================
    // 4. Dark Patterns: Urgency, Timers & Traps
    // ==========================================
    const darkPatterns = [
        {
            regex: /(?:expires\s+in|offer\s+ends\s+in|deal\s+expires\s+in|timer\s+ends|limited\s+time\s+offer)\s*:?\s*\d+/i,
            title: 'Artificial Countdown Urgency Timer',
            desc: 'Manipulates decision making with artificial expiration countdowns (Dark Pattern).',
            points: 25
        },
        {
            regex: /only\s+\d+\s+(?:items?|left|remaining|tickets?)\s+(?:in\s+stock|available)/i,
            title: 'Manipulative Fake Scarcity Claim',
            desc: 'Fabricates low stock levels to pressure immediate purchases (Dark Pattern).',
            points: 20
        },
        {
            regex: /\d+\s+people\s+(?:are\s+looking|viewing|bought\s+this|in\s+cart)/i,
            title: 'Fabricated Social Proof',
            desc: 'Displays synthetic viewer counters to create herd anxiety (Dark Pattern).',
            points: 15
        },
        {
            regex: /(?:automatically\s+renews|recurring\s+(?:charge|payment|billing)|renews\s+at\s+\$\d+|billed\s+monthly\s+after\s+trial)/i,
            title: 'Forced Continuity / Hidden Recurring Billing',
            desc: 'Binds users into recurring subscription fees obscured in secondary text (Dark Pattern).',
            points: 30
        },
        {
            regex: /(?:no\s+thanks\s*,?\s*i\s+(?:hate\s+saving|don't\s+care\s+about\s+security|prefer\s+to\s+pay\s+full|want\s+to\s+stay\s+unprotected))/i,
            title: 'Confirmshaming Deceptive Choice',
            desc: 'Guilt-trips the user into accepting terms with emotionally manipulative rejection copy.',
            points: 20
        }
    ];

    for (const dp of darkPatterns) {
        if (dp.regex.test(content)) {
            cumulativeScore += dp.points;
            findings.push({
                id: 'dark-pattern',
                title: dp.title,
                description: dp.desc,
                severity: 'medium',
                category: 'dark_pattern'
            });
        }
    }

    // ==========================================
    // 5. HTML DOM & Technical Threat Checks
    // ==========================================
    if (type === 'html') {
        const hasPasswordInput = /<input[^>]*type=["']password["'][^>]*>/i.test(content);
        const hasCreditCardInput = /<input[^>]*(?:name|id|autocomplete)=["']?(?:cc-number|cardnumber|cvv|cvc|card_number|creditcard)["']?[^>]*>/i.test(content);

        // Check for suspicious password form endpoints (external exfiltration)
        if (hasPasswordInput) {
            const hasExfilAction = /action=["'](?:https?:\/\/(?:docs\.google\.com\/forms|api\.telegram\.org|discord(?:app)?\.com\/api\/webhooks|formspree\.io|formsubmit\.co)|mailto:)/i.test(content);
            
            if (hasExfilAction) {
                cumulativeScore += 55;
                findings.push({
                    id: 'credential-exfiltration-form',
                    title: 'Active Credential Harvesting Exfiltration Form',
                    description: 'Form containing password input routes data directly to an unverified third-party webhook or submission service.',
                    severity: 'critical',
                    category: 'credential'
                });
            } else if (!isWhitelisted && (targetUrl || lowerContent.includes('login') || lowerContent.includes('sign in'))) {
                cumulativeScore += 35;
                findings.push({
                    id: 'unverified-password-form',
                    title: 'Unverified Login Credential Collection',
                    description: 'Form actively solicits secret passwords on an unverified domain.',
                    severity: 'high',
                    category: 'credential'
                });
            }
        }

        // Direct Credit Card Solicitation
        if (hasCreditCardInput) {
            cumulativeScore += 40;
            findings.push({
                id: 'credit-card-harvesting',
                title: 'Direct Credit Card & CVV Harvesting Form',
                description: 'HTML form contains direct unencrypted payment card fields rather than a secure tokenized processor.',
                severity: 'critical',
                category: 'credential'
            });
        }

        // Malicious scripts / Cryptominers
        for (const miner of CRYPTOMINER_SIGNATURES) {
            if (lowerContent.includes(miner)) {
                cumulativeScore += 60;
                findings.push({
                    id: 'cryptominer-detected',
                    title: 'In-Browser Cryptocurrency Miner',
                    description: `Script reference to known in-browser cryptojacker (${miner}) detected. Hijacks visitor CPU cycles.`,
                    severity: 'critical',
                    category: 'malicious_code'
                });
                break;
            }
        }

        // Obfuscated payload execution
        const hasObfuscation = /eval\s*\(\s*(?:unescape|atob|decodeURIComponent)\b/i.test(content) ||
            /String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+/i.test(content) ||
            /(?:\\x[0-9a-fA-F]{2}){10,}/.test(content);

        if (hasObfuscation) {
            cumulativeScore += 40;
            findings.push({
                id: 'obfuscated-script',
                title: 'Obfuscated JavaScript Payload',
                description: 'Executable code packed with hex/eval/decode functions designed to evade signature scanners.',
                severity: 'critical',
                category: 'malicious_code'
            });
        }

        // Anti-analysis / UI tampering (disabling right-click or F12)
        const hasAntiAnalysis = /contextmenu\s*=\s*["']?return\s+false/i.test(content) ||
            /addEventListener\s*\(\s*["']contextmenu["']/i.test(content) ||
            /keydown.*(?:keyCode|which)\s*===\s*123/i.test(content);

        if (hasAntiAnalysis) {
            cumulativeScore += 25;
            findings.push({
                id: 'anti-inspection-tamper',
                title: 'Anti-Inspection UI Tampering',
                description: 'Page actively disables right-click context menus or developer tools keybindings to hide inspection.',
                severity: 'medium',
                category: 'malicious_code'
            });
        }

        // Hidden / Invisible Iframes
        const hasHiddenIframe = /<iframe[^>]*(?:style=["'][^"']*(?:display:\s*none|visibility:\s*hidden|width:\s*0|height:\s*0|opacity:\s*0)[^"']*|width=["']0["']|height=["']0["'])[^>]*>/i.test(content);
        if (hasHiddenIframe) {
            cumulativeScore += 25;
            findings.push({
                id: 'hidden-iframe',
                title: 'Hidden Zero-Pixel Iframe',
                description: 'Invisible iframe embedded on the page, commonly used for clickjacking or background cookie drops.',
                severity: 'medium',
                category: 'malicious_code'
            });
        }
    }

    // ==========================================
    // 6. Safe Whitelist Protection
    // ==========================================
    if (isWhitelisted) {
        // High-reputation sites (Google, YouTube, etc.) should never score as malicious
        cumulativeScore = 0;
        findings.length = 0; // Clear false positives for certified domains
    }

    // Cap score at 100
    const finalScore = Math.min(Math.max(cumulativeScore, 0), 100);

    // Threat level categorization
    let level: 'Safe' | 'Suspicious' | 'Critical Danger' = 'Safe';
    let summary = 'No malicious indicators, phishing signatures, or manipulation tactics detected. Page structure appears secure.';

    if (finalScore >= 65) {
        level = 'Critical Danger';
        summary = 'Severe security threats identified: credential harvesting, high-confidence phishing signatures, or malicious payloads.';
    } else if (finalScore >= 30) {
        level = 'Suspicious';
        summary = 'Manipulative dark patterns, deceptive countdown timers, or questionable structural elements warrant caution.';
    }

    // Human-readable flags
    const flags = findings.length > 0
        ? findings.map(f => `${f.title} (${f.severity.toUpperCase()})`)
        : isWhitelisted
            ? ['Verified trusted domain authority', 'Safe structural patterns verified']
            : ['No active threat signatures or dark patterns found', 'Clean structural patterns verified safe'];

    return {
        score: finalScore,
        level,
        summary,
        flags,
        detailedFindings: findings
    };
}