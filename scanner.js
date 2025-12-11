/* ============================================================
   SUPER ADVANCED LOOP-BASED URL ANALYZER
   Extracted from home.html and moved into standalone JS file
============================================================ */

/* ----------------------------
   Utility Functions
----------------------------- */

function levenshtein(a, b) {
    const dp = Array.from({ length: b.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= a.length; j++) dp[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + (a[j - 1] === b[i - 1] ? 0 : 1)
            );
        }
    }
    return dp[b.length][a.length];
}

function hasHomoglyphs(str) {
    return /[\u0400-\u04FF\u0370-\u03FF]/.test(str);
}

function looksEncoded(str) {
    return /^[A-Za-z0-9+/]{12,}={0,2}$/.test(str) ||
           /^[0-9A-F]{16,}$/i.test(str);
}

/* ----------------------------
   Pattern Data
----------------------------- */

const phishingClusters = [
    ["login","verify"],["secure","update"],["account","verify"],
    ["security","alert"],["action","required"],["package","held"],
    ["delivery","confirm"],["account","locked"],["review","appeal"],
    ["billing","payment"]
];

const highRiskBrands = [
    "bankofamerica","boa","chase","wellsfargo",
    "instagram","facebook","meta","apple","appleid",
    "icloud","outlook","hotmail","fedex","ups","usps","dhl"
];

const autoUnsafeTLDs = [
    ".fake",".invalid",".test",".support",".support-login",
    ".co-login",".security-check",".verify-user",".user-update"
];

const phishingWords = [
    "login","verify","secure","update","alert","confirm","required",
    "locked","restore","appeal","payment","billing","review",
    "suspended","disabled"
];

const deliveryWords = [
    "package","delivery","fedex","usps","ups","dhl",
    "held","action-required","fee","confirm-details"
];

const numberMaps = [
    { bad: "0", good: "o" }, { bad: "1", good: "l" },
    { bad: "3", good: "e" }, { bad: "5", good: "s" },
    { bad: "7", good: "t" }
];

const baseBrands = [
    "paypal","google","amazon","apple",
    "facebook","netflix","chase","microsoft"
];

/* ----------------------------
   Main Analyzer (Loop-Based)
----------------------------- */

function analyzeURL(inputUrl) {

    let url = inputUrl.trim();
    let lower = url.toLowerCase();
    let clean = lower.replace(/^https?:\/\//, "").replace(/^www\./, "");
    let host = clean.split(/[/?#]/)[0];

    let risk = 0;
    let findings = [];

    const rules = [

        // Auto-unsafe TLDs
        ...autoUnsafeTLDs.map(tld => ({
            check: () => host.includes(tld),
            score: 90,
            msg: `Domain uses high-risk TLD '${tld}'.`
        })),

        // Hyphen overload
        {
            check: () => (host.match(/-/g) || []).length >= 4,
            score: 40,
            msg: "Excessive hyphens indicate synthetic phishing."
        },

        // Brand impersonation
        ...highRiskBrands.map(brand => ({
            check: () => host.includes(brand),
            score: 50,
            msg: `Brand impersonation detected: '${brand}'.`
        })),

        // Keyword clusters
        ...phishingClusters.map(cluster => ({
            check: () => cluster.filter(w => lower.includes(w)).length >= 2,
            score: 50,
            msg: `Phishing keyword cluster detected: ${cluster.join(" + ")}`
        })),

        // Simple phishing words
        ...phishingWords.map(word => ({
            check: () => host.includes(word),
            score: 25,
            msg: `Suspicious keyword detected: '${word}'.`
        })),

        // Numeric tokens
        {
            check: () => /[0-9]{3,}/.test(host),
            score: 25,
            msg: "Suspicious numeric token detected."
        },

        // Delivery scam patterns
        ...deliveryWords.map(word => ({
            check: () => lower.includes(word),
            score: 40,
            msg: `Delivery scam pattern: '${word}'.`
        })),

        // Encoded redirect
        {
            check: () => looksEncoded(lower.split("=").pop()),
            score: 40,
            msg: "Encoded redirect detected."
        },

        // Homoglyphs
        {
            check: () => hasHomoglyphs(url),
            score: 40,
            msg: "Foreign homoglyph characters detected."
        },

        // Typosquatting numeric replacements
        ...numberMaps.map(m => ({
            check: () => host.includes(m.bad),
            score: 45,
            msg: `Typosquatting substitution: '${m.bad}' for '${m.good}'.`
        })),

        // Levenshtein similarity
        ...baseBrands.map(b => ({
            check: () => {
                const dist = levenshtein(host, b);
                return dist <= 2 && !host.endsWith(`${b}.com`);
            },
            score: 50,
            msg: `Domain resembles '${b}' — highly suspicious.`
        })),

        // Long URL
        {
            check: () => url.length > 80,
            score: 20,
            msg: "URL is unusually long."
        },

        // Excessive subdomains
        {
            check: () => (host.match(/\./g) || []).length > 3,
            score: 25,
            msg: "Excessive subdomains — common in phishing."
        }
    ];

    // Execute all rules
    rules.forEach(rule => {
        if (rule.check()) {
            risk += rule.score;
            findings.push(rule.msg);
        }
    });

    const score = Math.min(100, risk);
    const safePercent = Math.max(0, 100 - score);

    let verdict = "SAFE";
    if (safePercent < 80) verdict = "SUSPICIOUS";
    if (safePercent < 50) verdict = "UNSAFE";

    return { score, safePercent, verdict, findings };
}

/* ----------------------------
   Scan Handler
----------------------------- */

document.addEventListener("DOMContentLoaded", () => {

    const form = document.getElementById("urlForm");
    const box = document.getElementById("resultBox");

    form.addEventListener("submit", (e) => {
        e.preventDefault();

        const input = document.getElementById("urlInput").value;

        // Animation
        box.innerHTML = "<p>🔍 Scanning URL</p>";
        let dots = 0;

        const interval = setInterval(() => {
            dots = (dots + 1) % 4;
            box.innerHTML = `<p>🔍 Scanning${'.'.repeat(dots)}</p>`;
        }, 200);

        setTimeout(() => {
            clearInterval(interval);

            const result = analyzeURL(input);

            const emoji =
                result.verdict === "SAFE" ? "✅" :
                result.verdict === "SUSPICIOUS" ? "⚠️" :
                "❌";

            const list = result.findings.map(i => `<li>${i}</li>`).join("");

            box.innerHTML = `
                <p><strong>Status:</strong> ${emoji} ${result.verdict}</p>

                <div style="margin-top:12px;">
                    <div style="width:100%;height:16px;background:#ddd;border-radius:10px;overflow:hidden;">
                        <div id="meterBar"
                            style="width:0%;height:100%;background:red;transition:width 1.2s,background 1s"></div>
                    </div>
                    <p><strong>Safety Score:</strong> ${result.safePercent}%</p>
                </div>

                <p><strong>Reasons:</strong></p>
                <ul>${list}</ul>
            `;

            const bar = document.getElementById("meterBar");

            setTimeout(() => {
                bar.style.width = result.safePercent + "%";
                bar.style.background =
                    result.safePercent >= 80 ? "#2ecc71" :
                    result.safePercent >= 50 ? "#f1c40f" :
                    "#e74c3c";
            }, 50);

        }, 900);
    });

});
