// =============================================================================
// analyzer.js — Element Threat Analysis
// Pure functions — no global state read at definition time, no DOM side-effects.
// =============================================================================

// ── Javascript URI deep scanner ───────────────────────────────────────────────
function scanJavascriptURI(uri) {
  if (!uri.trim().toLowerCase().startsWith("javascript:")) {
    return { isSuspicious: false };
  }

  let payload = uri.trim().substring(11);
  try {
    payload = decodeURIComponent(payload);
  } catch (e) {
    return { isSuspicious: true, threats: ["Malformed URI encoding"], payload: uri };
  }

  const threatRules = [
    { name: "XSS Execution Probe", regex: /alert\(|confirm\(|prompt\(/i },
    { name: "Cookie Theft", regex: /document\.cookie/i },
    { name: "Local Storage Access", regex: /localStorage|sessionStorage/i },
    { name: "Data Exfiltration", regex: /fetch\(|XMLHttpRequest|webhook/i },
    { name: "Code Execution/Obfuscation", regex: /eval\(|setTimeout\(|atob\(|btoa\(/i },
    { name: "Page Redirection", regex: /window\.location|document\.location/i },
  ];

  const matchedThreats = threatRules
    .filter((r) => r.regex.test(payload))
    .map((r) => r.name);

  if (matchedThreats.length > 0) {
    return { isSuspicious: true, threats: matchedThreats, payload };
  }
  return { isSuspicious: false, threats: [], payload };
}

// ── Internal: analyse a SINGLE element only ───────────────────────────────────
function _analyseSingle(element) {
  let reasons = [];
  let score = 0; // 0 = safe | 1 = warning | 2 = danger
  let previewUrl = null;

  // ── 1. Link (<a>) ─────────────────────────────────────────────────────────
  if (element.tagName === "A") {
    const href = element.getAttribute("href") || "";
    previewUrl = element.href; // absolute URL

    // javascript: URI — deep static analysis
    if (href.trim().toLowerCase().startsWith("javascript:")) {
      const jsReport = scanJavascriptURI(href);
      const payload = (jsReport.payload || "").trim();

      // Known-safe patterns: void(0), empty payload, bare semicolons, return false
      const isSafePattern = /^(void\s*\(0\)|;*|return\s+false;?)$/i.test(payload);

      if (isSafePattern) {
        // Safe javascript: usage — do not flag at all
      } else if (jsReport.isSuspicious && jsReport.threats && jsReport.threats.length > 0) {
        // Confirmed threat signatures found — DANGER
        jsReport.threats.forEach((threat) => {
          reasons.push({
            short: `⚠ javascript: URI — ${threat}`,
            verbose: `Payload: ${payload.slice(0, 120)}`,
          });
        });
        score = Math.max(score, 2);
      } else {
        // Unknown javascript: payload — flag as WARNING only
        reasons.push({
          short: tmText("reasonLinkInlineJsShort", "Contains inline JavaScript execution in link."),
          verbose: tmText(
            "reasonLinkInlineJsVerbose",
            "Inline JS (`javascript:`) can be used by attackers to run malicious scripts (XSS) when you click the link.",
          ),
        });
        score = Math.max(score, 1);
      }
      previewUrl = null;

      // Plain HTTP
    } else if (href.startsWith("http://")) {
      reasons.push({
        short: tmText("reasonInsecureHttpShort", "Link uses insecure HTTP protocol."),
        verbose: tmText(
          "reasonInsecureHttpVerbose",
          "Data sent over this connection is unencrypted and can be intercepted by third parties.",
        ),
      });
      score = Math.max(score, 1);
    }

    // Raw IP address (skip localhost/dev server IPs)
    const ipMatch = element.href.match(/^https?:\/\/(\d{1,3}(\.\d{1,3}){3})/);
    if (ipMatch) {
      const ip = ipMatch[1];
      const isLocalhost = ip === "127.0.0.1" || ip === "0.0.0.0" || ip.startsWith("192.168.") === false && ip === ip; // keep
      const isLoopback = ip === "127.0.0.1" || ip === "0.0.0.0";
      if (!isLoopback) {
        reasons.push({
          short: tmText(
            "reasonRawIpShort",
            "Link points to a raw IP address instead of a domain name.",
          ),
          verbose: tmText(
            "reasonRawIpVerbose",
            "Legitimate websites almost never use raw IPs for user-facing pages — a common phishing and malware hosting technique.",
          ),
        });
        score = Math.max(score, 2);
      }
    }

    // Punycode / Homograph attack
    if (/xn--/.test(element.href)) {
      reasons.push({
        short: tmText(
          "reasonPunycodeShort",
          "Domain uses Punycode encoding (possible homograph/look-alike attack).",
        ),
        verbose: tmText(
          "reasonPunycodeVerbose",
          "e.g. xn--pple-43d.com can look identical to apple.com using Cyrillic characters. Attackers register visually identical domains to steal credentials.",
        ),
      });
      score = Math.max(score, 2);
    }

    // Dangerous file extensions
    if (
      /\.(exe|bat|ps1|vbs|msi|cmd|scr|jar|dmg|sh|hta|pif|cpl)(\?.*)?$/i.test(
        element.href,
      )
    ) {
      reasons.push({
        short: tmText(
          "reasonDangerousFileShort",
          "Link downloads a potentially dangerous executable or script file.",
        ),
        verbose: tmText(
          "reasonDangerousFileVerbose",
          "This link points to a file with a dangerous extension (.exe, .bat, .ps1, .vbs, .msi, etc.) that could be malware or ransomware.",
        ),
      });
      score = Math.max(score, 2);
      previewUrl = null;
    }

    // Data URI
    if (href.startsWith("data:")) {
      reasons.push({
        short: tmText(
          "reasonDataUriShort",
          "Link uses a Data URI — commonly used in phishing attacks.",
        ),
        verbose: tmText(
          "reasonDataUriVerbose",
          "`data:` URIs can embed an entire web page in the URL. Attackers use them to create fake login pages that bypass domain-based security checks.",
        ),
      });
      score = Math.max(score, 2);
      previewUrl = null;
    }

    // External link
    try {
      const url = new URL(href, window.location.origin);
      if (
        url.hostname !== window.location.hostname &&
        href.startsWith("http")
      ) {
        reasons.push({
          short: tmFormat(
            tmText("reasonExternalLinkShort", "External link (goes to: {host})."),
            { host: url.hostname },
          ),
          verbose: tmText(
            "reasonExternalLinkVerbose",
            "Be careful clicking links that take you away from the current website — they could be phishing attempts.",
          ),
        });
        score = Math.max(score, 1);
      }
    } catch (err) { }

    // Subdomain spoofing / brand impersonation
    const spoofBrands = {
      paypal: "paypal.com",
      google: "google.com",
      apple: "apple.com",
      microsoft: "microsoft.com",
      amazon: "amazon.com",
      facebook: "facebook.com",
      instagram: "instagram.com",
      netflix: "netflix.com",
      twitter: "twitter.com",
      linkedin: "linkedin.com",
      dropbox: "dropbox.com",
      adobe: "adobe.com",
    };
    try {
      const spoofUrl = new URL(href, window.location.origin);
      if (spoofUrl.hostname !== window.location.hostname) {
        const hn = spoofUrl.hostname.toLowerCase();
        for (const [brand, trueDomain] of Object.entries(spoofBrands)) {
          if (hn.includes(brand) && !hn.endsWith(trueDomain)) {
            reasons.push({
              short: tmFormat(
                tmText(
                  "reasonSpoofShort",
                  'Domain contains "{brand}" but is not {domain} — possible brand spoofing.',
                ),
                { brand, domain: trueDomain },
              ),
              verbose: tmText(
                "reasonSpoofVerbose",
                "Attackers register lookalike domains (e.g. paypal-secure.net) to impersonate trusted brands and steal credentials.",
              ),
            });
            score = Math.max(score, 2);
            break;
          }
        }
      }
    } catch (e) { }

    // Open redirect
    try {
      const urlObj = new URL(href, window.location.origin);
      const redirectParams = [
        "redirect",
        "redirect_uri",
        "redirect_url",
        "url",
        "goto",
        "next",
        "return",
        "returnUrl",
        "target",
        "rurl",
        "dest",
        "destination",
      ];
      for (const param of redirectParams) {
        const val = urlObj.searchParams.get(param);
        if (val) {
          try {
            const redirectTarget = new URL(val);
            if (
              redirectTarget.hostname &&
              redirectTarget.hostname !== window.location.hostname
            ) {
              reasons.push({
                short: tmFormat(
                  tmText(
                    "reasonOpenRedirectShort",
                    'Possible open redirect — "{param}" parameter leads to {host}.',
                  ),
                  { param, host: redirectTarget.hostname },
                ),
                verbose: tmText(
                  "reasonOpenRedirectVerbose",
                  "Attackers exploit open redirects to make malicious links appear to originate from a trusted site.",
                ),
              });
              score = Math.max(score, 1);
            }
          } catch (e) { }
        }
      }
    } catch (e) { }

    // Missing rel="noopener" on target="_blank"
    if (element.target === "_blank") {
      const rel = element.getAttribute("rel") || "";
      if (!rel.includes("noopener") && !rel.includes("noreferrer")) {
        reasons.push({
          short: tmText(
            "reasonNoNoopenerShort",
            'Opens in new tab without rel="noopener" — risk of reverse tabnapping.',
          ),
          verbose: tmText(
            "reasonNoNoopenerVerbose",
            "The opened page can access window.opener and silently redirect this page to a phishing site (reverse tabnapping attack).",
          ),
        });
        score = Math.max(score, 1);
      }
    }

    // Hidden link (invisible trap)
    const style = window.getComputedStyle(element);
    if (style.display === "none" || style.visibility === "hidden") {
      reasons.push({
        short: tmText("reasonHiddenLinkShort", "Link is hidden — could be an invisible trap."),
        verbose: tmText(
          "reasonHiddenLinkVerbose",
          "Attackers hide links to manipulate search rankings or overlay invisible links over trusted buttons to steal clicks.",
        ),
      });
      score = Math.max(score, 2);
      previewUrl = null;
    }
  }

  // ── 2. Form ───────────────────────────────────────────────────────────────
  const form = element.closest("form");
  if (form) {
    const action = form.getAttribute("action") || "";
    if (action.startsWith("http://")) {
      reasons.push({
        short: tmText("reasonFormHttpShort", "Form submits data insecurely (HTTP)."),
        verbose: tmText(
          "reasonFormHttpVerbose",
          "Any information entered (passwords, emails, credit cards) can be read by anyone monitoring the network!",
        ),
      });
      score = Math.max(score, 2);
    }
    try {
      const actionUrl = new URL(action, window.location.origin);
      if (
        actionUrl.hostname !== window.location.hostname &&
        actionUrl.hostname !== ""
      ) {
        reasons.push({
          short: tmFormat(
            tmText(
              "reasonFormThirdPartyShort",
              "Form submits data to a third-party domain ({host}).",
            ),
            { host: actionUrl.hostname },
          ),
          verbose: tmText(
            "reasonFormThirdPartyVerbose",
            "This is highly suspicious for login forms and often indicates a phishing site designed to steal credentials.",
          ),
        });
        score = Math.max(score, 2);
      }
    } catch (err) { }
  }

  // ── 3. Password field ─────────────────────────────────────────────────────
  if (element.tagName === "INPUT" && element.type === "password") {
    const hostname = window.location.hostname;
    const isLocalDev = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "";
    if (window.location.protocol !== "https:" && !isLocalDev) {
      reasons.push({
        short: tmText(
          "reasonPasswordHttpShort",
          "Password input on an insecure HTTP page!",
        ),
        verbose: tmText(
          "reasonPasswordHttpVerbose",
          "Entering passwords on non-HTTPS connections is extremely dangerous — the password traverses the web completely unprotected.",
        ),
      });
      score = Math.max(score, 2);
    }
  }

  // ── 4. Iframe ─────────────────────────────────────────────────────────────
  if (element.tagName === "IFRAME") {
    reasons.push({
      short: tmText(
        "reasonIframeShort",
        "Embedded iframe — can hide phishing pages or malicious ads.",
      ),
      verbose: tmText(
        "reasonIframeVerbose",
        "Attackers use iframes to load invisible malicious ads or credential-stealing prompts onto a benign page.",
      ),
    });
    score = Math.max(score, 1);
  }

  // ── 5. Script tag ─────────────────────────────────────────────────────────
  if (element.tagName === "SCRIPT") {
    const src = element.getAttribute("src") || "";
    if (src) {
      try {
        const scriptUrl = new URL(src, window.location.origin);
        if (scriptUrl.hostname !== window.location.hostname) {
          reasons.push({
            short: tmFormat(
              tmText(
                "reasonExternalScriptShort",
                "External script loaded from {host}.",
              ),
              { host: scriptUrl.hostname },
            ),
            verbose: tmText(
              "reasonExternalScriptVerbose",
              "Third-party scripts have full access to this page and can steal cookies, hijack sessions, or log keystrokes.",
            ),
          });
          score = Math.max(score, 1);
        }
      } catch (e) { }
    } else {
      // Inline script — static flag
      reasons.push({
        short: tmText(
          "reasonInlineScriptShort",
          "Inline <script> tag — executes JavaScript directly on this page.",
        ),
        verbose: tmText(
          "reasonInlineScriptVerbose",
          "Inline scripts can indicate injected malicious code (XSS) designed to steal cookies or session tokens.",
        ),
      });
      score = Math.max(score, 1);

      // ── Hash Integrity Check (async) ────────────────────────────────────
      // Mark a placeholder so the tooltip can show a "Checking hash…" item.
      // The actual async result is posted back by updateHashResult() in ui.js.
      reasons.push({
        short: "🔐 Hash integrity: <em id='tm-hash-status'>computing SHA-256…</em>",
        isHashPlaceholder: true,
        scriptElement: element,
      });
    }
  }

  // ── 6. Base tag hijack ────────────────────────────────────────────────────
  if (element.tagName === "BASE") {
    const baseHref = element.getAttribute("href") || "";
    if (baseHref) {
      try {
        const baseUrl = new URL(baseHref, window.location.origin);
        if (baseUrl.hostname !== window.location.hostname) {
          reasons.push({
            short: tmFormat(
              tmText(
                "reasonBaseTagShort",
                "<base> tag redirects all relative URLs to {host}.",
              ),
              { host: baseUrl.hostname },
            ),
            verbose: tmText(
              "reasonBaseTagVerbose",
              "Every relative link and resource on the page resolves to that external domain — used to hijack navigation and steal credentials.",
            ),
          });
          score = Math.max(score, 2);
        }
      } catch (e) { }
    }
  }

  if (score === 0) return { status: "safe", analysis: reasons, previewUrl };
  if (score === 1) return { status: "warning", analysis: reasons, previewUrl };
  return { status: "danger", analysis: reasons, previewUrl };
}

// ── Public: scan element + nearest meaningful ancestor + direct children ───────
function analyzeElement(element) {
  const candidates = new Set();

  // 1. The element itself
  candidates.add(element);

  // 2. Walk UP — find NEAREST <a> or <form> wrapping the hovered element.
  //    Stop as soon as one is found (don't accumulate all 5 levels).
  let ancestor = element.parentElement;
  while (ancestor && ancestor !== document.body) {
    const tag = ancestor.tagName;
    if (tag === "A" || tag === "FORM") {
      candidates.add(ancestor);
      break; // Stop at first meaningful ancestor
    }
    ancestor = ancestor.parentElement;
  }

  // 3. Walk DOWN — only DIRECT children (not deep descendants).
  //    This catches an <a> immediately inside a hovered button/div.
  for (const child of element.children) {
    const tag = child.tagName;
    if (
      tag === "A" ||
      tag === "FORM" ||
      tag === "IFRAME" ||
      tag === "SCRIPT" ||
      tag === "BASE" ||
      (tag === "INPUT" && child.type === "password")
    ) {
      candidates.add(child);
    }
  }

  // 4. Analyse each candidate, merge and prioritise worst threat
  let bestScore = 0;
  let bestReasons = [];
  let bestPreviewUrl = null;

  for (const el of candidates) {
    const result = _analyseSingle(el);
    const s = result.status === "danger" ? 2 : result.status === "warning" ? 1 : 0;
    if (s > bestScore) {
      bestScore = s;
      bestReasons = result.analysis;
      bestPreviewUrl = result.previewUrl;
    } else if (s === bestScore && result.analysis.length > bestReasons.length) {
      bestReasons = result.analysis;
      if (result.previewUrl) bestPreviewUrl = result.previewUrl;
    }
  }

  if (bestScore === 0) return { status: "safe", analysis: bestReasons, previewUrl: bestPreviewUrl };
  if (bestScore === 1) return { status: "warning", analysis: bestReasons, previewUrl: bestPreviewUrl };
  return { status: "danger", analysis: bestReasons, previewUrl: bestPreviewUrl };
}

// Scans all meaningful elements on the page and returns a summary.
function scanEntirePage() {
  const elements = document.querySelectorAll(
    'a[href], form, iframe, input[type="password"], script, base',
  );
  let danger = 0,
    warning = 0,
    safe = 0;
  elements.forEach((el) => {
    const result = _analyseSingle(el);
    if (result.status === "danger") danger++;
    else if (result.status === "warning") warning++;
    else safe++;
  });
  return { total: elements.length, danger, warning, safe };
}
