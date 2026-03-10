// =============================================================================
// analyzer.js — Element Threat Analysis
// Pure functions — no global state read at definition time, no DOM side-effects.
// =============================================================================

function analyzeElement(element) {
  let reasons = [];
  let score = 0; // 0 = safe | 1 = warning | 2 = danger
  let previewUrl = null;

  // ── 1. Link (<a>) ─────────────────────────────────────────────────────────
  if (element.tagName === "A") {
    const href = element.getAttribute("href") || "";
    previewUrl = element.href; // absolute URL

    // javascript: URI
    if (href.startsWith("javascript:")) {
      reasons.push({
        short: "Contains inline JavaScript execution in link.",
        verbose:
          "Inline JS (`javascript:`) can be used by attackers to run malicious scripts (XSS) when you click the link.",
      });
      score = Math.max(score, 2);
      previewUrl = null;

      // Plain HTTP
    } else if (href.startsWith("http://")) {
      reasons.push({
        short: "Link uses insecure HTTP protocol.",
        verbose:
          "Data sent over this connection is unencrypted and can be intercepted by third parties.",
      });
      score = Math.max(score, 1);
    }

    // Raw IP address
    if (/^https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(element.href)) {
      reasons.push({
        short: "Link points to a raw IP address instead of a domain name.",
        verbose:
          "Legitimate websites almost never use raw IPs for user-facing pages — a common phishing and malware hosting technique.",
      });
      score = Math.max(score, 2);
    }

    // Punycode / Homograph attack
    if (/xn--/.test(element.href)) {
      reasons.push({
        short:
          "Domain uses Punycode encoding (possible homograph/look-alike attack).",
        verbose:
          "e.g. xn--pple-43d.com can look identical to apple.com using Cyrillic characters. Attackers register visually identical domains to steal credentials.",
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
        short:
          "Link downloads a potentially dangerous executable or script file.",
        verbose:
          "This link points to a file with a dangerous extension (.exe, .bat, .ps1, .vbs, .msi, etc.) that could be malware or ransomware.",
      });
      score = Math.max(score, 2);
      previewUrl = null;
    }

    // Data URI
    if (href.startsWith("data:")) {
      reasons.push({
        short: "Link uses a Data URI — commonly used in phishing attacks.",
        verbose:
          "`data:` URIs can embed an entire web page in the URL. Attackers use them to create fake login pages that bypass domain-based security checks.",
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
          short: `External link (goes to: ${url.hostname}).`,
          verbose: `Be careful clicking links that take you away from the current website — they could be phishing attempts.`,
        });
        score = Math.max(score, 1);
      }
    } catch (err) {}

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
              short: `Domain contains "${brand}" but is not ${trueDomain} — possible brand spoofing.`,
              verbose: `Attackers register lookalike domains (e.g. paypal-secure.net) to impersonate trusted brands and steal credentials.`,
            });
            score = Math.max(score, 2);
            break;
          }
        }
      }
    } catch (e) {}

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
                short: `Possible open redirect — "${param}" parameter leads to ${redirectTarget.hostname}.`,
                verbose: `Attackers exploit open redirects to make malicious links appear to originate from a trusted site.`,
              });
              score = Math.max(score, 1);
            }
          } catch (e) {}
        }
      }
    } catch (e) {}

    // Missing rel="noopener" on target="_blank"
    if (element.target === "_blank") {
      const rel = element.getAttribute("rel") || "";
      if (!rel.includes("noopener") && !rel.includes("noreferrer")) {
        reasons.push({
          short:
            'Opens in new tab without rel="noopener" — risk of reverse tabnapping.',
          verbose:
            "The opened page can access window.opener and silently redirect this page to a phishing site (reverse tabnapping attack).",
        });
        score = Math.max(score, 1);
      }
    }

    // Hidden link (invisible trap)
    const style = window.getComputedStyle(element);
    if (style.display === "none" || style.visibility === "hidden") {
      reasons.push({
        short: "Link is hidden — could be an invisible trap.",
        verbose:
          "Attackers hide links to manipulate search rankings or overlay invisible links over trusted buttons to steal clicks.",
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
        short: "Form submits data insecurely (HTTP).",
        verbose:
          "Any information entered (passwords, emails, credit cards) can be read by anyone monitoring the network!",
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
          short: `Form submits data to a third-party domain (${actionUrl.hostname}).`,
          verbose: `This is highly suspicious for login forms and often indicates a phishing site designed to steal credentials.`,
        });
        score = Math.max(score, 2);
      }
    } catch (err) {}
  }

  // ── 3. Password field ─────────────────────────────────────────────────────
  if (element.tagName === "INPUT" && element.type === "password") {
    if (window.location.protocol !== "https:") {
      reasons.push({
        short: "Password input on an insecure HTTP page!",
        verbose:
          "Entering passwords on non-HTTPS connections is extremely dangerous — the password traverses the web completely unprotected.",
      });
      score = Math.max(score, 2);
    }
  }

  // ── 4. Iframe ─────────────────────────────────────────────────────────────
  if (element.tagName === "IFRAME") {
    reasons.push({
      short: "Embedded iframe — can hide phishing pages or malicious ads.",
      verbose:
        "Attackers use iframes to load invisible malicious ads or credential-stealing prompts onto a benign page.",
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
            short: `External script loaded from ${scriptUrl.hostname}.`,
            verbose: `Third-party scripts have full access to this page and can steal cookies, hijack sessions, or log keystrokes.`,
          });
          score = Math.max(score, 1);
        }
      } catch (e) {}
    } else {
      reasons.push({
        short:
          "Inline <script> tag — executes JavaScript directly on this page.",
        verbose:
          "Inline scripts can indicate injected malicious code (XSS) designed to steal cookies or session tokens.",
      });
      score = Math.max(score, 1);
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
            short: `<base> tag redirects all relative URLs to ${baseUrl.hostname}.`,
            verbose: `Every relative link and resource on the page resolves to that external domain — used to hijack navigation and steal credentials.`,
          });
          score = Math.max(score, 2);
        }
      } catch (e) {}
    }
  }

  if (score === 0) return { status: "safe", analysis: reasons, previewUrl };
  if (score === 1) return { status: "warning", analysis: reasons, previewUrl };
  return { status: "danger", analysis: reasons, previewUrl };
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
    const result = analyzeElement(el);
    if (result.status === "danger") danger++;
    else if (result.status === "warning") warning++;
    else safe++;
  });
  return { total: elements.length, danger, warning, safe };
}
