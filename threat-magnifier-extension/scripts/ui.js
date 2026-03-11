// =============================================================================
// ui.js — Tooltip UI & Mouse Event Handlers
// Depends on globals in content.js : isActive, advancedMode, vtApiKey
// Calls                            : analyzeElement (analyzer.js)
//                                    fetchVirusTotalScore (api.js)
// =============================================================================

let tooltip = null;
let currentHoverTarget = null;
let blockedLink = null;

// ── Danger link click blocker ─────────────────────────────────────────────────
function blockDangerClick(e) {
  e.preventDefault();
  e.stopImmediatePropagation();
  showBlockWarning(e.target.closest("a") || e.target);
}

let _bannerScrollHandler = null;

function showBlockWarning(anchor) {
  removeBlockWarning();
  const banner = document.createElement("div");
  banner.id = "threat-magnifier-block-warning";
  const title = tmText("blockedTitle", "Threat Magnifier blocked this link!");
  const desc = tmText(
    "blockedDesc",
    'This link was classified as dangerous. Click "Continue Anyway" if you trust it.',
  );
  const okText = tmText("blockOk", "Go Back");
  const proceedText = tmText("blockProceed", "Continue Anyway");
  banner.innerHTML =
    `<strong>\u26A0\uFE0F ${title}</strong>` +
    `<span>${desc}</span>` +
    '<div class="tm-block-actions">' +
    `<button id="tm-block-dismiss">${okText}</button>` +
    `<button id="tm-block-proceed">${proceedText}</button>` +
    "</div>";

  // Append to <html> to avoid transform inheritance from <body>
  document.documentElement.appendChild(banner);

  // Keep banner pinned 20px from viewport top even while scrolling
  function repositionBanner() {
    banner.style.top = (window.scrollY + 20) + "px";
  }
  repositionBanner();
  _bannerScrollHandler = repositionBanner;
  window.addEventListener("scroll", _bannerScrollHandler, { passive: true });

  document.getElementById("tm-block-dismiss").addEventListener("click", () => {
    removeBlockWarning();
  });
  document.getElementById("tm-block-proceed").addEventListener("click", () => {
    removeBlockWarning();
    // Temporarily remove blocker so the navigation goes through
    if (anchor) {
      anchor.removeEventListener("click", blockDangerClick, true);
      anchor.click();
      anchor.addEventListener("click", blockDangerClick, true);
    }
  });
}

function removeBlockWarning() {
  if (_bannerScrollHandler) {
    window.removeEventListener("scroll", _bannerScrollHandler);
    _bannerScrollHandler = null;
  }
  const existing = document.getElementById("threat-magnifier-block-warning");
  if (existing) existing.remove();
}

function createTooltip() {
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.id = "threat-magnifier-tooltip";
    document.body.appendChild(tooltip);
  }
  return tooltip;
}

function updateTooltip(e, status, analysis, urlPreview) {
  if (!isActive) return;

  const tip = createTooltip();
  tip.className = "status-" + status;

  if (!advancedMode) {
    if (status === "safe") {
      tip.style.display = "none";
      return;
    }
    tip.classList.add("minimal-mode");
    tip.innerHTML = "";
    tip.style.display = "block";
  } else {
    tip.classList.remove("minimal-mode");

    // Build analysis list
    const statusTitle = tmText("statusTitle", "Status");
    let html = `<strong>${statusTitle}: ${tmStatusLabel(status)}</strong><ul>`;

    // Collect any hash placeholder item (set by analyzer.js for inline scripts)
    let hashPlaceholder = null;
    const hashPlaceholderId = `tm-hash-li-${Date.now()}`;

    analysis.forEach((item) => {
      if (item && item.isHashPlaceholder) {
        // Render a uniquely-IDed <li> we can update after async hash check
        hashPlaceholder = item;
        html += `<li id="${hashPlaceholderId}">🔐 Hash integrity: <em>computing SHA-256…</em></li>`;
      } else {
        html += `<li>${item.short || item}</li>`;
      }
    });

    // VirusTotal inline result placeholder
    const vtContainerId = `vt-result-${Date.now()}`;
    if (urlPreview && vtApiKey) {
      html += `<li id="${vtContainerId}"><em>${tmText("vtFetching", "Fetching VirusTotal report...")}</em></li>`;
    } else if (urlPreview && !vtApiKey) {
      html += `<li><em>${tmText("vtKeyMissing", "VirusTotal API key missing. Add it in options to score this link.")}</em></li>`;
    }

    // Count real (non-placeholder) items to decide if we need the 'Looks safe' fallback
    const realItemCount = analysis.filter(i => !i.isHashPlaceholder).length;
    if (realItemCount === 0) {
      html += `<li>${tmText("safeNoThreat", "Looks safe. No obvious structural threats detected.")}</li>`;
    }
    html += `</ul>`;

    // Quick "Check on VirusTotal" link
    if (urlPreview) {
      try {
        new URL(urlPreview);
        const vtUrl =
          "https://www.virustotal.com/gui/search/" +
          encodeURIComponent(urlPreview);
        html += `<a class="vt-link" href="${vtUrl}" target="_blank" rel="noopener noreferrer">🔍 ${tmText("vtCheckLink", "Check on VirusTotal")} ↗</a>`;
      } catch (ex) { }
    }

    // Website preview iframe
    if (urlPreview) {
      try {
        new URL(urlPreview);
        html += `<div class="preview-container">
                            <span class="preview-label">${tmText("websitePreview", "Website Preview:")}</span>
                            <div class="preview-iframe-wrapper">
                              <iframe class="preview-iframe" src="${urlPreview}" sandbox="allow-scripts allow-same-origin"></iframe>
                            </div>
                         </div>`;
      } catch (ex) { }
    }

    tip.innerHTML = html;
    tip.style.display = "block";

    // ── Async hash check ──────────────────────────────────────────────────
    if (hashPlaceholder && hashPlaceholder.scriptElement) {
      checkScriptHash(hashPlaceholder.scriptElement)
        .then((result) => { updateHashResult(hashPlaceholderId, result, tip, status); })
        .catch(() => {
          const li = document.getElementById(hashPlaceholderId);
          if (li) li.innerHTML = "⚠️ Hash check unavailable (crypto.subtle not accessible).";
        });
    }

    if (urlPreview && vtApiKey) {
      fetchVirusTotalScore(urlPreview, vtContainerId, tip, status);
    }
  }

  // Position tooltip near cursor
  const offset = 15;
  let leftPos = e.clientX + offset;
  let topPos = e.clientY + offset;

  if (leftPos + tip.offsetWidth > window.innerWidth)
    leftPos = e.clientX - tip.offsetWidth - offset;
  if (topPos + tip.offsetHeight > window.innerHeight)
    topPos = e.clientY - tip.offsetHeight - offset;

  tip.style.left = leftPos + "px";
  tip.style.top = topPos + "px";
}

// ── Hash result updater (called after async checkScriptHash resolves) ─────────
function updateHashResult(liId, result, tipElement, currentStatus) {
  const li = document.getElementById(liId);
  if (!li) return; // Tooltip closed before hash finished

  if (result.matched) {
    // Known malicious script hash detected!
    li.innerHTML =
      `\ud83d\udd34 <strong>Hash matched known malicious signature!</strong><br>` +
      `<span style="color:#e57373;font-size:11px;">` +
      `\u26a0\ufe0f ${result.description}</span><br>` +
      `<span style="color:#888;font-size:10px;font-family:monospace;word-break:break-all;">` +
      `SHA-256: ${result.hash}</span>`;

    // Upgrade tooltip to DANGER
    if (currentStatus !== "danger") {
      tipElement.className = "status-danger";
      const strong = tipElement.querySelector("strong");
      if (strong) strong.textContent = `Status: DANGER`;
    }
    // Re-highlight the hovered element
    if (currentHoverTarget) {
      currentHoverTarget.classList.remove(
        "threat-magnifier-highlight-safe",
        "threat-magnifier-highlight-warning",
      );
      currentHoverTarget.classList.add("threat-magnifier-highlight-danger");
    }
  } else {
    // No match — show the computed hash for transparency
    const shortHash = result.hash ? result.hash.substring(0, 16) + "\u2026" : "N/A";
    li.innerHTML =
      `\u2705 Hash integrity: <strong>No known malicious signature</strong><br>` +
      `<span style="color:#888;font-size:10px;font-family:monospace;">` +
      `SHA-256: ${shortHash}</span>`;
  }
}



function optimizedHandleMouseOver(e) {
  if (!isActive) return;
  const target = e.target;
  if (target.closest("#threat-magnifier-tooltip")) return;
  if (target.closest("#threat-magnifier-block-warning")) return;

  if (currentHoverTarget !== target) {
    currentHoverTarget = target;
    const result = analyzeElement(target);
    if (advancedMode) {
      target.classList.add(`threat-magnifier-highlight-${result.status}`);
    }
    updateTooltip(e, result.status, result.analysis, result.previewUrl);

    // Block clicks on danger links
    if (blockDangerLinks && result.status === "danger") {
      const anchor = target.tagName === "A" ? target : target.closest("a");
      if (anchor) {
        // Remove from previous blocked link first
        if (blockedLink && blockedLink !== anchor) {
          blockedLink.removeEventListener("click", blockDangerClick, true);
        }
        anchor.addEventListener("click", blockDangerClick, true);
        blockedLink = anchor;
      }
    }
  }
}

function optimizedHandleMouseMove(e) {
  if (!isActive || !tooltip || tooltip.style.display === "none") return;

  const offset = 15;
  let leftPos = e.clientX + offset;
  let topPos = e.clientY + offset;

  if (leftPos + tooltip.offsetWidth > window.innerWidth)
    leftPos = e.clientX - tooltip.offsetWidth - offset;
  if (topPos + tooltip.offsetHeight > window.innerHeight)
    topPos = e.clientY - tooltip.offsetHeight - offset;

  tooltip.style.left = leftPos + "px";
  tooltip.style.top = topPos + "px";
}

function optimizedHandleMouseOut(e) {
  if (!isActive) return;
  const target = e.target;

  target.classList.remove(
    "threat-magnifier-highlight-safe",
    "threat-magnifier-highlight-warning",
    "threat-magnifier-highlight-danger",
  );

  // Keep tooltip visible if mouse moves into it or block warning
  if (e.relatedTarget && e.relatedTarget.closest("#threat-magnifier-tooltip"))
    return;
  if (
    e.relatedTarget &&
    e.relatedTarget.closest("#threat-magnifier-block-warning")
  )
    return;

  if (tooltip) {
    currentHoverTarget = null;
    tooltip.style.display = "none";
    tooltip.innerHTML = ""; // Clear iframe to stop background loading
  }
}
