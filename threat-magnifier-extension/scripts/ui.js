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

function showBlockWarning(anchor) {
  removeBlockWarning();
  const banner = document.createElement("div");
  banner.id = "threat-magnifier-block-warning";
  banner.innerHTML =
    "<strong>\u26A0\uFE0F Threat Magnifier blocked this link!</strong>" +
    "<span>This link was classified as <em>dangerous</em>. Click \u201COpen Anyway\u201D if you trust it.</span>" +
    '<div class="tm-block-actions">' +
    '<button id="tm-block-dismiss">OK</button>' +
    '<button id="tm-block-proceed">Open Anyway</button>' +
    "</div>";
  document.body.appendChild(banner);

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
    tip.classList.add("minimal-mode");
    tip.innerHTML = "";
    tip.style.display = "block";
  } else {
    tip.classList.remove("minimal-mode");

    // Build analysis list
    let html = `<strong>Status: ${status.toUpperCase()}</strong><ul>`;
    analysis.forEach((item) => {
      html += `<li>${item.short || item}</li>`;
    });

    // VirusTotal inline result placeholder
    const vtContainerId = `vt-result-${Date.now()}`;
    if (urlPreview && vtApiKey) {
      html += `<li id="${vtContainerId}"><em>Fetching VirusTotal report...</em></li>`;
    } else if (urlPreview && !vtApiKey) {
      html += `<li><em>VirusTotal API key missing. Add it in options to score this link.</em></li>`;
    }

    if (analysis.length === 0) {
      html += `<li>Looks safe. No obvious structural threats detected.</li>`;
    }
    html += `</ul>`;

    // Quick "Check on VirusTotal" link
    if (urlPreview) {
      try {
        new URL(urlPreview);
        const vtUrl =
          "https://www.virustotal.com/gui/search/" +
          encodeURIComponent(urlPreview);
        html += `<a class="vt-link" href="${vtUrl}" target="_blank" rel="noopener noreferrer">🔍 Check on VirusTotal ↗</a>`;
      } catch (ex) {}
    }

    // Website preview iframe
    if (urlPreview) {
      try {
        new URL(urlPreview);
        html += `<div class="preview-container">
                            <span class="preview-label">Website Preview:</span>
                            <iframe class="preview-iframe" src="${urlPreview}" sandbox=""></iframe>
                         </div>`;
      } catch (ex) {}
    }

    tip.innerHTML = html;
    tip.style.display = "block";

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
