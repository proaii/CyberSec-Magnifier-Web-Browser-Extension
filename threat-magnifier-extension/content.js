// =============================================================================
// content.js — Entry Point
// Declares shared state and wires everything together.
// Load order: api.js → analyzer.js → ui.js → content.js  (see manifest.json)
//
// Why state lives here (loaded last):
//   Helper scripts only *define* functions; they never call them at load time.
//   By the time any function is first invoked (async storage callback or user
//   interaction), all four scripts are fully executed and these variables exist.
// =============================================================================

let isActive = false;
let advancedMode = false;
let vtApiKey = "";
let blockDangerLinks = true;

// ── Initialise from storage ───────────────────────────────────────────────────
chrome.storage.local.get(
  ["isActive", "advancedMode", "vtApiKey", "blockDangerLinks"],
  (result) => {
    isActive = !!result.isActive;
    advancedMode = !!result.advancedMode;
    vtApiKey = result.vtApiKey || "";
    blockDangerLinks = result.blockDangerLinks !== false; // default on
    if (isActive) enableMagnifier();
  },
);

// ── Message listener (from popup) ────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "updateState") {
    if (message.state.isActive !== undefined) {
      isActive = message.state.isActive;
      if (isActive) enableMagnifier();
      else disableMagnifier();
    }
    if (message.state.advancedMode !== undefined) {
      advancedMode = message.state.advancedMode;
      if (!advancedMode) {
        document
          .querySelectorAll('[class*="threat-magnifier-highlight"]')
          .forEach((el) => {
            el.classList.remove(
              "threat-magnifier-highlight-safe",
              "threat-magnifier-highlight-warning",
              "threat-magnifier-highlight-danger",
            );
          });
      }
    }
    if (message.state.vtApiKey !== undefined) {
      vtApiKey = message.state.vtApiKey;
    }
    if (message.state.blockDangerLinks !== undefined) {
      blockDangerLinks = message.state.blockDangerLinks;
    }
  }
  if (message.action === "scanPage") {
    sendResponse(scanEntirePage());
  }
});

// ── Enable / Disable ──────────────────────────────────────────────────────────
function enableMagnifier() {
  document.addEventListener("mouseover", optimizedHandleMouseOver);
  document.addEventListener("mouseout", optimizedHandleMouseOut);
  document.addEventListener("mousemove", optimizedHandleMouseMove);
}

function disableMagnifier() {
  document.removeEventListener("mouseover", optimizedHandleMouseOver);
  document.removeEventListener("mouseout", optimizedHandleMouseOut);
  document.removeEventListener("mousemove", optimizedHandleMouseMove);

  if (tooltip) {
    tooltip.style.display = "none";
    tooltip.innerHTML = "";
  }

  // Clean up blocked link listener
  if (blockedLink) {
    blockedLink.removeEventListener("click", blockDangerClick, true);
    blockedLink = null;
  }
  removeBlockWarning();

  document
    .querySelectorAll('[class*="threat-magnifier-highlight"]')
    .forEach((el) => {
      el.classList.remove(
        "threat-magnifier-highlight-safe",
        "threat-magnifier-highlight-warning",
        "threat-magnifier-highlight-danger",
      );
    });
}

// ── Keyboard shortcut: Alt+M ──────────────────────────────────────────────────
document.addEventListener("keydown", (e) => {
  if (e.altKey && (e.key === "m" || e.key === "M")) {
    isActive = !isActive;
    chrome.storage.local.set({ isActive });
    if (isActive) enableMagnifier();
    else disableMagnifier();
  }
});
