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
let selectedLanguage = "en";
const localeCache = {};
const i18n = self.ThreatMagnifierI18n;

function tmFormat(template, values) {
  if (!template) return "";
  return template.replace(/\{(\w+)\}/g, (_, key) => values[key] || "");
}

function tmText(key, fallback = "") {
  const locale = localeCache[selectedLanguage] || localeCache.en || {};
  const content = locale.content || {};
  return content[key] || fallback;
}

function tmStatusLabel(status) {
  if (status === "danger") return tmText("statusDanger", "DANGER");
  if (status === "warning") return tmText("statusWarning", "WARNING");
  return tmText("statusSafe", "SAFE");
}

function clearTransientUi() {
  currentHoverTarget = null;
  if (tooltip) {
    tooltip.style.display = "none";
    tooltip.innerHTML = "";
  }
  removeBlockWarning();
}

async function initLocaleAndState() {
  await i18n.preloadLocales(["en", "th"], localeCache);
  chrome.storage.local.get(
    ["isActive", "advancedMode", "vtApiKey", "blockDangerLinks", "selectedLanguage"],
    (result) => {
      isActive = !!result.isActive;
      advancedMode = !!result.advancedMode;
      vtApiKey = result.vtApiKey || "";
      blockDangerLinks = result.blockDangerLinks !== false; // default on
      selectedLanguage = i18n.normalizeLanguage(result.selectedLanguage);
      if (isActive) enableMagnifier();
    },
  );
}

// ── Initialise from storage ───────────────────────────────────────────────────
initLocaleAndState();

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local") return;
  if (changes.selectedLanguage) {
    selectedLanguage = i18n.normalizeLanguage(changes.selectedLanguage.newValue);
    clearTransientUi();
  }
});

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
    if (message.state.selectedLanguage !== undefined) {
      selectedLanguage = i18n.normalizeLanguage(message.state.selectedLanguage);
      clearTransientUi();
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
