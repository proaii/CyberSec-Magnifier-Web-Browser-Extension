document.addEventListener("DOMContentLoaded", () => {
    const SUPPORTED_LANGUAGES = ["en", "th"];
    const i18n = window.ThreatMagnifierI18n;
    const btn = document.getElementById("toggleBtn");
    const advancedToggle = document.getElementById("advancedToggle");
    const blockDangerToggle = document.getElementById("blockDangerToggle");
    const apiInput = document.getElementById("vtApiKey");
    const saveApiBtn = document.getElementById("saveApiBtn");
    const languageToggle = document.getElementById("languageToggle");
    const titleText = document.getElementById("titleText");
    const descText = document.getElementById("descText");
    const advancedLabel = document.getElementById("advancedLabel");
    const advancedDesc = document.getElementById("advancedDesc");
    const blockDangerLabel = document.getElementById("blockDangerLabel");
    const blockDangerDesc = document.getElementById("blockDangerDesc");
    const apiLabel = document.getElementById("apiLabel");
    const apiDesc = document.getElementById("apiDesc");
    let currentLanguage = "en";
    let isActive = false;
    const locales = {};

    function t() {
        return (locales[currentLanguage] && locales[currentLanguage].popup) || {};
    }

    function renderTexts() {
        const text = t();
        titleText.textContent = text.title || "Threat Magnifier 2.0";
        descText.textContent = text.description || "What a Sigma Tool!";
        advancedLabel.textContent = text.advancedLabel || "Advanced Option";
        advancedDesc.textContent =
            text.advancedDesc ||
            "Shows detailed threat analysis and website previews. If disabled, only a color flag is shown.";
        blockDangerLabel.textContent = text.blockDangerLabel || "Block Dangerous Links";
        blockDangerDesc.textContent =
            text.blockDangerDesc ||
            "Prevents clicking links classified as dangerous. A warning will appear with an option to proceed anyway.";
        apiLabel.textContent = text.apiLabel || "VirusTotal API Key (Optional)";
        apiDesc.textContent =
            text.apiDesc || "Used to score external links in Advanced Mode.";
        apiInput.placeholder = text.apiPlaceholder || "Enter API Key here...";
        if (saveApiBtn.dataset.state === "saved") {
            saveApiBtn.textContent = text.saved || "Saved";
        } else {
            saveApiBtn.textContent = text.saveKey || "Save Key";
        }
    }

    async function init() {
        await i18n.preloadLocales(SUPPORTED_LANGUAGES, locales);
        chrome.storage.local.get(
            ["isActive", "advancedMode", "vtApiKey", "blockDangerLinks", "selectedLanguage"],
            (result) => {
                isActive = !!result.isActive;
                currentLanguage = i18n.normalizeLanguage(result.selectedLanguage);
                languageToggle.checked = currentLanguage === "en";
                renderTexts();
                updateUI(isActive);

                advancedToggle.checked = !!result.advancedMode;
                blockDangerToggle.checked = result.blockDangerLinks !== false; // default on
                if (result.vtApiKey) {
                    apiInput.value = result.vtApiKey;
                    saveApiBtn.dataset.state = "saved";
                    saveApiBtn.textContent = t().saved || "Saved";
                }
            },
        );
    }
    init();

    // Notify content scripts of changes
    function notifyContentScripts(stateUpdate) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, {
                    action: "updateState",
                    state: stateUpdate,
                });
            }
        });
    }

    // Toggle logic for Main Button
    btn.addEventListener("click", () => {
        chrome.storage.local.get(["isActive"], (result) => {
            isActive = !result.isActive;
            chrome.storage.local.set({ isActive: isActive }, () => {
                updateUI(isActive);
                notifyContentScripts({ isActive: isActive });
            });
        });
    });

    languageToggle.addEventListener("change", (e) => {
        currentLanguage = i18n.normalizeLanguage(e.target.checked ? "en" : "th");
        renderTexts();
        updateUI(isActive);
        chrome.storage.local.set({ selectedLanguage: currentLanguage }, () => {
            notifyContentScripts({ selectedLanguage: currentLanguage });
        });
    });

    // Toggle logic for Advanced Option
    advancedToggle.addEventListener("change", (e) => {
        chrome.storage.local.set({ advancedMode: e.target.checked }, () => {
            notifyContentScripts({ advancedMode: e.target.checked });
        });
    });

    // Toggle logic for Block Dangerous Links
    blockDangerToggle.addEventListener("change", (e) => {
        chrome.storage.local.set({ blockDangerLinks: e.target.checked }, () => {
            notifyContentScripts({ blockDangerLinks: e.target.checked });
        });
    });

    // Save API Key
    saveApiBtn.addEventListener("click", () => {
        const key = apiInput.value.trim();
        chrome.storage.local.set({ vtApiKey: key }, () => {
            saveApiBtn.dataset.state = "saved";
            saveApiBtn.textContent = t().saved || "Saved";
            notifyContentScripts({ vtApiKey: key });
            setTimeout(() => {
                saveApiBtn.dataset.state = "";
                saveApiBtn.textContent = t().saveKey || "Save Key";
            }, 2000);
        });
    });

    // Reset button text on typing
    apiInput.addEventListener("input", () => {
        saveApiBtn.dataset.state = "";
        saveApiBtn.textContent = t().saveKey || "Save Key";
    });

    function updateUI(active) {
        const text = t();
        if (active) {
            btn.textContent = text.stopButton || "Stop Magnifier";
            btn.classList.add("active");
        } else {
            btn.textContent = text.startButton || "Start Magnifier";
            btn.classList.remove("active");
        }
    }
});
