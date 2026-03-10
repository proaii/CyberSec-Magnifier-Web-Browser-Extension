document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("toggleBtn");
  const advancedToggle = document.getElementById("advancedToggle");
  const blockDangerToggle = document.getElementById("blockDangerToggle");
  const apiInput = document.getElementById("vtApiKey");
  const saveApiBtn = document.getElementById("saveApiBtn");

  // Load current state from browser storage
  chrome.storage.local.get(
    ["isActive", "advancedMode", "vtApiKey", "blockDangerLinks"],
    (result) => {
      let active = !!result.isActive;
      updateUI(active);

      advancedToggle.checked = !!result.advancedMode;
      blockDangerToggle.checked = result.blockDangerLinks !== false; // default on
      if (result.vtApiKey) {
        apiInput.value = result.vtApiKey;
        saveApiBtn.textContent = "Saved";
      }
    },
  );

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
      let active = !result.isActive;
      chrome.storage.local.set({ isActive: active }, () => {
        updateUI(active);
        notifyContentScripts({ isActive: active });
      });
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
      saveApiBtn.textContent = "Saved";
      notifyContentScripts({ vtApiKey: key });
      setTimeout(() => {
        saveApiBtn.textContent = "Save Key";
      }, 2000);
    });
  });

  // Reset button text on typing
  apiInput.addEventListener("input", () => {
    saveApiBtn.textContent = "Save Key";
  });

  function updateUI(active) {
    if (active) {
      btn.textContent = "Stop Magnifier";
      btn.classList.add("active");
    } else {
      btn.textContent = "Start Magnifier";
      btn.classList.remove("active");
    }
  }
});
