document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('toggleBtn');
    const previewToggle = document.getElementById('previewToggle');
    const verboseToggle = document.getElementById('verboseToggle');

    // Load current state from browser storage
    chrome.storage.local.get(['isActive', 'showPreviews', 'verboseMode'], (result) => {
        let active = !!result.isActive;
        updateUI(active);

        previewToggle.checked = !!result.showPreviews;
        verboseToggle.checked = !!result.verboseMode;
    });

    // Notify content scripts of changes
    function notifyContentScripts(stateUpdate) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, { action: "updateState", state: stateUpdate });
            }
        });
    }

    // Toggle logic for Main Button
    btn.addEventListener('click', () => {
        chrome.storage.local.get(['isActive'], (result) => {
            let active = !result.isActive;
            chrome.storage.local.set({ isActive: active }, () => {
                updateUI(active);
                notifyContentScripts({ isActive: active });
            });
        });
    });

    // Toggle logic for options
    previewToggle.addEventListener('change', (e) => {
        chrome.storage.local.set({ showPreviews: e.target.checked }, () => {
            notifyContentScripts({ showPreviews: e.target.checked });
        });
    });

    verboseToggle.addEventListener('change', (e) => {
        chrome.storage.local.set({ verboseMode: e.target.checked }, () => {
            notifyContentScripts({ verboseMode: e.target.checked });
        });
    });

    function updateUI(active) {
        if (active) {
            btn.textContent = "Stop Magnifier";
            btn.classList.add('active');
        } else {
            btn.textContent = "Start Magnifier";
            btn.classList.remove('active');
        }
    }
});
