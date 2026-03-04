let isActive = false;
let showPreviews = false;
let verboseMode = false;
let tooltip = null;

// Initialize state from storage when the script loads
chrome.storage.local.get(['isActive', 'showPreviews', 'verboseMode'], (result) => {
    isActive = !!result.isActive;
    showPreviews = !!result.showPreviews;
    verboseMode = !!result.verboseMode;
    if (isActive) {
        enableMagnifier();
    }
});

// Listen for updates from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "updateState") {
        if (message.state.isActive !== undefined) {
            isActive = message.state.isActive;
            if (isActive) enableMagnifier();
            else disableMagnifier();
        }
        if (message.state.showPreviews !== undefined) {
            showPreviews = message.state.showPreviews;
        }
        if (message.state.verboseMode !== undefined) {
            verboseMode = message.state.verboseMode;
        }
    }
});

function createTooltip() {
    if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.id = 'threat-magnifier-tooltip';
        document.body.appendChild(tooltip);
    }
    return tooltip;
}

function updateTooltip(e, status, analysis, urlPreview) {
    if (!isActive) return;

    const tip = createTooltip();

    // Clear old classes and add new status class for styling
    tip.className = 'status-' + status;

    // Build HTML content for the magnifying glass tooltip
    let html = `<strong>Status: ${status.toUpperCase()}</strong><ul>`;
    analysis.forEach(item => {
        // item can be a string or an object { short, verbose }
        let msg = (verboseMode && item.verbose) ? item.verbose : (item.short || item);
        html += `<li>${msg}</li>`;
    });
    if (analysis.length === 0) {
        let safeMsg = verboseMode ? "Looks safe. We couldn't find any obvious structural threats like hidden iframes, cross-origin forms, or dangerous inline scripts." : "Looks safe. No obvious structural threats detected.";
        html += `<li>${safeMsg}</li>`;
    }
    html += `</ul>`;

    // Add iframe preview if enabled and url is provided
    if (showPreviews && urlPreview) {
        // ensure urlPreview is a full URL
        try {
            new URL(urlPreview);
            html += `<div class="preview-container">
                        <span class="preview-label">Website Preview:</span>
                        <iframe class="preview-iframe" src="${urlPreview}" sandbox=""></iframe>
                    </div>`;
        } catch (e) { }
    }

    tip.innerHTML = html;
    tip.style.display = 'block';

    // Position tooltip near the mouse pointer
    const offset = 15;
    let leftPos = e.clientX + offset;
    let topPos = e.clientY + offset;

    if (leftPos + tip.offsetWidth > window.innerWidth) {
        leftPos = e.clientX - tip.offsetWidth - offset;
    }
    if (topPos + tip.offsetHeight > window.innerHeight) {
        topPos = e.clientY - tip.offsetHeight - offset;
    }

    tip.style.left = leftPos + 'px';
    tip.style.top = topPos + 'px';
}

function analyzeElement(element) {
    let reasons = [];
    let score = 0; // 0 = safe, 1 = warning, 2 = danger
    let previewUrl = null;

    // 1. Link Check
    if (element.tagName === 'A') {
        const href = element.getAttribute('href') || '';
        previewUrl = element.href; // absolute URL

        if (href.startsWith('javascript:')) {
            reasons.push({
                short: 'Contains inline JavaScript execution in link.',
                verbose: 'Contains inline JavaScript execution in link. Inline JS (`javascript:`) can be used by attackers to run malicious scripts (XSS) when you click the link.'
            });
            score = Math.max(score, 2);
            previewUrl = null; // Do not preview javascript links
        } else if (href.startsWith('http://')) {
            reasons.push({
                short: 'Link uses insecure HTTP protocol.',
                verbose: 'Link uses insecure HTTP protocol (not HTTPS). Data sent over this connection is unencrypted and can be intercepted by third parties.'
            });
            score = Math.max(score, 1);
        }

        try {
            const url = new URL(href, window.location.origin);
            if (url.hostname !== window.location.hostname && href.startsWith('http')) {
                reasons.push({
                    short: `External link (goes to: ${url.hostname}).`,
                    verbose: `External link (goes to: ${url.hostname}). Be careful clicking links that take you away from the current website, as they could be phishing attempts pretending to be familiar services.`
                });
                score = Math.max(score, 1);
            }
        } catch (err) { }

        // Hidden links
        const style = window.getComputedStyle(element);
        if (style.display === 'none' || style.visibility === 'hidden') {
            reasons.push({
                short: 'Link is hidden, could be an invisible trap.',
                verbose: 'Link is completely hidden from view using CSS (`display: none` or `visibility: hidden`). Attackers often hide links to manipulate search engine rankings or overlay invisible links over buttons you trust to steal clicks.'
            });
            score = Math.max(score, 2);
            previewUrl = null; // Do not preview hidden trap links
        }
    }

    // 2. Forms
    const form = element.closest('form');
    if (form) {
        const action = form.getAttribute('action') || '';
        if (action.startsWith('http://')) {
            reasons.push({
                short: 'Form submits data insecurely (HTTP).',
                verbose: 'Form submits data insecurely via HTTP. Any information you put into this form (passwords, emails, credit cards) can be read by anyone monitoring the network!'
            });
            score = Math.max(score, 2);
        }
        try {
            const actionUrl = new URL(action, window.location.origin);
            if (actionUrl.hostname !== window.location.hostname && actionUrl.hostname !== '') {
                reasons.push({
                    short: `Form submits data to a third-party domain (${actionUrl.hostname}).`,
                    verbose: `Form submits your data directly to a third-party domain (${actionUrl.hostname}). This is highly suspicious behavior for login forms and often indicates a phishing site designed to steal credentials.`
                });
                score = Math.max(score, 2);
            }
        } catch (err) { }
    }

    // 3. Password field
    if (element.tagName === 'INPUT' && element.type === 'password') {
        if (window.location.protocol !== 'https:') {
            reasons.push({
                short: 'Password input on an insecure HTTP page!',
                verbose: 'Password input found on an HTTP page. Entering passwords on non-HTTPS connections is extremely dangerous, as the password traverses the web completely unprotected.'
            });
            score = Math.max(score, 2);
        }
    }

    // 4. iframes
    if (element.tagName === 'IFRAME') {
        reasons.push({
            short: 'Embedded elements (iframes) can hide phishing pages or malicious ads.',
            verbose: 'Embedded iframe detected. Iframes let a website load another webpage inside of it. While common for YouTube videos, attackers use them to securely load invisible malicious ads or credential-stealing prompts onto a benign page.'
        });
        score = Math.max(score, 1);
    }

    if (score === 0) return { status: 'safe', analysis: reasons, previewUrl };
    if (score === 1) return { status: 'warning', analysis: reasons, previewUrl };
    return { status: 'danger', analysis: reasons, previewUrl };
}

let currentHoverTarget = null;

function optimizedHandleMouseOver(e) {
    if (!isActive) return;
    const target = e.target;
    if (target.closest('#threat-magnifier-tooltip')) return;

    if (currentHoverTarget !== target) {
        currentHoverTarget = target;
        const result = analyzeElement(target);
        target.classList.add(`threat-magnifier-highlight-${result.status}`);
        updateTooltip(e, result.status, result.analysis, result.previewUrl);
    }
}

function optimizedHandleMouseMove(e) {
    if (!isActive || !tooltip || tooltip.style.display === 'none') return;

    const offset = 15;
    let leftPos = e.clientX + offset;
    let topPos = e.clientY + offset;

    if (leftPos + tooltip.offsetWidth > window.innerWidth) {
        leftPos = e.clientX - tooltip.offsetWidth - offset;
    }
    if (topPos + tooltip.offsetHeight > window.innerHeight) {
        topPos = e.clientY - tooltip.offsetHeight - offset;
    }

    tooltip.style.left = leftPos + 'px';
    tooltip.style.top = topPos + 'px';
}

function optimizedHandleMouseOut(e) {
    if (!isActive) return;
    const target = e.target;

    target.classList.remove('threat-magnifier-highlight-safe');
    target.classList.remove('threat-magnifier-highlight-warning');
    target.classList.remove('threat-magnifier-highlight-danger');

    // If moving into the tooltip itself, don't hide it
    if (e.relatedTarget && e.relatedTarget.closest('#threat-magnifier-tooltip')) {
        return;
    }

    if (tooltip) {
        currentHoverTarget = null;
        tooltip.style.display = 'none';
        tooltip.innerHTML = ''; // Clear iframe to prevent it from loading in background
    }
}

function enableMagnifier() {
    document.addEventListener('mouseover', optimizedHandleMouseOver);
    document.addEventListener('mouseout', optimizedHandleMouseOut);
    document.addEventListener('mousemove', optimizedHandleMouseMove);
}

function disableMagnifier() {
    document.removeEventListener('mouseover', optimizedHandleMouseOver);
    document.removeEventListener('mouseout', optimizedHandleMouseOut);
    document.removeEventListener('mousemove', optimizedHandleMouseMove);

    // Cleanup any lingering tooltip or classes
    if (tooltip) {
        tooltip.style.display = 'none';
        tooltip.innerHTML = ''; // Clear iframe to prevent it from loading in background
    }

    const highlighted = document.querySelectorAll('[class*="threat-magnifier-highlight"]');
    highlighted.forEach(el => {
        el.classList.remove('threat-magnifier-highlight-safe');
        el.classList.remove('threat-magnifier-highlight-warning');
        el.classList.remove('threat-magnifier-highlight-danger');
    });
}
