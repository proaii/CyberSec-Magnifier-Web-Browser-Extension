// =============================================================================
// hash.js — SHA-256 Script Integrity Checker
// Uses the browser's built-in Web Crypto API (no external dependencies).
//
// Exports:
//   hashString(str)                – SHA-256 hash of any string
//   KNOWN_MALICIOUS_HASHES         – Map of known bad SHA-256 hashes
//   checkScriptHash(el)            – Checks inline <script> against the hash DB
//   fetchVirusTotalFileHash(...)   – Looks up a hash on VirusTotal's Files API
// =============================================================================

// Computes the SHA-256 hash of a plain string using the Web Crypto API.
// Returns a hex-encoded digest string (64 characters for SHA-256).
async function hashString(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    // Convert ArrayBuffer → hex string
    return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

// Known Malicious Hash Database
// Maps SHA-256 hex digest → { description, vtKnown }.
// vtKnown indicates whether VirusTotal has a file record for this hash.
const KNOWN_MALICIOUS_HASHES = new Map([
    [
        // EICAR Anti-Malware Test File (68-byte standard AV test string)
        // Every antivirus engine flags this hash as malicious.
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        {
            description: "EICAR Anti-Malware Test File — detected by all AV engines (VirusTotal: 60+ vendors)",
            vtKnown: true,
        },
    ],
]);

// Computes the SHA-256 of an inline <script> element's textContent and
// checks it against KNOWN_MALICIOUS_HASHES.
// Returns { matched, description, hash, vtKnown, error? }.
async function checkScriptHash(scriptElement) {
    try {
        const content = (scriptElement.textContent || "").trim();
        if (!content) {
            return { matched: false, description: null, hash: "", vtKnown: false };
        }
        const hash = await hashString(content);
        if (KNOWN_MALICIOUS_HASHES.has(hash)) {
            const info = KNOWN_MALICIOUS_HASHES.get(hash);
            return {
                matched: true,
                description: info.description,
                hash,
                vtKnown: info.vtKnown,
            };
        }
        return { matched: false, description: null, hash, vtKnown: false };
    } catch (err) {
        // crypto.subtle may be unavailable in insecure contexts (HTTP pages)
        return { matched: false, description: null, hash: "", vtKnown: false, error: err.message };
    }
}

// Looks up a file by its SHA-256 hash on VirusTotal (GET /api/v3/files/{hash}).
// Updates the specified <li> element with the scan results once the response arrives.
// If the file is flagged as malicious, upgrades the tooltip status to DANGER.
async function fetchVirusTotalFileHash(sha256, liId, tip, apiKey) {
    const li = document.getElementById(liId);
    if (!li) return;

    try {
        const res = await fetch(
            `https://www.virustotal.com/api/v3/files/${sha256}`,
            {
                method: "GET",
                headers: { accept: "application/json", "x-apikey": apiKey },
            }
        );

        // Re-fetch the element in case the tooltip was rebuilt while waiting
        const el = document.getElementById(liId);
        if (!el) return;

        if (res.ok) {
            const data = await res.json();
            const stats = data.data.attributes.last_analysis_stats;
            const mal = stats.malicious || 0;
            const sus = stats.suspicious || 0;
            const total = mal + sus + (stats.harmless || 0) + (stats.undetected || 0);

            el.innerHTML =
                `🛡️ <strong>VirusTotal File Scan: ${mal} / ${total} engines flagged as malicious</strong><br>` +
                `<span style="color:#e57373;font-size:11px;">` +
                `${mal} malicious, ${sus} suspicious out of ${total} vendors<br>` +
                `<a href="https://www.virustotal.com/gui/file/${sha256}" target="_blank" rel="noopener noreferrer" ` +
                `style="color:#90caf9;">🔗 View full VirusTotal report ↗</a></span>`;

            // Upgrade tooltip to DANGER if engines flagged the file
            if (tip && mal > 0) {
                tip.className = tip.className.replace(/status-\w+/, "status-danger");
                const strong = tip.querySelector("strong");
                if (strong && !strong.textContent.includes("DANGER")) {
                    strong.textContent = "Status: DANGER";
                }
            }
        } else if (res.status === 404) {
            el.innerHTML = "🛡️ VirusTotal: File not found in database.";
        } else if (res.status === 401 || res.status === 403) {
            el.innerHTML = "🛡️ VirusTotal: Invalid API key or quota exceeded.";
        } else {
            el.innerHTML = `🛡️ VirusTotal file lookup failed (HTTP ${res.status}).`;
        }
    } catch (err) {
        const el = document.getElementById(liId);
        if (el) el.innerHTML = "🛡️ VirusTotal file lookup could not connect.";
    }
}
