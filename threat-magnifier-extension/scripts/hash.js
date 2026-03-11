// =============================================================================
// hash.js — SHA-256 Script Integrity Checker
// Uses the browser's built-in Web Crypto API (no external dependencies).
// Provides:
//   hashString(str)        → Promise<hex string>   — SHA-256 of any string
//   KNOWN_MALICIOUS_HASHES — Map<hex, description> — pre-registered bad hashes
//   checkScriptHash(el)    → Promise<result>        — checks an inline <script>
// =============================================================================

/**
 * Computes the SHA-256 hash of a plain string using the Web Crypto API.
 * @param {string} str - Input string to hash
 * @returns {Promise<string>} - Hex-encoded SHA-256 digest
 */
async function hashString(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    // Convert the ArrayBuffer to a hex string
    return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

// ── Known Malicious Hash Database ─────────────────────────────────────────────
// Maps SHA-256 hex digest → human-readable threat description.
// In a real deployment this would be fetched from a threat-intel feed.
// These hashes correspond exactly to the mock payloads in the test site's
// Section 4 (Hashing Integrity Check Demo).
const KNOWN_MALICIOUS_HASHES = new Map([
    [
        // SHA-256 of mock keylogger payload (index.html Section 4)
        "70caf0fe6a406ade99fa4e4286caf26e7ef690f8c3563ddfc8fe3877570f5bad",
        "Mock Keylogger — exfiltrates keystrokes via fetch()",
    ],
    [
        // SHA-256 of mock crypto-miner payload (index.html Section 4)
        "cebad64f25e575de501e4d7bf56739cf03a3bb268a87d5a220b26f35527ea8d8",
        "Mock Cryptominer — WebSocket connection to mining pool",
    ],
    [
        // SHA-256 of mock XSS beacon payload (index.html Section 4)
        "1540f74c7b9b10ca0805abbb2d1ac2c669be1e87fcba4c488f1875fdb5ce982d",
        "Mock XSS Beacon — leaks cookies + URL to remote attacker",
    ],
]);

// ── Public checker ─────────────────────────────────────────────────────────────
/**
 * Computes the SHA-256 of an inline <script> element's text content and
 * checks it against the known-malicious hash database.
 *
 * @param {HTMLScriptElement} scriptElement
 * @returns {Promise<{matched: boolean, description: string|null, hash: string}>}
 */
async function checkScriptHash(scriptElement) {
    try {
        const content = (scriptElement.textContent || "").trim();
        if (!content) {
            return { matched: false, description: null, hash: "" };
        }
        const hash = await hashString(content);
        if (KNOWN_MALICIOUS_HASHES.has(hash)) {
            return {
                matched: true,
                description: KNOWN_MALICIOUS_HASHES.get(hash),
                hash,
            };
        }
        return { matched: false, description: null, hash };
    } catch (err) {
        // crypto.subtle unavailable or other error — fail gracefully
        return { matched: false, description: null, hash: "", error: err.message };
    }
}
