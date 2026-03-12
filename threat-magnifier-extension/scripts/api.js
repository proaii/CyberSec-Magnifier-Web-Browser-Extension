// =============================================================================
// api.js — VirusTotal API Integration
// Queries VirusTotal's Search endpoint (GET /api/v3/search) to look up URLs.
// Depends on globals in content.js : vtApiKey
// Depends on globals in ui.js      : currentHoverTarget
// =============================================================================

async function fetchVirusTotalScore(url, containerId, tipElement, currentStatus) {
  try {
    // Query VirusTotal Search API with the URL
    const response = await fetch(
      `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(url)}&limit=5`,
      {
        method: "GET",
        headers: {
          accept: "application/json",
          "x-apikey": vtApiKey,
        },
      },
    );

    const container = document.getElementById(containerId);
    if (!container) return; // Tooltip closed before response arrived

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        container.innerHTML = tmText("vtInvalidKey", "VirusTotal: Invalid API Key or Quota Exceeded.");
      } else if (response.status === 404) {
        container.innerHTML = tmText("vtNoData", "VirusTotal: No scan data available for this URL.");
      } else {
        container.innerHTML = tmFormat(
          tmText("vtCheckFailed", "VirusTotal: Check failed (Status {status})."),
          { status: response.status },
        );
      }
      return;
    }

    const data = await response.json();
    const items = data.data;

    // Search returns an array; find the first URL-type result
    const urlResult = items && items.find(i => i.type === "url");

    if (!urlResult) {
      // URL has not been scanned by VirusTotal yet
      container.innerHTML = tmText("vtNoData", "VirusTotal: URL not in database yet. Visit VirusTotal to scan it.");
      return;
    }

    const stats = urlResult.attributes.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);

    if (malicious > 0) {
      container.innerHTML = `<strong>${tmFormat(
        tmText("vtMalicious", "VirusTotal: {count} malicious vendors found! ({ratio})"),
        { count: malicious, ratio: `${malicious}/${total}` },
      )}</strong>`;
      if (currentStatus !== "danger") {
        tipElement.className = "status-danger";
        tipElement.querySelector("strong").textContent =
          `${tmText("statusTitle", "Status")}: ${tmStatusLabel("danger")}`;
        if (currentHoverTarget) {
          currentHoverTarget.classList.remove(
            "threat-magnifier-highlight-warning",
            "threat-magnifier-highlight-safe",
          );
          currentHoverTarget.classList.add("threat-magnifier-highlight-danger");

          if (typeof attachBlocker === "function") {
            attachBlocker(currentHoverTarget);
          }
        }
      }
    } else if (suspicious > 0) {
      container.innerHTML = `<strong>${tmFormat(
        tmText("vtSuspicious", "VirusTotal: {count} suspicious reports. ({ratio})"),
        { count: suspicious, ratio: `${suspicious}/${total}` },
      )}</strong>`;
      if (currentStatus === "safe") {
        tipElement.className = "status-warning";
        tipElement.querySelector("strong").textContent =
          `${tmText("statusTitle", "Status")}: ${tmStatusLabel("warning")}`;
        if (currentHoverTarget) {
          currentHoverTarget.classList.remove("threat-magnifier-highlight-safe");
          currentHoverTarget.classList.add("threat-magnifier-highlight-warning");
        }
      }
    } else {
      container.innerHTML = tmFormat(
        tmText("vtClean", "VirusTotal: Clean ({count} vendors say harmless)"),
        { count: stats.harmless || 0 },
      );
    }
  } catch (e) {
    const container = document.getElementById(containerId);
    if (container) container.innerHTML = tmText("vtConnectFailed", "VirusTotal check failed to connect.");
  }
}
