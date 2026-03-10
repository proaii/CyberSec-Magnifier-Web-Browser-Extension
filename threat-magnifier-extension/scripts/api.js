// =============================================================================
// api.js — VirusTotal API Integration
// Depends on globals in content.js : vtApiKey
// Depends on globals in ui.js      : currentHoverTarget
// =============================================================================

async function fetchVirusTotalScore(
  url,
  containerId,
  tipElement,
  currentStatus,
) {
  try {
    // VT API v3: identify a URL by its base64url-encoded form
    const urlId = btoa(url)
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    const response = await fetch(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
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

    if (response.ok) {
      const data = await response.json();
      const stats = data.data.attributes.last_analysis_stats;
      const malicious = stats.malicious;
      const suspicious = stats.suspicious;
      const total = malicious + suspicious + stats.harmless + stats.undetected;

      if (malicious > 0) {
        container.innerHTML = `<strong>${tmFormat(tmText("vtMalicious", "VirusTotal: {count} malicious vendors found! ({ratio})"), {
          count: malicious,
          ratio: `${malicious}/${total}`,
        })}</strong>`;
        if (currentStatus !== "danger") {
          tipElement.className = "status-danger";
          tipElement.querySelector("strong").textContent = `${tmText("statusTitle", "Status")}: ${tmStatusLabel("danger")}`;
          if (currentHoverTarget) {
            currentHoverTarget.classList.remove(
              "threat-magnifier-highlight-warning",
              "threat-magnifier-highlight-safe",
            );
            currentHoverTarget.classList.add(
              "threat-magnifier-highlight-danger",
            );
          }
        }
      } else if (suspicious > 0) {
        container.innerHTML = `<strong>${tmFormat(tmText("vtSuspicious", "VirusTotal: {count} suspicious reports. ({ratio})"), {
          count: suspicious,
          ratio: `${suspicious}/${total}`,
        })}</strong>`;
        if (currentStatus === "safe") {
          tipElement.className = "status-warning";
          tipElement.querySelector("strong").textContent = `${tmText("statusTitle", "Status")}: ${tmStatusLabel("warning")}`;
          if (currentHoverTarget) {
            currentHoverTarget.classList.remove(
              "threat-magnifier-highlight-safe",
            );
            currentHoverTarget.classList.add(
              "threat-magnifier-highlight-warning",
            );
          }
        }
      } else {
        container.innerHTML = tmFormat(
          tmText("vtClean", "VirusTotal: Clean ({count} vendors say harmless)"),
          { count: stats.harmless },
        );
      }
    } else if (response.status === 404) {
      container.innerHTML = tmText(
        "vtNoData",
        "VirusTotal: No scan data available for this specific URL.",
      );
    } else if (response.status === 401 || response.status === 403) {
      container.innerHTML = tmText(
        "vtInvalidKey",
        "VirusTotal: Invalid API Key or Quota Exceeded.",
      );
    } else {
      container.innerHTML = tmFormat(
        tmText("vtCheckFailed", "VirusTotal: Check failed (Status {status})."),
        { status: response.status },
      );
    }
  } catch (e) {
    const container = document.getElementById(containerId);
    if (container) container.innerHTML = tmText("vtConnectFailed", "VirusTotal check failed to connect.");
  }
}
