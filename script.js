// 1. SELECT UI MONITORS (DOM ELEMENTS)
const scanForm = document.getElementById("scanForm");
const targetIpInput = document.getElementById("targetIp");
const portRangeInput = document.getElementById("portRange");

// KPI Cards & Threat Assessment
const kpiTarget = document.getElementById("kpiTarget");
const kpiOpenPorts = document.getElementById("kpiOpenPorts");
const kpiService = document.getElementById("kpiService");
const threatText = document.getElementById("threatText");
const threatSegments = document.querySelectorAll(".threat-segment");

// Table Body & Refresh Button
const tableBody = document.getElementById("results-body");
const refreshBtn = document.getElementById("refreshBtn");

// Alert Banner Components
const alertBanner = document.getElementById("alertBanner");
const alertMessage = document.getElementById("alertMessage");
const alertIcon = document.getElementById("alertIcon");

// Backend Dispatcher API Endpoint
const API_BASE_URL = "http://127.0.0.1:8000";


function showAlert(message, type = "error") {
    if (!alertBanner || !alertMessage) return;

    alertMessage.textContent = message;
    alertBanner.className = `alert-banner ${type}`;

    if (alertIcon) {
        if (type === "error") {
            alertIcon.className = "fa-solid fa-triangle-exclamation";
        } else if (type === "warning") {
            alertIcon.className = "fa-solid fa-circle-exclamation";
        } else if (type === "success") {
            alertIcon.className = "fa-solid fa-circle-check";
        }
    }

    alertBanner.classList.remove("hidden");
}

function dismissAlert() {
    if (alertBanner) {
        alertBanner.classList.add("hidden");
    }
}


// RENDER DATA INTO DASHBOARD UI
function updateDashboardUI(scans, activeTarget = null) {
    if (tableBody) {
        tableBody.innerHTML = "";
    }

    const currentInputValue = targetIpInput ? targetIpInput.value.trim() : "";
    const selectedTarget = activeTarget || currentInputValue || (scans && scans.length > 0 ? scans[0].target_ip : "127.0.0.1");

    if (!scans || scans.length === 0) {
        if (tableBody) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="8" style="text-align: center; color: #8a99ad; padding: 20px;">
                        No scan records found in database. Run a recon scan to populate feed.
                    </td>
                </tr>`;
        }
        if (kpiTarget) kpiTarget.textContent = selectedTarget;
        if (kpiOpenPorts) kpiOpenPorts.textContent = "0";
        if (kpiService) kpiService.textContent = "NONE";
        updateThreatAssessment(0, "Low");
        return;
    }

    // Populate Table Rows (1 to N index, ascending order)
    const displayScans = [...scans].reverse();

    displayScans.forEach((row, index) => {
        const tr = document.createElement("tr");
        const stateLower = row.state ? row.state.toLowerCase() : "open";
        const stateUpper = row.state ? row.state.toUpperCase() : "OPEN";

        tr.innerHTML = `
            <td>${index + 1}</td>
            <td>${row.target_ip}</td>
            <td><strong>${row.port}</strong></td>
            <td><span class="status-badge ${stateLower}">${stateUpper}</span></td>
            <td>${row.service || "unknown"}</td>
            <td>${row.product || "N/A"}</td>
            <td>${row.version || "N/A"}</td>
            <td>${row.timestamp}</td>
        `;
        if (tableBody) tableBody.appendChild(tr);
    });

    // Filter Records for Selected Target
    const targetScans = scans.filter((s) => s.target_ip === selectedTarget);

    const latestScanId = targetScans.length > 0 ? targetScans[0].scan_id : null;
    const latestSessionScans = latestScanId 
        ? targetScans.filter((s) => s.scan_id === latestScanId)
        : targetScans;

    // Calculate & Update KPI Summaries
    if (kpiTarget) kpiTarget.textContent = selectedTarget;

    const uniqueTargetPorts = new Set(latestSessionScans.map((s) => s.port));
    if (kpiOpenPorts) kpiOpenPorts.textContent = uniqueTargetPorts.size;

    const services = latestSessionScans
        .map((s) => (s.service ? s.service.toUpperCase() : ""))
        .filter((s) => s !== "" && s !== "UNKNOWN");
    const uniqueServices = [...new Set(services)].slice(0, 2);

    if (kpiService) {
        kpiService.textContent = uniqueServices.length > 0 ? uniqueServices.join(" / ") : "NONE";
    }

    const openCount = uniqueTargetPorts.size;
    if (openCount === 0) {
        updateThreatAssessment(0, "Low");
    } else if (openCount <= 3) {
        updateThreatAssessment(1, "Low");
    } else if (openCount <= 7) {
        updateThreatAssessment(2, "Medium");
    } else {
        updateThreatAssessment(3, "High");
    }
}

function updateThreatAssessment(level, label) {
    if (threatText) {
        threatText.textContent = label;
        if (label === "Low") threatText.style.color = "#00e676";
        else if (label === "Medium") threatText.style.color = "#ffb300";
        else if (label === "High") threatText.style.color = "#ff3d00";
    }

    threatSegments.forEach((segment, index) => {
        if (index < level) {
            segment.classList.add("active");
        } else {
            segment.classList.remove("active");
        }
    });
}

// FETCH ALL HISTORICAL RESULTS (GET)
async function fetchScanResults(overrideTarget = null) {
    let originalBtnContent = "";
    if (refreshBtn) {
        originalBtnContent = refreshBtn.innerHTML;
        refreshBtn.innerHTML = `<i class="fa-solid fa-rotate-right fa-spin"></i> Refreshing...`;
        refreshBtn.disabled = true;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/results`);
        if (!response.ok) {
            throw new Error(`HTTP Error Status: ${response.status}`);
        }

        const scans = await response.json();
        updateDashboardUI(scans, overrideTarget);

    } catch (error) {
        console.error("[Dispatcher Error]:", error);
        showAlert("Could not fetch database records. Check if FastAPI/uvicorn server is running.", "error");
    } finally {
        if (refreshBtn) {
            refreshBtn.innerHTML = originalBtnContent || `<i class="fa-solid fa-rotate-right"></i> Refresh Data`;
            refreshBtn.disabled = false;
        }
    }
}

// LAUNCH NEW RECON SCAN (POST)
if (scanForm) {
    scanForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        dismissAlert();

        const targetIp = targetIpInput ? targetIpInput.value.trim() : "";
        const portRange = portRangeInput ? portRangeInput.value.trim() : "";

        if (!targetIp || !portRange) {
            showAlert("Please provide both Target IP and Port Range parameters.", "warning");
            return;
        }

        const submitBtn = scanForm.querySelector('button[type="submit"]');
        const originalBtnContent = submitBtn ? submitBtn.innerHTML : "";

        if (submitBtn) {
            submitBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Executing Nmap Scan...`;
            submitBtn.disabled = true;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/api/scan`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    target_ip: targetIp,
                    port_range: portRange,
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Backend failed to execute scan.");
            }

            if (data.status === "warning") {
                showAlert(data.message, "warning");
            } else {
                showAlert(data.message, "success");
            }

            await fetchScanResults(targetIp);

        } catch (error) {
            console.error("[Scan Error]:", error);
            showAlert(`Scan Error: ${error.message}`, "error");
        } finally {
            if (submitBtn) {
                submitBtn.innerHTML = originalBtnContent;
                submitBtn.disabled = false;
            }
        }
    });
}

// Refresh button event listener
if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
        const activeIp = targetIpInput ? targetIpInput.value.trim() : null;
        fetchScanResults(activeIp);
    });
}

// Load initial database records on startup
document.addEventListener("DOMContentLoaded", () => fetchScanResults());