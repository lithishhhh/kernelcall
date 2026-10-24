const API_BASE_URL = "http://127.0.0.1:8000";

const state = {
  currentView: "dashboard-view",
  scans: [],
  selectedScanId: null,
  selectedScan: null,
  filters: {
    historySearch: "",
    status: "all",
    dateWindow: "all",
  },
  comparisonSelection: {
    first: "",
    second: "",
  },
  relationshipSelection: null,
  copilotMessages: [],
  lastUploadFile: null,
};

const ui = {};

document.addEventListener("DOMContentLoaded", initializeApp);

function initializeApp() {
  cacheElements();
  bindNavigation();
  bindUploadFlow();
  bindHistoryFilters();
  bindComparisonControls();
  bindCopilotControls();
  bindReportControls();
  bindGlobalSearch();
  bindScanActions();
  showView("dashboard-view");
  loadDashboard();
  loadHistory();
  refreshComparisonOptions();
  refreshReportOptions();
  refreshCopilotScanOptions();
}

function cacheElements() {
  ui.navButtons = [...document.querySelectorAll(".nav-item")];
  ui.viewPanels = [...document.querySelectorAll(".view-panel")];
  ui.dashboardStats = document.getElementById("dashboard-stats");
  ui.recentScans = document.getElementById("recent-scans-container");
  ui.recentFindings = document.getElementById("recent-findings-container");
  ui.activityChart = document.getElementById("activity-chart");

  ui.selectedFileName = document.getElementById("selected-file-name");
  ui.selectedFileSize = document.getElementById("selected-file-size");
  ui.uploadDropzone = document.getElementById("upload-dropzone");
  ui.apkFileInput = document.getElementById("apk-file-input");
  ui.uploadValidation = document.getElementById("upload-validation");
  ui.uploadSubmit = document.getElementById("upload-submit");
  ui.uploadReset = document.getElementById("upload-reset");
  ui.uploadProgress = document.getElementById("upload-progress");
  ui.uploadProgressText = document.getElementById("upload-progress-text");
  ui.uploadProgressFill = document.getElementById("upload-progress-fill");
  ui.uploadStatus = document.getElementById("upload-status");

  ui.historySearch = document.getElementById("history-search");
  ui.historyStatusFilter = document.getElementById("history-status-filter");
  ui.historyDateFilter = document.getElementById("history-date-filter");
  ui.historyReset = document.getElementById("history-reset");
  ui.historyTable = document.getElementById("history-table-container");

  ui.scanDetailTitle = document.getElementById("scan-detail-title");
  ui.scanDetails = document.getElementById("scan-details-container");
  ui.scanDetailsBack = document.getElementById("scan-details-back");

  ui.findingsContainer = document.getElementById("findings-container");
  ui.compareFirst = document.getElementById("compare-first-scan");
  ui.compareSecond = document.getElementById("compare-second-scan");
  ui.compareSubmit = document.getElementById("compare-submit");
  ui.comparisonOutput = document.getElementById("comparison-output");

  ui.relationshipContainer = document.getElementById("relationship-container");
  ui.copilotMessages = document.getElementById("copilot-messages");
  ui.copilotForm = document.getElementById("copilot-form");
  ui.copilotInput = document.getElementById("copilot-input");
  ui.copilotClear = document.getElementById("copilot-clear");
  ui.copilotScanSelect = document.getElementById("copilot-scan-select");
  ui.reportScanSelect = document.getElementById("report-scan-select");
  ui.reportOutput = document.getElementById("report-output");
  ui.globalSearch = document.getElementById("global-search");
}

function bindNavigation() {
  ui.navButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const targetView = button.dataset.view;
      if (targetView) {
        showView(targetView);
      }
    });
  });

  ui.scanDetailsBack.addEventListener("click", () => {
    showView("history-view");
  });
}

function showView(viewName) {
  state.currentView = viewName;

  ui.viewPanels.forEach((panel) => {
    panel.classList.toggle("active", panel.id === viewName);
  });

  ui.navButtons.forEach((button) => {
    const isActive = button.dataset.view === viewName;
    button.classList.toggle("active", isActive);
  });

  switch (viewName) {
    case "dashboard-view":
      loadDashboard();
      break;
    case "history-view":
      loadHistory();
      break;
    case "scan-details-view":
      if (state.selectedScanId) {
        renderScanDetails(state.selectedScanId);
      }
      break;
    case "findings-view":
      loadFindingsView();
      break;
    case "comparison-view":
      refreshComparisonOptions();
      break;
    case "relationship-view":
      loadRelationshipGraph();
      break;
    case "copilot-view":
      refreshCopilotScanOptions();
      break;
    case "reports-view":
      refreshReportOptions();
      break;
    default:
      break;
  }
}

function bindGlobalSearch() {
  ui.globalSearch.addEventListener("input", (event) => {
    const value = event.target.value.trim();
    if (state.currentView === "history-view") {
      state.filters.historySearch = value;
      renderHistoryTable();
      return;
    }

    if (state.currentView === "findings-view") {
      filterFindingsTable(value);
    }
  });
}

function bindHistoryFilters() {
  ui.historySearch.addEventListener("input", (event) => {
    state.filters.historySearch = event.target.value.trim();
    renderHistoryTable();
  });

  ui.historyStatusFilter.addEventListener("change", (event) => {
    state.filters.status = event.target.value;
    renderHistoryTable();
  });

  ui.historyDateFilter.addEventListener("change", (event) => {
    state.filters.dateWindow = event.target.value;
    renderHistoryTable();
  });

  ui.historyReset.addEventListener("click", () => {
    state.filters = { historySearch: "", status: "all", dateWindow: "all" };
    ui.historySearch.value = "";
    ui.historyStatusFilter.value = "all";
    ui.historyDateFilter.value = "all";
    renderHistoryTable();
  });
}

function bindComparisonControls() {
  ui.compareSubmit.addEventListener("click", compareSelectedScans);
}

function bindCopilotControls() {
  ui.copilotForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const question = ui.copilotInput.value.trim();
    if (!question) {
      showToast("Type a question before sending it to the copilot.");
      return;
    }

    const selectedScanId = ui.copilotScanSelect.value;
    addCopilotMessage("user", question);
    ui.copilotInput.value = "";
    ui.copilotInput.focus();

    try {
      const response = await askCopilot(question, selectedScanId || null);
      const answer = response?.answer || response?.message || response?.content || response?.response || "No answer returned by the backend.";
      addCopilotMessage("assistant", answer);
      if (response?.references) {
        addCopilotMessage("assistant", formatReferenceList(response.references));
      }
    } catch (error) {
      addCopilotMessage("assistant", "The AI forensic copilot is currently unavailable. The backend may not yet expose this endpoint.");
      showToast(error.message || "Copilot service unavailable.");
    }
  });

  ui.copilotClear.addEventListener("click", () => {
    state.copilotMessages = [];
    renderCopilotMessages();
  });

  document.querySelectorAll(".suggestion-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      ui.copilotInput.value = chip.textContent.trim();
      ui.copilotInput.focus();
    });
  });
}

function bindReportControls() {
  ui.reportScanSelect.addEventListener("change", (event) => {
    const scanId = event.target.value;
    if (!scanId) {
      ui.reportOutput.innerHTML = '<div class="empty-state">Choose a scan to retrieve a report.</div>';
      return;
    }

    loadReport(scanId);
  });
}

function bindScanActions() {
  document.addEventListener("click", (event) => {
    const actionButton = event.target.closest("[data-scan-id]");
    if (!actionButton) {
      return;
    }

    const scanId = actionButton.dataset.scanId;
    const action = actionButton.dataset.action;

    if (action === "view-scan") {
      openScanDetails(scanId);
    }

    if (action === "view-findings") {
      state.selectedScanId = scanId;
      showView("findings-view");
      loadFindingsView(scanId);
    }
  });
}

function bindUploadFlow() {
  ui.uploadDropzone.addEventListener("click", () => ui.apkFileInput.click());

  ui.uploadDropzone.addEventListener("dragover", (event) => {
    event.preventDefault();
    ui.uploadDropzone.classList.add("dragover");
  });

  ui.uploadDropzone.addEventListener("dragleave", () => {
    ui.uploadDropzone.classList.remove("dragover");
  });

  ui.uploadDropzone.addEventListener("drop", (event) => {
    event.preventDefault();
    ui.uploadDropzone.classList.remove("dragover");
    const file = event.dataTransfer?.files?.[0];
    if (file) {
      handleSelectedFile(file);
    }
  });

  ui.uploadDropzone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      ui.apkFileInput.click();
    }
  });

  ui.apkFileInput.addEventListener("change", (event) => {
    const file = event.target.files?.[0];
    if (file) {
      handleSelectedFile(file);
    }
  });

  ui.uploadSubmit.addEventListener("click", submitUpload);
  ui.uploadReset.addEventListener("click", resetUpload);
}

function handleSelectedFile(file) {
  if (!file) {
    resetUpload();
    return;
  }

  const validation = validateApkFile(file);
  if (!validation.valid) {
    ui.uploadValidation.textContent = validation.message;
    ui.uploadValidation.className = "validation-message warning-message";
    ui.uploadSubmit.disabled = true;
    state.lastUploadFile = null;
    return;
  }

  state.lastUploadFile = file;
  ui.selectedFileName.textContent = file.name;
  ui.selectedFileSize.textContent = formatBytes(file.size);
  ui.uploadValidation.textContent = validation.message;
  ui.uploadValidation.className = "validation-message success-message";
  ui.uploadSubmit.disabled = false;
}

function validateApkFile(file) {
  const extension = file.name.toLowerCase().endsWith(".apk");
  const typeOkay = file.type === "application/vnd.android.package-archive" || file.type === "" || file.type.includes("apk");
  const sizeLimit = 300 * 1024 * 1024;

  if (!extension && !typeOkay) {
    return {
      valid: false,
      message: "Selected file is not an APK package. Please choose an Android application archive.",
    };
  }

  if (file.size > sizeLimit) {
    return {
      valid: false,
      message: `The APK exceeds the current backend upload limit (${formatBytes(sizeLimit)}).`,
    };
  }

  return {
    valid: true,
    message: "APK ready for upload.",
  };
}

async function submitUpload() {
  const file = state.lastUploadFile;
  if (!file) {
    ui.uploadStatus.textContent = "No APK has been selected for upload.";
    ui.uploadStatus.className = "status-panel warning-message";
    return;
  }

  ui.uploadSubmit.disabled = true;
  ui.uploadStatus.textContent = "Uploading APK...";
  ui.uploadStatus.className = "status-panel";
  ui.uploadProgress.classList.remove("hidden");
  updateUploadProgress(10);

  const formData = new FormData();
  formData.append("file", file, file.name);

  try {
    const result = await apiRequest("/api/scans", {
      method: "POST",
      body: formData,
    });

    const scanId = extractScanId(result);
    const status = normalizeStatus(result?.status || result?.scan_status || result?.state || "queued");

    updateUploadProgress(100);
    ui.uploadStatus.textContent = scanId
      ? `Scan submitted successfully. Scan ID: ${scanId}.`
      : "Scan submitted successfully. Waiting for backend status.";
    ui.uploadStatus.className = "status-panel success-message";

    if (scanId) {
      state.selectedScanId = scanId;
      showToast("Scan submitted successfully.");
      await trackScanStatus(scanId, status);
      showView("scan-details-view");
      renderScanDetails(scanId);
      loadHistory();
      refreshComparisonOptions();
      refreshReportOptions();
      refreshCopilotScanOptions();
      return;
    }

    showView("history-view");
    loadHistory();
  } catch (error) {
    ui.uploadStatus.textContent = error.message || "The APK could not be uploaded. Check the file and try again.";
    ui.uploadStatus.className = "status-panel error-message";
    showToast(error.message || "Upload failed.");
  } finally {
    ui.uploadSubmit.disabled = false;
    ui.uploadProgress.classList.add("hidden");
  }
}

function resetUpload() {
  state.lastUploadFile = null;
  ui.apkFileInput.value = "";
  ui.selectedFileName.textContent = "No file selected";
  ui.selectedFileSize.textContent = "0 B";
  ui.uploadValidation.textContent = "";
  ui.uploadValidation.className = "validation-message";
  ui.uploadStatus.textContent = "";
  ui.uploadStatus.className = "status-panel";
}

function updateUploadProgress(value) {
  ui.uploadProgressText.textContent = `${Math.min(value, 100)}%`;
  ui.uploadProgressFill.style.width = `${Math.min(value, 100)}%`;
}

async function trackScanStatus(scanId, currentStatus) {
  const terminalStates = ["completed", "success", "failed", "error", "complete"];
  if (!scanId || terminalStates.includes(normalizeStatus(currentStatus))) {
    return;
  }

  for (let attempt = 0; attempt < 12; attempt += 1) {
    await wait(1200);
    try {
      const details = await getScanDetails(scanId);
      const nextStatus = normalizeStatus(details?.status || details?.scan_status || details?.state || "processing");
      ui.uploadStatus.textContent = `Processing scan ${scanId}. Status: ${nextStatus}.`;
      if (terminalStates.includes(nextStatus)) {
        return;
      }
    } catch (error) {
      return;
    }
  }
}

async function loadDashboard() {
  ui.dashboardStats.innerHTML = '<div class="loading-state">Retrieving scan summaries...</div>';
  ui.recentScans.innerHTML = '<div class="loading-state">Loading recent scans...</div>';
  ui.recentFindings.innerHTML = '<div class="loading-state">Loading findings...</div>';
  ui.activityChart.innerHTML = '<div class="loading-state">Calculating activity trend...</div>';

  try {
    const scans = await getScans();
    const findings = await collectFindings(scans);
    const stats = calculateDashboardStats(scans, findings);

    ui.dashboardStats.innerHTML = "";
    const cards = [
      { label: "Total Scans", value: stats.totalScans, trend: "Across active investigation records" },
      { label: "Completed Scans", value: stats.completedScans, trend: "Successful and completed analyses" },
      { label: "Findings Detected", value: stats.totalFindings, trend: "Evidence-backed findings reported" },
      { label: "High/Critical Findings", value: stats.highCriticalFindings, trend: "Priority items requiring review" },
    ];

    cards.forEach((card) => {
      const metric = document.createElement("div");
      metric.className = "metric-card";
      metric.innerHTML = `
        <div class="metric-label">${escapeHtml(card.label)}</div>
        <div class="metric-value">${escapeHtml(card.value)}</div>
        <div class="metric-trend">${escapeHtml(card.trend)}</div>
      `;
      ui.dashboardStats.appendChild(metric);
    });

    renderRecentScans(scans);
    renderRecentFindings(findings);
    renderActivityChart(scans);
  } catch (error) {
    ui.dashboardStats.innerHTML = '<div class="error-message">Unable to load scan summary data. The backend may not be running or may not expose the expected scan API.</div>';
    ui.recentScans.innerHTML = '<div class="empty-state">No scan data is currently available.</div>';
    ui.recentFindings.innerHTML = '<div class="empty-state">No findings are available yet.</div>';
    ui.activityChart.innerHTML = '<div class="empty-state">Scan activity will appear here when data is available.</div>';
  }
}

function calculateDashboardStats(scans, findings) {
  const scanList = Array.isArray(scans) ? scans : [];
  const findingsList = Array.isArray(findings) ? findings : [];

  const completedScans = scanList.filter((scan) => {
    const status = normalizeStatus(scan.status || scan.scan_status || scan.state || "");
    return ["completed", "success", "finished", "complete"].includes(status);
  }).length;

  const highCritical = findingsList.filter((finding) => {
    const severity = normalizeStatus(finding.severity || "");
    return ["critical", "high"].includes(severity);
  }).length;

  return {
    totalScans: scanList.length,
    completedScans,
    totalFindings: findingsList.length,
    highCriticalFindings: highCritical,
  };
}

function renderRecentScans(scans) {
  const scanRows = Array.isArray(scans) ? scans.slice(0, 6) : [];

  if (!scanRows.length) {
    ui.recentScans.innerHTML = '<div class="empty-state">No scans have been created yet. Upload an APK to begin an investigation.</div>';
    return;
  }

  const table = document.createElement("div");
  table.className = "table-wrap";
  table.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>APK</th>
          <th>Package</th>
          <th>Hash</th>
          <th>Status</th>
          <th>Findings</th>
          <th>Timestamp</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        ${scanRows.map((scan) => {
          const scanId = escapeHtml(extractScanId(scan));
          const fileName = escapeHtml(readScanValue(scan, ["file_name", "filename", "apk_filename", "name"]) || "Unknown APK");
          const packageName = escapeHtml(readScanValue(scan, ["package_name", "package", "application_id"]) || "N/A");
          const hash = escapeHtml(readScanValue(scan, ["sha256", "sha_256", "hash"]) || "");
          const status = normalizeStatus(scan.status || scan.scan_status || scan.state || "queued");
          const findingsCount = Number(readScanValue(scan, ["finding_count", "findings_count", "findings"]) || 0);
          const timestamp = formatTimestamp(readScanValue(scan, ["timestamp", "created_at", "scan_timestamp"]) || "");
          return `
            <tr>
              <td>${fileName}</td>
              <td>${packageName}</td>
              <td class="hash-mono">${hash ? truncateHash(hash) : "N/A"}</td>
              <td><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replace(/_/g, " ") || "queued")}</span></td>
              <td>${escapeHtml(findingsCount)}</td>
              <td>${escapeHtml(timestamp)}</td>
              <td><button class="table-action" type="button" data-scan-id="${scanId}" data-action="view-scan">View details</button></td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;
  ui.recentScans.innerHTML = "";
  ui.recentScans.appendChild(table);
}

function renderRecentFindings(findings) {
  const recent = Array.isArray(findings) ? findings.slice(0, 8) : [];

  if (!recent.length) {
    ui.recentFindings.innerHTML = '<div class="empty-state">No findings available. Upload an APK and allow analysis to finish.</div>';
    return;
  }

  const list = document.createElement("ul");
  list.className = "report-list";
  list.innerHTML = recent.map((finding) => {
    const title = escapeHtml(readFindingValue(finding, ["title", "name"]) || "Untitled finding");
    const severity = normalizeStatus(readFindingValue(finding, ["severity"]) || "informational");
    const scanRef = escapeHtml(readFindingValue(finding, ["scan_id", "apk_id", "scanId"]) || "");
    const findingId = escapeHtml(readFindingValue(finding, ["evidence_id", "id"]) || "");
    return `
      <li>
        <div class="finding-meta">
          <strong>${title}</strong>
          <span class="severity-badge ${escapeHtml(severity)}">${escapeHtml(severity)}</span>
        </div>
        <div class="muted-text">${findingId ? `Evidence: ${findingId}` : "Evidence ID unavailable"}${scanRef ? ` · Scan: ${scanRef}` : ""}</div>
      </li>
    `;
  }).join("");

  ui.recentFindings.innerHTML = "";
  ui.recentFindings.appendChild(list);
}

function renderActivityChart(scans) {
  const validScans = Array.isArray(scans) ? scans.filter((scan) => readScanValue(scan, ["timestamp", "created_at", "scan_timestamp"])) : [];

  if (!validScans.length) {
    ui.activityChart.innerHTML = '<div class="empty-state">No scan timestamps were returned by the backend.</div>';
    return;
  }

  const dateMap = new Map();
  validScans.forEach((scan) => {
    const iso = readScanValue(scan, ["timestamp", "created_at", "scan_timestamp"]) || "";
    const dateKey = iso ? new Date(iso).toISOString().slice(0, 10) : "";
    if (!dateKey) {
      return;
    }
    dateMap.set(dateKey, (dateMap.get(dateKey) || 0) + 1);
  });

  const entries = [...dateMap.entries()].sort(([left], [right]) => left.localeCompare(right)).slice(-7);
  if (!entries.length) {
    ui.activityChart.innerHTML = '<div class="empty-state">No usable scan timestamp data is available.</div>';
    return;
  }

  const maxValue = Math.max(...entries.map(([, count]) => count), 1);
  const chart = document.createElement("div");
  chart.style.display = "grid";
  chart.style.gridTemplateColumns = "repeat(auto-fit, minmax(48px, 1fr))";
  chart.style.alignItems = "end";
  chart.style.gap = "0.6rem";
  chart.style.padding = "1rem";
  chart.style.minHeight = "200px";

  entries.forEach(([date, value]) => {
    const barWrap = document.createElement("div");
    barWrap.style.display = "flex";
    barWrap.style.flexDirection = "column";
    barWrap.style.alignItems = "center";
    barWrap.style.gap = "0.5rem";

    const bar = document.createElement("div");
    bar.style.width = "100%";
    bar.style.maxWidth = "32px";
    bar.style.height = `${Math.max((value / maxValue) * 140, 16)}px`;
    bar.style.background = "linear-gradient(180deg, #48a0ff, #35d7f2)";
    bar.style.borderRadius = "8px 8px 0 0";
    bar.style.border = "1px solid rgba(72, 160, 255, 0.45)";

    const label = document.createElement("div");
    label.textContent = date.slice(5);
    label.style.color = "var(--secondary-text)";
    label.style.fontSize = "0.72rem";

    const count = document.createElement("div");
    count.textContent = `${value}`;
    count.style.color = "var(--text)";
    count.style.fontSize = "0.7rem";

    barWrap.appendChild(count);
    barWrap.appendChild(bar);
    barWrap.appendChild(label);
    chart.appendChild(barWrap);
  });

  ui.activityChart.innerHTML = "";
  ui.activityChart.appendChild(chart);
}

async function loadHistory() {
  try {
    const scans = await getScans();
    state.scans = scans;
    renderHistoryTable();
  } catch (error) {
    ui.historyTable.innerHTML = '<div class="error-message">Scan history is unavailable. The backend may not be exposing the scan listing endpoint.</div>';
  }
}

function renderHistoryTable() {
  const scans = Array.isArray(state.scans) ? state.scans : [];
  const filtered = applyHistoryFilters(scans);

  if (!scans.length) {
    ui.historyTable.innerHTML = '<div class="empty-state">No scans have been created. Upload an APK to begin an investigation.</div>';
    return;
  }

  if (!filtered.length) {
    ui.historyTable.innerHTML = '<div class="empty-state">No scans match your current filters.</div>';
    return;
  }

  const table = document.createElement("div");
  table.className = "table-wrap";
  table.innerHTML = `
    <table class="data-table">
      <thead>
        <tr>
          <th>Filename</th>
          <th>Package</th>
          <th>Hash</th>
          <th>Status</th>
          <th>Findings</th>
          <th>Date</th>
          <th>Open</th>
        </tr>
      </thead>
      <tbody>
        ${filtered.map((scan) => {
          const scanId = escapeHtml(extractScanId(scan));
          const fileName = escapeHtml(readScanValue(scan, ["file_name", "filename", "apk_filename", "name"]) || "Unknown APK");
          const packageName = escapeHtml(readScanValue(scan, ["package_name", "package", "application_id"]) || "N/A");
          const hash = escapeHtml(readScanValue(scan, ["sha256", "sha_256", "hash"]) || "");
          const status = normalizeStatus(scan.status || scan.scan_status || scan.state || "queued");
          const findingsCount = readScanValue(scan, ["finding_count", "findings_count", "findings"]) || 0;
          const date = formatTimestamp(readScanValue(scan, ["timestamp", "created_at", "scan_timestamp"]) || "");
          return `
            <tr>
              <td>${fileName}</td>
              <td>${packageName}</td>
              <td class="hash-mono">${hash ? truncateHash(hash) : "N/A"}</td>
              <td><span class="status-badge ${escapeHtml(status)}">${escapeHtml(status.replace(/_/g, " "))}</span></td>
              <td>${escapeHtml(Number(findingsCount) || 0)}</td>
              <td>${escapeHtml(date)}</td>
              <td><button class="table-action" type="button" data-scan-id="${scanId}" data-action="view-scan">Open</button></td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;

  ui.historyTable.innerHTML = "";
  ui.historyTable.appendChild(table);
}

function applyHistoryFilters(scans) {
  return scans.filter((scan) => {
    const status = normalizeStatus(scan.status || scan.scan_status || scan.state || "queued");
    const query = state.filters.historySearch.toLowerCase();
    const text = [
      readScanValue(scan, ["file_name", "filename", "apk_filename", "name"]),
      readScanValue(scan, ["package_name", "package", "application_id"]),
      readScanValue(scan, ["sha256", "sha_256", "hash"]),
      extractScanId(scan),
    ].join(" ").toLowerCase();

    if (query && !text.includes(query)) {
      return false;
    }

    if (state.filters.status !== "all" && status !== state.filters.status) {
      return false;
    }

    const days = Number(state.filters.dateWindow || 0);
    if (days > 0) {
      const rawTimestamp = readScanValue(scan, ["timestamp", "created_at", "scan_timestamp"]) || "";
      const timestamp = rawTimestamp ? new Date(rawTimestamp).getTime() : 0;
      const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
      if (timestamp < cutoff) {
        return false;
      }
    }

    return true;
  });
}

async function openScanDetails(scanId) {
  state.selectedScanId = scanId;
  showView("scan-details-view");
  await renderScanDetails(scanId);
}

async function renderScanDetails(scanId) {
  try {
    const scan = await getScanDetails(scanId);
    state.selectedScan = scan;
    const findings = await getScanFindings(scanId).catch(() => []);
    const evidence = await getScanEvidence(scanId).catch(() => []);
    ui.scanDetailTitle.textContent = `${readScanValue(scan, ["file_name", "filename", "apk_filename", "name"]) || "APK"} · ${scanId}`;

    const metadata = [
      { label: "APK filename", value: readScanValue(scan, ["file_name", "filename", "apk_filename", "name"]) || "Not provided" },
      { label: "Package name", value: readScanValue(scan, ["package_name", "package", "application_id"]) || "Not provided" },
      { label: "Version name", value: readScanValue(scan, ["version_name", "version"]) || "Not provided" },
      { label: "Version code", value: readScanValue(scan, ["version_code"]) || "Not provided" },
      { label: "SHA-256", value: readScanValue(scan, ["sha256", "sha_256", "hash"]) || "Not provided" },
      { label: "File size", value: formatBytes(readScanValue(scan, ["file_size", "size"]) || 0) },
      { label: "Scan ID", value: extractScanId(scan) || scanId },
      { label: "Scan timestamp", value: formatTimestamp(readScanValue(scan, ["timestamp", "created_at", "scan_timestamp"]) || "") },
      { label: "Scan status", value: normalizeStatus(scan.status || scan.scan_status || scan.state || "queued") },
      { label: "Risk score", value: readScanValue(scan, ["risk_score", "score"]) || "Not supplied by backend" },
      { label: "Tool version", value: readScanValue(scan, ["tool_version", "engine_version"]) || "Not supplied by backend" },
    ];

    const permissions = Array.isArray(scan.permissions) ? scan.permissions : [];
    const components = Array.isArray(scan.components) ? scan.components : [];
    const technicalObservations = scan.observations || scan.technical_observations || scan.analysis || {};
    const findingsList = Array.isArray(findings) ? findings : [];
    const evidenceList = Array.isArray(evidence) ? evidence : [];

    ui.scanDetails.innerHTML = `
      <div class="detail-grid">
        ${metadata.map((item) => `
          <div class="detail-item">
            <span class="detail-name">${escapeHtml(item.label)}</span>
            <div class="detail-value">${escapeHtml(item.value)}${item.label.toLowerCase().includes("hash") || item.label.toLowerCase().includes("sha") ? '<button class="copy-button" type="button" data-copy="${escapeHtml(item.value)}">Copy</button>' : ""}</div>
          </div>
        `).join("")}
      </div>

      <div class="info-grid">
        <div class="info-card">
          <h3>Permissions explorer</h3>
          ${permissions.length ? `
            <ul class="permission-list">
              ${permissions.map((permission) => `
                <li>
                  <strong>${escapeHtml(permission.name || permission.permission || "Permission")}</strong>
                  <div class="muted-text">${escapeHtml(permission.protection_level || permission.level || "Protection level not provided")}</div>
                  <div>${permission.sensitive ? "Sensitive by policy" : "Permission may be legitimate depending on app purpose"}</div>
                </li>
              `).join("")}
            </ul>
          ` : '<div class="empty-state">No permissions were returned by the backend for this APK.</div>'}
        </div>

        <div class="info-card">
          <h3>Components</h3>
          ${components.length ? `
            <ul class="component-list">
              ${components.map((component) => `
                <li>
                  <strong>${escapeHtml(component.name || component.component || "Component")}</strong>
                  <div class="muted-text">${escapeHtml(component.type || "Unknown component type")}</div>
                  <div>${component.exported ? "Exported component" : "Not exported or status unknown"}</div>
                </li>
              `).join("")}
            </ul>
          ` : '<div class="empty-state">No component data is currently available for this APK.</div>'}
        </div>
      </div>

      <div class="info-card">
        <h3>Technical observations</h3>
        ${Object.keys(technicalObservations).length ? `
          <ul class="evidence-list">
            ${Object.entries(technicalObservations).map(([key, value]) => `
              <li>
                <strong>${escapeHtml(key.replace(/_/g, " "))}</strong>
                <div>${escapeHtml(typeof value === "string" ? value : JSON.stringify(value))}</div>
              </li>
            `).join("")}
          </ul>
        ` : '<div class="empty-state">Technical observations are not available for this scan yet.</div>'}
      </div>

      <div class="info-card">
        <h3>Analysis status</h3>
        <div class="status-badge ${escapeHtml(normalizeStatus(scan.status || scan.scan_status || scan.state || "queued"))}">
          ${escapeHtml(normalizeStatus(scan.status || scan.scan_status || scan.state || "queued").replace(/_/g, " "))}
        </div>
      </div>

      <div class="info-card">
        <h3>Evidence</h3>
        ${evidenceList.length ? `
          <ul class="evidence-list">
            ${evidenceList.map((item) => `
              <li>
                <strong>${escapeHtml(item.evidence_id || item.id || "Evidence")}</strong>
                <div>${escapeHtml(item.description || item.summary || item.message || "No description provided")}</div>
              </li>
            `).join("")}
          </ul>
        ` : '<div class="empty-state">No evidence metadata is available for this scan.</div>'}
      </div>

      <div class="info-card">
        <h3>Findings linked to this scan</h3>
        ${findingsList.length ? `
          <ul class="report-list">
            ${findingsList.map((finding) => `
              <li>
                <div class="finding-meta">
                  <strong>${escapeHtml(readFindingValue(finding, ["title", "name"]) || "Finding")}</strong>
                  <span class="severity-badge ${escapeHtml(normalizeStatus(readFindingValue(finding, ["severity"]) || "informational"))}">${escapeHtml(normalizeStatus(readFindingValue(finding, ["severity"]) || "informational"))}</span>
                </div>
                <div class="muted-text">${escapeHtml(readFindingValue(finding, ["rule_id", "ruleId"]) || "Rule ID not provided")}</div>
              </li>
            `).join("")}
          </ul>
        ` : '<div class="empty-state">This scan does not currently report any findings.</div>'}
      </div>
    `;

    document.querySelectorAll("[data-copy]").forEach((button) => {
      button.addEventListener("click", async () => {
        const value = button.getAttribute("data-copy");
        if (navigator.clipboard) {
          await navigator.clipboard.writeText(value || "");
          showToast("Value copied to clipboard.");
        }
      });
    });
  } catch (error) {
    ui.scanDetails.innerHTML = `<div class="error-message">Unable to load scan details for ${escapeHtml(scanId)}. ${escapeHtml(error.message || "The backend response was not usable.")}</div>`;
  }
}

async function loadFindingsView(scanIdOverride) {
  const preferredScanId = scanIdOverride || state.selectedScanId || null;
  const selectedScan = preferredScanId ? await getScanDetails(preferredScanId).catch(() => null) : null;
  const scanId = preferredScanId || (selectedScan ? extractScanId(selectedScan) : null);

  try {
    const mostRelevant = scanId ? await getScanFindings(scanId) : await getAllFindings();
    const items = Array.isArray(mostRelevant) ? mostRelevant : [];

    if (!items.length) {
      ui.findingsContainer.innerHTML = '<div class="empty-state">No findings are available for this investigation yet.</div>';
      return;
    }

    const list = document.createElement("div");
    list.className = "card";
    list.innerHTML = `
      <div class="card-header">
        <h3>Findings table</h3>
      </div>
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>Evidence ID</th>
              <th>Rule ID</th>
              <th>Title</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Observation</th>
              <th>Next step</th>
            </tr>
          </thead>
          <tbody>
            ${items.map((finding) => {
              const title = readFindingValue(finding, ["title", "name"]) || "Untitled finding";
              const severity = normalizeStatus(readFindingValue(finding, ["severity"]) || "informational");
              const confidence = readFindingValue(finding, ["confidence"]) || "Not provided";
              const category = readFindingValue(finding, ["category"]) || "Not provided";
              const observation = readFindingValue(finding, ["observation", "description"]) || "No observation provided";
              const nextStep = readFindingValue(finding, ["recommended_next_step", "recommended_next_step", "next_step"]) || "Review the evidence and validate with the analyst.";
              const evidenceId = readFindingValue(finding, ["evidence_id", "id"]) || "N/A";
              const ruleId = readFindingValue(finding, ["rule_id", "ruleId"]) || "N/A";
              return `
                <tr>
                  <td>${escapeHtml(evidenceId)}</td>
                  <td>${escapeHtml(ruleId)}</td>
                  <td>${escapeHtml(title)}</td>
                  <td>${escapeHtml(category)}</td>
                  <td><span class="severity-badge ${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
                  <td>${escapeHtml(confidence)}</td>
                  <td>${escapeHtml(shortText(observation, 90))}</td>
                  <td>${escapeHtml(shortText(nextStep, 80))}</td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      </div>
    `;

    ui.findingsContainer.innerHTML = "";
    ui.findingsContainer.appendChild(list);
  } catch (error) {
    ui.findingsContainer.innerHTML = `<div class="error-message">Findings could not be retrieved. ${escapeHtml(error.message || "The findings endpoint is unavailable.")}</div>`;
  }
}

function filterFindingsTable(searchTerm) {
  const table = ui.findingsContainer.querySelector("table");
  if (!table) {
    return;
  }

  const rows = [...table.querySelectorAll("tbody tr")];
  rows.forEach((row) => {
    const text = row.textContent.toLowerCase();
    row.classList.toggle("hidden", searchTerm && !text.includes(searchTerm.toLowerCase()));
  });
}

async function refreshComparisonOptions() {
  try {
    const scans = await getScans();
    state.scans = scans;

    const firstOptions = scans.map((scan) => `<option value="${escapeHtml(extractScanId(scan))}">${escapeHtml(readScanValue(scan, ["file_name", "filename", "apk_filename", "name"]) || "Unknown APK")}</option>`).join("");
    const secondOptions = firstOptions;

    ui.compareFirst.innerHTML = `<option value="">Select first APK</option>${firstOptions}`;
    ui.compareSecond.innerHTML = `<option value="">Select second APK</option>${secondOptions}`;
  } catch (error) {
    ui.compareFirst.innerHTML = '<option value="">Comparison service unavailable</option>';
    ui.compareSecond.innerHTML = '<option value="">Comparison service unavailable</option>';
  }
}

async function compareSelectedScans() {
  const firstScanId = ui.compareFirst.value;
  const secondScanId = ui.compareSecond.value;

  if (!firstScanId || !secondScanId) {
    ui.comparisonOutput.innerHTML = '<div class="error-message">Please select two scans before running a comparison.</div>';
    return;
  }

  if (firstScanId === secondScanId) {
    ui.comparisonOutput.innerHTML = '<div class="error-message">Choose two different APK scans to compare.</div>';
    return;
  }

  ui.comparisonOutput.innerHTML = '<div class="loading-state">Comparing APKs and extracting differences...</div>';

  try {
    const result = await compareScans(firstScanId, secondScanId);
    renderComparisonResult(result);
  } catch (error) {
    ui.comparisonOutput.innerHTML = `<div class="error-message">Comparison service unavailable. ${escapeHtml(error.message || "The backend does not expose compare support yet.")}</div>`;
  }
}

function renderComparisonResult(result) {
  const payload = result || {};
  const overview = payload.application_overview || payload.applicationOverview || payload.overview || {};
  const permissions = payload.permissions || {};
  const components = payload.components || {};
  const indicators = payload.indicators || {};
  const findings = payload.findings || [];
  const interpretation = payload.interpretation || payload.analysis || payload.summary || "No interpretation returned by the backend.";

  ui.comparisonOutput.innerHTML = `
    <div class="comparison-section">
      <h4>Application overview</h4>
      <div class="detail-grid">
        ${Object.entries(overview).map(([key, value]) => `
          <div class="detail-item">
            <span class="detail-name">${escapeHtml(key.replace(/_/g, " "))}</span>
            <div class="detail-value">${escapeHtml(typeof value === "string" ? value : JSON.stringify(value))}</div>
          </div>
        `).join("") || '<div class="empty-state">No application overview data returned by the backend.</div>'}
      </div>
    </div>

    <div class="comparison-section">
      <h4>Permissions</h4>
      ${Object.keys(permissions).length ? renderComparisonList(permissions) : '<div class="empty-state">No permission differences were returned.</div>'}
    </div>

    <div class="comparison-section">
      <h4>Components</h4>
      ${Object.keys(components).length ? renderComparisonList(components) : '<div class="empty-state">No component differences were returned.</div>'}
    </div>

    <div class="comparison-section">
      <h4>Indicators</h4>
      ${Object.keys(indicators).length ? renderComparisonList(indicators) : '<div class="empty-state">No indicator differences were returned.</div>'}
    </div>

    <div class="comparison-section">
      <h4>Findings</h4>
      ${findings.length ? `
        <ul class="related-list">
          ${findings.map((finding) => `<li>${escapeHtml(typeof finding === "string" ? finding : (finding.title || finding.rule_id || JSON.stringify(finding)))}</li>`).join("")}
        </ul>
      ` : '<div class="empty-state">No findings comparison output was returned.</div>'}
    </div>

    <div class="comparison-section">
      <h4>Interpretation</h4>
      <div>${escapeHtml(typeof interpretation === "string" ? interpretation : JSON.stringify(interpretation))}</div>
    </div>
  `;
}

function renderComparisonList(data) {
  return `
    <ul class="related-list">
      ${Object.entries(data).map(([key, value]) => `
        <li>
          <strong>${escapeHtml(key.replace(/_/g, " "))}</strong>
          <div>${escapeHtml(typeof value === "string" ? value : JSON.stringify(value))}</div>
        </li>
      `).join("")}
    </ul>
  `;
}

async function loadRelationshipGraph() {
  ui.relationshipContainer.innerHTML = '<div class="loading-state">Retrieving relationship data...</div>';

  try {
    const payload = await getRelationships();
    const nodes = Array.isArray(payload?.nodes) ? payload.nodes : [];
    const edges = Array.isArray(payload?.edges) ? payload.edges : [];

    if (!nodes.length) {
      ui.relationshipContainer.innerHTML = '<div class="empty-state">No correlation data is available. The backend may not expose relationship graph data yet.</div>';
      return;
    }

    const selected = state.relationshipSelection || nodes[0].id;
    renderGraph(nodes, edges, selected);
  } catch (error) {
    ui.relationshipContainer.innerHTML = `<div class="unavailable-state">Relationship graph service unavailable. ${escapeHtml(error.message || "No correlation data is available.")}</div>`;
  }
}

function renderGraph(nodes, edges, selectedNodeId) {
  const surface = document.createElement("div");
  surface.className = "graph-surface";
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 760 420");
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", "100%");

  const nodeMap = new Map();
  const positionedNodes = nodes.map((node, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(nodes.length, 1);
    const radius = 160;
    const x = 380 + Math.cos(angle) * radius;
    const y = 210 + Math.sin(angle) * radius * 0.8;
    const normalized = {
      ...node,
      x,
      y,
    };
    nodeMap.set(node.id, normalized);
    return normalized;
  });

  edges.forEach((edge) => {
    const fromNode = nodeMap.get(edge.source || edge.from);
    const toNode = nodeMap.get(edge.target || edge.to);
    if (!fromNode || !toNode) {
      return;
    }

    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", fromNode.x);
    line.setAttribute("y1", fromNode.y);
    line.setAttribute("x2", toNode.x);
    line.setAttribute("y2", toNode.y);
    line.setAttribute("class", "graph-edge");
    if (selectedNodeId && (edge.source === selectedNodeId || edge.target === selectedNodeId)) {
      line.setAttribute("stroke", "#48a0ff");
      line.setAttribute("stroke-width", "3");
    }
    svg.appendChild(line);
  });

  positionedNodes.forEach((node) => {
    const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
    group.setAttribute("class", "graph-node");
    group.dataset.nodeId = String(node.id);

    const color = {
      apk: "#2878ff",
      domain: "#35d7f2",
      ip: "#16c79a",
      certificate: "#9767ff",
      url: "#ffb547",
      indicator: "#ff8a3d",
    }[node.type] || "#9baec9";

    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", node.x);
    circle.setAttribute("cy", node.y);
    circle.setAttribute("r", selectedNodeId === node.id ? 22 : 16);
    circle.setAttribute("fill", color);
    circle.setAttribute("opacity", selectedNodeId === node.id ? "1" : "0.8");
    circle.style.cursor = "pointer";

    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", node.x + 18);
    label.setAttribute("y", node.y + 30);
    label.textContent = (node.label || node.name || node.id || "node").slice(0, 18);

    group.appendChild(circle);
    group.appendChild(label);
    group.addEventListener("click", () => {
      state.relationshipSelection = node.id;
      renderGraph(nodes, edges, node.id);
      const selectedNode = nodes.find((item) => String(item.id) === String(node.id)) || {};
      const details = document.getElementById("relationship-details");
      if (details) {
        details.innerHTML = `
          <div><strong>Node:</strong> ${escapeHtml(selectedNode.label || selectedNode.name || node.id)}</div>
          <div><strong>Type:</strong> ${escapeHtml(selectedNode.type || "unknown")}</div>
          <div><strong>Details:</strong> ${escapeHtml(selectedNode.detail || selectedNode.description || "No additional metadata provided.")}</div>
        `;
      }
    });

    svg.appendChild(group);
  });

  surface.appendChild(svg);
  ui.relationshipContainer.innerHTML = "";
  ui.relationshipContainer.appendChild(surface);

  const panel = document.createElement("div");
  panel.className = "relationship-panel";
  panel.id = "relationship-details";
  const selectedNode = nodes.find((node) => String(node.id) === String(selectedNodeId)) || nodes[0];
  panel.innerHTML = `
    <div><strong>Selected node:</strong> ${escapeHtml(selectedNode?.label || selectedNode?.name || selectedNode?.id || "Unknown node")}</div>
    <div><strong>Type:</strong> ${escapeHtml(selectedNode?.type || "unknown")}</div>
    <div><strong>Details:</strong> ${escapeHtml(selectedNode?.detail || selectedNode?.description || "No additional metadata was provided.")}</div>
  `;
  ui.relationshipContainer.appendChild(panel);
}

async function refreshCopilotScanOptions() {
  try {
    const scans = await getScans();
    const options = scans.map((scan) => `
      <option value="${escapeHtml(extractScanId(scan))}">${escapeHtml(readScanValue(scan, ["file_name", "filename", "apk_filename", "name"]) || "Unknown APK")}</option>
    `).join("");
    ui.copilotScanSelect.innerHTML = `<option value="">No scan selected</option>${options}`;
  } catch (error) {
    ui.copilotScanSelect.innerHTML = '<option value="">No scan selected</option>';
  }
}

async function refreshReportOptions() {
  try {
    const scans = await getScans();
    const options = scans.map((scan) => `
      <option value="${escapeHtml(extractScanId(scan))}">${escapeHtml(readScanValue(scan, ["file_name", "filename", "apk_filename", "name"]) || "Unknown APK")}</option>
    `).join("");
    ui.reportScanSelect.innerHTML = `<option value="">Choose a scan</option>${options}`;
  } catch (error) {
    ui.reportScanSelect.innerHTML = '<option value="">No reports available</option>';
  }
}

async function loadReport(scanId) {
  ui.reportOutput.innerHTML = '<div class="loading-state">Retrieving report...</div>';

  try {
    const report = await getReport(scanId);
    const isBlob = report instanceof Blob;
    const isPlainText = typeof report === "string";

    if (isBlob) {
      const url = URL.createObjectURL(report);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `report-${scanId}.pdf`;
      anchor.click();
      URL.revokeObjectURL(url);
      ui.reportOutput.innerHTML = '<div class="success-message">Report downloaded successfully.</div>';
      return;
    }

    if (isPlainText) {
      ui.reportOutput.innerHTML = `<div class="report-list"><strong>Report output</strong><pre>${escapeHtml(report)}</pre></div>`;
      return;
    }

    const reportData = report || {};
    const metadata = [
      { label: "Scan ID", value: reportData.scan_id || reportData.scanId || scanId },
      { label: "APK filename", value: reportData.apk_filename || reportData.file_name || "Not supplied" },
      { label: "SHA-256", value: reportData.sha256 || reportData.hash || "Not supplied" },
      { label: "Risk assessment", value: reportData.risk_assessment || reportData.risk || "Not supplied" },
      { label: "Summary", value: reportData.summary || reportData.overview || "Not supplied" },
    ];

    ui.reportOutput.innerHTML = `
      <div class="detail-grid">
        ${metadata.map((item) => `
          <div class="detail-item">
            <span class="detail-name">${escapeHtml(item.label)}</span>
            <div class="detail-value">${escapeHtml(item.value)}</div>
          </div>
        `).join("")}
      </div>
    `;
  } catch (error) {
    ui.reportOutput.innerHTML = `<div class="unavailable-state">Report generation is not available for this backend build. ${escapeHtml(error.message || "Feature not implemented.")}</div>`;
  }
}

async function askCopilot(question, selectedScanId) {
  const payload = {
    question,
    scan_id: selectedScanId || null,
    context: selectedScanId ? { scan_id: selectedScanId } : {},
  };

  const endpoints = [
    { path: "/api/ask", method: "POST" },
    { path: "/api/copilot", method: "POST" },
    { path: "/api/copilot/ask", method: "POST" },
  ];

  for (const endpoint of endpoints) {
    try {
      return await apiRequest(endpoint.path, {
        method: endpoint.method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch (error) {
      if (endpoint.path === "/api/copilot/ask") {
        throw error;
      }
    }
  }

  throw new Error("AI forensic copilot is not available in the current backend build.");
}

async function getScans() {
  try {
    const data = await apiRequest("/api/scans");
    return Array.isArray(data) ? data : Array.isArray(data?.scans) ? data.scans : [];
  } catch (error) {
    return [];
  }
}

async function getScanDetails(scanId) {
  if (!scanId) {
    throw new Error("Missing scan ID.");
  }
  return apiRequest(`/api/scans/${scanId}`);
}

async function getScanFindings(scanId) {
  if (!scanId) {
    return [];
  }

  try {
    const response = await apiRequest(`/api/scans/${scanId}/findings`);
    return Array.isArray(response) ? response : Array.isArray(response?.findings) ? response.findings : [];
  } catch (error) {
    return [];
  }
}

async function getScanEvidence(scanId) {
  if (!scanId) {
    return [];
  }

  try {
    const response = await apiRequest(`/api/scans/${scanId}/evidence`);
    return Array.isArray(response) ? response : Array.isArray(response?.evidence) ? response.evidence : [];
  } catch (error) {
    return [];
  }
}

async function compareScans(firstScanId, secondScanId) {
  const payload = {
    first_scan_id: firstScanId,
    second_scan_id: secondScanId,
    left_scan_id: firstScanId,
    right_scan_id: secondScanId,
  };

  return apiRequest("/api/compare", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function getRelationships() {
  const endpoints = ["/api/relationships", "/api/correlation", "/api/graph"];
  for (const endpoint of endpoints) {
    try {
      return await apiRequest(endpoint);
    } catch (error) {
      continue;
    }
  }
  throw new Error("Relationship data is not available in the current backend build.");
}

async function getReport(scanId) {
  return apiRequest(`/api/reports/${scanId}`);
}

async function collectFindings(scans) {
  const findings = await getAllFindings();
  if (findings.length) {
    return findings;
  }

  const scanList = Array.isArray(scans) ? scans : [];
  const results = await Promise.all(
    scanList.slice(0, 6).map(async (scan) => {
      const scanId = extractScanId(scan);
      if (!scanId) {
        return [];
      }
      return getScanFindings(scanId).catch(() => []);
    }),
  );

  return results.flat();
}

async function getAllFindings() {
  try {
    const response = await apiRequest("/api/findings");
    return Array.isArray(response) ? response : Array.isArray(response?.findings) ? response.findings : [];
  } catch (error) {
    return [];
  }
}

async function apiRequest(path, options = {}) {
  const requestOptions = {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.headers || {}),
    },
  };

  if (!(requestOptions.body instanceof FormData)) {
    requestOptions.headers = {
      ...requestOptions.headers,
      "Content-Type": requestOptions.headers["Content-Type"] || requestOptions.headers["content-type"] || "application/json",
    };
  }

  const url = new URL(path, `${API_BASE_URL}/`).toString();
  const response = await fetch(url, requestOptions);

  const contentType = response.headers.get("content-type") || "";
  let payload;

  if (contentType.includes("application/json")) {
    payload = await response.json();
  } else if (response.status !== 204) {
    payload = await response.text();
  }

  if (!response.ok) {
    const detail = payload?.detail || payload?.message || payload?.error || response.statusText || "Request failed.";
    throw new Error(detail);
  }

  return payload;
}

function extractScanId(scan) {
  if (!scan) {
    return "";
  }
  return readScanValue(scan, ["id", "scan_id", "scanId", "scanID"]) || "";
}

function readScanValue(scan, keys) {
  if (!scan) {
    return "";
  }

  for (const key of keys) {
    if (scan[key] !== undefined && scan[key] !== null && scan[key] !== "") {
      return scan[key];
    }
  }

  return "";
}

function readFindingValue(finding, keys) {
  if (!finding) {
    return "";
  }

  for (const key of keys) {
    if (finding[key] !== undefined && finding[key] !== null && finding[key] !== "") {
      return finding[key];
    }
  }

  return "";
}

function normalizeStatus(value) {
  if (!value) {
    return "queued";
  }

  const text = String(value).trim().toLowerCase();
  const normalized = text.replace(/\s+/g, "_");
  if (["completed", "complete", "success", "finished"].includes(normalized)) {
    return "completed";
  }
  if (["in_progress", "processing", "running", "pending", "queued"].includes(normalized)) {
    return normalized === "pending" ? "queued" : normalized;
  }
  if (["failed", "error", "failure"].includes(normalized)) {
    return "failed";
  }
  return normalized || "queued";
}

function formatTimestamp(value) {
  if (!value) {
    return "N/A";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatBytes(bytesValue) {
  const value = Number(bytesValue || 0);
  if (!value || value <= 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function truncateHash(hashValue) {
  const value = String(hashValue || "");
  if (value.length <= 16) {
    return value;
  }
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function shortText(value, length) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

function escapeHtml(value) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatReferenceList(references) {
  if (!Array.isArray(references) || !references.length) {
    return "No supporting references were returned by the backend.";
  }

  return `References: ${references.map((item) => item.id || item.evidence_id || item).join(", ")}`;
}

function addCopilotMessage(role, content) {
  state.copilotMessages.push({ role, content });
  renderCopilotMessages();
}

function renderCopilotMessages() {
  if (!state.copilotMessages.length) {
    ui.copilotMessages.innerHTML = '<div class="empty-state">Ask a question to start an evidence-backed investigation.</div>';
    return;
  }

  ui.copilotMessages.innerHTML = state.copilotMessages.map((message) => `
    <div class="message ${message.role}">${escapeHtml(message.content)}</div>
  `).join("");

  ui.copilotMessages.scrollTop = ui.copilotMessages.scrollHeight;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function showToast(message) {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  const region = document.getElementById("toast-region");
  region.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 2800);
}
