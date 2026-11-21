const state = { devices: [], alerts: [], history: [], filter: "all", alertFilter: "all", search: "" };
const $ = (selector) => document.querySelector(selector);
const on = (selector, event, handler) => {
  const element = $(selector);
  if (element) element.addEventListener(event, handler);
};
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]));
const formatTime = (value) => value ? new Date(value).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "Never";

async function api(url, options = {}) {
  const response = await fetch(url, { headers: { "Content-Type": "application/json" }, ...options });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`Request failed (${response.status})`);
  }
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function showView(view) {
  document.querySelectorAll(".view").forEach((item) => item.classList.toggle("active", item.id === `view-${view}`));
  document.querySelectorAll("[data-view]").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  if (view === "devices") renderDevices();
  if (view === "alerts") renderAlerts();
  if (view === "history") renderHistory();
}

async function refreshOverview() {
  const data = await api("/api/overview");
  $("#total-devices").textContent = data.total_devices;
  $("#online-devices").textContent = data.online_devices;
  $("#trusted-devices").textContent = data.trusted_devices;
  $("#unknown-devices").textContent = data.unknown_devices;
  $("#network-status").textContent = `${data.network_status} · Online`;
  $("#subnet-value").textContent = data.subnet;
  $("#interval-value").textContent = data.scan_interval;
  $("#scanner-state").textContent = data.scanner_active ? "Scanner active" : "Scanner waiting";
  const count = data.alert_count;
  $("#nav-alert-count").textContent = count;
  $("#bell-count").textContent = count;
  $("#recent-alerts").innerHTML = data.recent_alerts.length ? data.recent_alerts.map(alertMarkup).join("") : emptyMarkup("No recent security alerts.");
}

async function refreshData() {
  [state.devices, state.alerts, state.history] = await Promise.all([api("/api/devices"), api("/api/alerts"), api("/api/history")]);
  renderDevices(); renderAlerts(); renderHistory(); await refreshOverview();
}

function alertMarkup(alert) {
  const normal = alert.alert_type === "Normal";
  return `<div class="alert-row"><span class="alert-icon ${normal ? "normal" : ""}">${normal ? "✓" : "⚠"}</span><main><strong>${escapeHtml(alert.message)}</strong><small>${escapeHtml(alert.ip)} · ${formatTime(alert.created_at)}</small></main><span class="badge ${normal ? "normal" : "warning"}">${escapeHtml(alert.alert_type)}</span>${!normal ? `<button class="action-button" data-trust="${escapeHtml(alert.mac)}" data-ip="${escapeHtml(alert.ip)}">Trust</button>` : ""}</div>`;
}
function emptyMarkup(message) { return `<div class="empty-state muted">${message}</div>`; }
function renderDevices() {
  let devices = state.devices.filter((device) => state.filter === "all" || (state.filter === "trusted" ? device.is_trusted : state.filter === "unknown" ? !device.is_trusted : device.status === state.filter));
  if (state.search) devices = devices.filter((device) => Object.values(device).some((value) => String(value).toLowerCase().includes(state.search)));
  $("#device-count").textContent = `${devices.length} device${devices.length === 1 ? "" : "s"}`;
  $("#devices-table").innerHTML = devices.length ? devices.map((device) => `<tr><td><div class="device-name"><span class="device-icon">▣</span><strong>${escapeHtml(device.hostname || "Unknown")}</strong></div></td><td>${escapeHtml(device.ip)}</td><td>${escapeHtml(device.mac)}</td><td><span class="badge ${device.status}">${escapeHtml(device.status)}</span></td><td><span class="badge ${device.is_trusted ? "trusted" : "offline"}">${device.is_trusted ? "Trusted" : "Unknown"}</span></td><td>${formatTime(device.last_seen)}</td><td><button class="action-button ${device.is_trusted ? "untrust" : ""}" data-toggle-trust="${escapeHtml(device.mac)}" data-trusted="${device.is_trusted}">${device.is_trusted ? "Untrust" : "Trust"}</button></td></tr>`).join("") : `<tr><td colspan="7">${emptyMarkup("No devices match this filter.")}</td></tr>`;
}
function renderAlerts() {
  const alerts = state.alerts.filter((alert) => {
    const matchesType = state.alertFilter === "all" || alert.alert_type === state.alertFilter;
    const matchesSearch = !state.search || Object.values(alert).some((value) => String(value).toLowerCase().includes(state.search));
    return matchesType && matchesSearch;
  });
  $("#alerts-table").innerHTML = alerts.length ? alerts.map((alert) => `<div class="feed-row"><span class="alert-icon ${alert.alert_type === "Normal" ? "normal" : ""}">${alert.alert_type === "Normal" ? "✓" : "⚠"}</span><div class="feed-content"><strong>${escapeHtml(alert.message)}</strong><small>${escapeHtml(alert.ip)} · ${escapeHtml(alert.mac)} · ${formatTime(alert.created_at)}</small></div><span class="badge ${alert.alert_type === "Normal" ? "normal" : "warning"}">${escapeHtml(alert.alert_type)}</span></div>`).join("") : emptyMarkup("No security alerts match this filter."); 
}
function renderHistory() { $("#history-list").innerHTML = state.history.length ? state.history.map((item) => `<div class="timeline-item"><strong>${escapeHtml(item.event)} <span class="badge ${item.event === "Connected" || item.event === "Trusted" ? "normal" : "offline"}">${escapeHtml(item.mac)}</span></strong><small>${escapeHtml(item.ip)} · ${formatTime(item.timestamp)}</small></div>`).join("") : emptyMarkup("No device activity recorded."); }

document.addEventListener("click", async (event) => {
  const viewButton = event.target.closest("[data-view]");
  if (viewButton) showView(viewButton.dataset.view);
  const toggle = event.target.closest("[data-toggle-trust]");
  const trustAlert = event.target.closest("[data-trust]");
  try {
    if (toggle) await api("/api/devices/trust", { method: "POST", body: JSON.stringify({ mac: toggle.dataset.toggleTrust, trusted: toggle.dataset.trusted !== "true" }) });
    if (trustAlert) await api("/api/devices/trust", { method: "POST", body: JSON.stringify({ mac: trustAlert.dataset.trust, ip: trustAlert.dataset.ip, trusted: true }) });
    if (toggle || trustAlert) await refreshData();
  } catch (error) { window.alert(error.message); }
});
document.querySelectorAll(".filter:not(.alert-filter)").forEach((button) => button.addEventListener("click", () => { document.querySelectorAll(".filter:not(.alert-filter)").forEach((item) => item.classList.remove("active")); button.classList.add("active"); state.filter = button.dataset.filter; renderDevices(); }));
document.querySelectorAll(".alert-filter").forEach((button) => button.addEventListener("click", () => { document.querySelectorAll(".alert-filter").forEach((item) => item.classList.remove("active")); button.classList.add("active"); state.alertFilter = button.dataset.alertFilter; renderAlerts(); }));
on("#global-search", "input", (event) => { state.search = event.target.value.toLowerCase(); renderDevices(); renderAlerts(); });
on("#add-device-button", "click", () => $("#device-modal")?.showModal());
on("#device-form", "submit", async (event) => { event.preventDefault(); try { await api("/api/devices/trust", { method: "POST", body: JSON.stringify({ mac: $("#mac-input").value, ip: $("#ip-input").value || "Unknown", trusted: true }) }); $("#device-modal")?.close(); event.target.reset(); await refreshData(); } catch (error) { window.alert(error.message); } });
on("#clear-alerts", "click", async () => { try { await api("/api/alerts/clear", { method: "POST" }); await refreshData(); } catch (error) { window.alert(error.message); } });
on("#settings-form", "submit", async (event) => { event.preventDefault(); const message = $("#settings-message"); try { await api("/api/settings", { method: "POST", body: JSON.stringify({ subnet: $("#settings-subnet").value, scan_interval: Number($("#settings-interval").value), desktop_notifications: $("#settings-notifications").checked }) }); message.textContent = "Settings saved."; message.style.color = ""; await refreshData(); } catch (error) { message.textContent = error.message; message.style.color = "#f87171"; } });

async function loadSettings() { const settings = await api("/api/settings"); $("#settings-subnet").value = settings.subnet; $("#settings-interval").value = settings.scan_interval; $("#settings-notifications").checked = Boolean(settings.desktop_notifications); }
refreshData().then(loadSettings).catch((error) => window.alert(error.message));
setInterval(() => refreshData().catch((error) => console.error("NetGuard refresh failed:", error)), 5000);
