const DEF = { enabled: true, backend: "http://127.0.0.1:8000", history: true };
const cfg = async () => ({ ...DEF, ...(await chrome.storage.local.get(Object.keys(DEF))) });
chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
  const c = await cfg(); c.history = c.history && (await chrome.storage.local.get("historyEnabled")).historyEnabled !== false; if (!c.enabled || d.url.startsWith(c.backend)) return;
  const u = new URL(d.url), { exceptions = {} } = await chrome.storage.local.get("exceptions");
  if ((exceptions[u.hostname] || 0) > Date.now()) return;
  try {
    const r = await fetch(c.backend + "/api/url/assess", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: d.url.split(/[?#]/)[0], source: "extension" }) });
    const a = await r.json(); if (!r.ok) return;
    if (c.history) { const { history = [] } = await chrome.storage.local.get("history");
      history.unshift({ t: Date.now(), host: u.hostname, level: a.risk_level }); await chrome.storage.local.set({ history: history.slice(0, 50) }); }
    if (a.risk_level === "High" || a.risk_level === "Critical")
      chrome.tabs.update(d.tabId, { url: chrome.runtime.getURL("warning.html") + "?" + new URLSearchParams({ target: d.url, host: u.hostname, level: a.risk_level, signals: JSON.stringify(a.signals.map(s => s.explanation)) }) });
  } catch (e) { /* backend unreachable: fail open (documented) */ }
});
