const KEEPALIVE_ALARM = "mcp_helper_keepalive";

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 0.5 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== KEEPALIVE_ALARM) return;
  const tabs = await chrome.tabs.query({ url: "https://gemini.google.com/*" });
  for (const tab of tabs) {
    if (tab.id && tab.autoDiscardable !== false) {
      chrome.tabs.update(tab.id, { autoDiscardable: false }).catch(() => {});
    }
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "STALL_NOTIFY") {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
      title: "Gemini Remote MCP",
      message: msg.message || "MCP execution appears stalled or circuit breaker tripped.",
    });
    sendResponse({ ok: true });
    return true;
  }
  return false;
});
