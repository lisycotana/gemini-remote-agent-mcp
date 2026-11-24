const DEFAULTS = {
  enabled: false,
  strategy: "allow_once_first",
  autoContinue: false,
  showHud: true,
  perTaskLimit: 15,
  dailyLimit: 100,
  healthUrl: "http://127.0.0.1:8000/healthz",
};

const fields = ["enabled", "strategy", "autoContinue", "showHud", "perTaskLimit", "dailyLimit", "healthUrl"];

chrome.storage.local.get(DEFAULTS, (stored) => {
  for (const id of fields) {
    const el = document.getElementById(id);
    if (el.type === "checkbox") el.checked = Boolean(stored[id]);
    else el.value = stored[id];
    el.addEventListener("change", () => {
      const val = el.type === "checkbox" ? el.checked : el.type === "number" ? Number(el.value) : el.value.trim();
      chrome.storage.local.set({ [id]: val });
    });
  }
});

document.getElementById("killSwitch").addEventListener("click", () => {
  document.getElementById("enabled").checked = false;
  chrome.storage.local.set({ enabled: false });
  document.getElementById("healthResult").textContent = "Emergency Stop activated.";
});

document.getElementById("checkHealth").addEventListener("click", async () => {
  const url = document.getElementById("healthUrl").value.trim();
  const out = document.getElementById("healthResult");
  out.textContent = "Checking...";
  try {
    const res = await fetch(url, { cache: "no-store" });
    const data = await res.json();
    out.textContent = `HTTP ${res.status}: status=${data.status}, auth=${data.auth_enabled}`;
  } catch (err) {
    out.textContent = `Unreachable: ${err.message}`;
  }
});
