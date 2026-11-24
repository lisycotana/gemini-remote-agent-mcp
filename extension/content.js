(() => {
  "use strict";

  const DEFAULTS = {
    enabled: false,
    strategy: "allow_once_first", // 'allow_once_first' avoids Gemini Web's Always-Allow reset bug
    autoContinue: false,
    showHud: true,
    cooldownMs: 2500,
    settleMs: 1800,
    perTaskLimit: 15,
    dailyLimit: 100,
    healthUrl: "http://127.0.0.1:8000/healthz",
  };

  const ALLOW_ONCE = [
    "allow once", "allow this time", "仅允许一次", "允许一次", "僅允許一次", "1回のみ許可", "今回のみ許可"
  ];
  const ALWAYS_ALLOW = [
    "always allow", "始终允许", "始終允許", "常に許可"
  ];
  const CONTINUE_WORDS = [
    "continue", "yes", "继续", "繼續", "続行"
  ];
  const BLOCKED_WORDS = [
    "delete", "remove", "deny", "cancel", "dismiss", "decline", "survey", "report", "sign out",
    "删除", "刪除", "拒绝", "拒絕", "取消", "关闭", "關閉", "削除", "拒否"
  ];
  const QUOTA_ERROR_PHRASES = [
    "reached your limit", "quota exceeded", "try again later", "已达上限", "配额已用完"
  ];

  let cfg = { ...DEFAULTS };
  let taskClicks = 0;
  let dailyClicks = 0;
  let lastClickAt = 0;
  let lastMutationAt = Date.now();
  let lastSnapshot = "";
  let stagnantHits = 0;
  let trippedReason = "";

  function isChatRoute() {
    const p = location.pathname;
    return !(/^\/(gems|extensions|settings|updates|faq)/i.test(p));
  }

  function collectButtons(root = document, out = []) {
    const nodes = root.querySelectorAll("button, [role='button'], [role='menuitem']");
    for (const el of nodes) {
      if (el.offsetParent !== null && !el.disabled) out.push(el);
    }
    const all = root.querySelectorAll("*");
    for (const el of all) {
      if (el.shadowRoot) collectButtons(el.shadowRoot, out);
    }
    return out;
  }

  function norm(text) {
    return (text || "").replace(/\s+/g, " ").trim().toLowerCase();
  }

  function matchesAny(text, list) {
    return list.some((k) => text === k || text.includes(k));
  }

  function trip(reason) {
    trippedReason = reason;
    cfg.enabled = false;
    chrome.storage.local.set({ enabled: false });
    chrome.runtime.sendMessage({ type: "STALL_NOTIFY", message: reason }).catch(() => {});
    renderHud();
  }

  function tick() {
    if (!cfg.enabled || trippedReason || !isChatRoute()) return;
    const now = Date.now();
    if (now - lastMutationAt < cfg.settleMs) return;
    if (now - lastClickAt < cfg.cooldownMs) return;

    const bodyText = norm(document.body?.innerText?.slice(-2000) || "");
    if (matchesAny(bodyText, QUOTA_ERROR_PHRASES)) {
      trip("Quota or service error detected — auto-approval halted.");
      return;
    }

    if (cfg.perTaskLimit > 0 && taskClicks >= cfg.perTaskLimit) {
      trip(`Per-task limit reached (${cfg.perTaskLimit}).`);
      return;
    }
    if (cfg.dailyLimit > 0 && dailyClicks >= cfg.dailyLimit) {
      trip(`Daily limit reached (${cfg.dailyLimit}).`);
      return;
    }

    const buttons = collectButtons();
    const primary = cfg.strategy === "always_allow_first" ? ALWAYS_ALLOW : ALLOW_ONCE;
    const secondary = cfg.strategy === "always_allow_first" ? ALLOW_ONCE : ALWAYS_ALLOW;

    let target = null;
    for (const list of [primary, secondary]) {
      target = buttons.find((b) => {
        const label = norm(b.innerText || b.getAttribute("aria-label"));
        return label && !matchesAny(label, BLOCKED_WORDS) && matchesAny(label, list);
      });
      if (target) break;
    }

    if (!target && cfg.autoContinue) {
      target = buttons.find((b) => {
        const label = norm(b.innerText || b.getAttribute("aria-label"));
        return label && !matchesAny(label, BLOCKED_WORDS) && CONTINUE_WORDS.includes(label);
      });
    }

    if (!target) return;

    const snap = bodyText.slice(-300);
    if (snap && snap === lastSnapshot) {
      stagnantHits += 1;
      if (stagnantHits >= 3) {
        trip("Stagnant output detected — circuit breaker tripped.");
        return;
      }
    } else {
      stagnantHits = 0;
      lastSnapshot = snap;
    }

    target.click();
    lastClickAt = now;
    taskClicks += 1;
    dailyClicks += 1;
    renderHud();
  }

  // Draggable floating HUD
  let hudEl = null;
  function ensureHud() {
    if (hudEl || !cfg.showHud) return;
    hudEl = document.createElement("div");
    hudEl.id = "mcp-auto-helper-hud";
    Object.assign(hudEl.style, {
      position: "fixed",
      right: "18px",
      bottom: "18px",
      zIndex: "2147483647",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
      fontSize: "12px",
      borderRadius: "12px",
      padding: "10px 12px",
      boxShadow: "0 8px 24px rgba(0,0,0,0.18)",
      border: "1px solid rgba(128,128,128,0.28)",
      backdropFilter: "blur(8px)",
      userSelect: "none",
      minWidth: "210px",
    });

    let dragging = false;
    let offsetX = 0;
    let offsetY = 0;
    hudEl.addEventListener("pointerdown", (e) => {
      if (e.button !== 0 || e.target.tagName === "BUTTON") return;
      dragging = true;
      const rect = hudEl.getBoundingClientRect();
      offsetX = e.clientX - rect.left;
      offsetY = e.clientY - rect.top;
      hudEl.setPointerCapture(e.pointerId);
    });
    hudEl.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      const x = Math.max(8, Math.min(window.innerWidth - hudEl.offsetWidth - 8, e.clientX - offsetX));
      const y = Math.max(8, Math.min(window.innerHeight - hudEl.offsetHeight - 8, e.clientY - offsetY));
      hudEl.style.left = `${x}px`;
      hudEl.style.top = `${y}px`;
      hudEl.style.right = "auto";
      hudEl.style.bottom = "auto";
    });
    hudEl.addEventListener("pointerup", () => { dragging = false; });

    document.body.appendChild(hudEl);
  }

  function renderHud() {
    if (!cfg.showHud) {
      if (hudEl) { hudEl.remove(); hudEl = null; }
      return;
    }
    ensureHud();
    const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    hudEl.style.background = dark ? "rgba(17,24,39,0.92)" : "rgba(255,255,255,0.94)";
    hudEl.style.color = dark ? "#f3f4f6" : "#111827";
    const status = trippedReason
      ? `Tripped`
      : cfg.enabled
      ? `Active (${cfg.strategy === "allow_once_first" ? "Once" : "Always"})`
      : "Paused";
    hudEl.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:6px;cursor:grab;">
        <strong>MCP Helper</strong>
        <span style="opacity:.8">${status} · ${taskClicks}/${cfg.perTaskLimit}</span>
      </div>
      <div style="display:flex;gap:6px;">
        <button id="mcp-hud-toggle" style="flex:1;padding:4px 8px;border:none;border-radius:6px;cursor:pointer;background:${cfg.enabled ? "#dc2626" : "#2563eb"};color:#fff;font-weight:600;">
          ${cfg.enabled ? "STOP" : "Start"}
        </button>
        <button id="mcp-hud-reset" style="padding:4px 8px;border:1px solid rgba(128,128,128,.35);border-radius:6px;cursor:pointer;background:transparent;color:inherit;">
          Reset
        </button>
      </div>
    `;
    hudEl.querySelector("#mcp-hud-toggle").onclick = () => {
      trippedReason = "";
      cfg.enabled = !cfg.enabled;
      chrome.storage.local.set({ enabled: cfg.enabled });
      renderHud();
    };
    hudEl.querySelector("#mcp-hud-reset").onclick = () => {
      trippedReason = "";
      taskClicks = 0;
      stagnantHits = 0;
      renderHud();
    };
  }

  const observer = new MutationObserver(() => { lastMutationAt = Date.now(); });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  chrome.storage.local.get(DEFAULTS, (stored) => {
    cfg = { ...DEFAULTS, ...stored };
    renderHud();
  });
  chrome.storage.onChanged.addListener((changes) => {
    for (const [k, v] of Object.entries(changes)) cfg[k] = v.newValue;
    if (changes.enabled?.newValue) trippedReason = "";
    renderHud();
  });

  setInterval(tick, 700);
})();
