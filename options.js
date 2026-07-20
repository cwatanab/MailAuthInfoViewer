"use strict";

const msg = (key) => browser.i18n.getMessage(key) || key;

const domainList = document.getElementById("domainList");
const domainInput = document.getElementById("domainInput");
const addBtn = document.getElementById("addBtn");
const exportBtn = document.getElementById("exportBtn");
const importBtn = document.getElementById("importBtn");
const importFile = document.getElementById("importFile");
const statusEl = document.getElementById("status");
const compactCheckbox = document.getElementById("compactMode");

// i18n
document.getElementById("title").textContent = msg("optionsTitle");
document.getElementById("displayTitle").textContent = msg("optionsDisplayTitle");
document.getElementById("displayDesc").textContent = msg("optionsDisplayDesc");
document.getElementById("compactLabel").textContent = msg("optionsCompactMode");
document.getElementById("whitelistTitle").textContent = msg("optionsWhitelistTitle");
document.getElementById("whitelistDesc").textContent = msg("optionsWhitelistDesc");
addBtn.textContent = msg("optionsAddDomain");
exportBtn.textContent = msg("optionsExport");
importBtn.textContent = msg("optionsImport");

const showStatus = (text) => {
  statusEl.textContent = text;
  setTimeout(() => { statusEl.textContent = ""; }, 3000);
};

const renderList = async () => {
  const stored = await browser.storage.local.get("trustedDomains");
  const domains = stored.trustedDomains || [];
  domains.sort();

  // 既存の子要素をすべて除去してから再構築する
  domainList.replaceChildren();

  if (domains.length === 0) {
    // エントリなし: 空状態メッセージを表示
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = msg("optionsNoEntries");
    domainList.appendChild(empty);
    return;
  }

  // 各ドメインの行を DOM API で構築
  for (const d of domains) {
    const item = document.createElement("div");
    item.className = "domain-item";

    const span = document.createElement("span");
    span.textContent = d;

    const btn = document.createElement("button");
    btn.className = "danger";
    btn.setAttribute("data-remove", d);
    btn.setAttribute("aria-label", msg("optionsRemove"));
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="bi bi-trash" viewBox="0 0 16 16"><path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0z"/><path d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4zM2.5 3h11V2h-11z"/></svg>`;

    item.appendChild(span);
    item.appendChild(btn);
    domainList.appendChild(item);
  }
};

// ドメイン追加
const addDomain = async () => {
  const raw = domainInput.value.trim().toLowerCase();
  if (!raw) return;
  let domain = raw;
  try {
    if (raw.includes("/")) {
      domain = new URL(raw.startsWith("http") ? raw : "http://" + raw).hostname;
    }
  } catch { /* そのまま使用 */ }
  domain = domain.replace(/^\.+|\.+$/g, "");
  if (!domain || !domain.includes(".")) return;

  const stored = await browser.storage.local.get("trustedDomains");
  const list = stored.trustedDomains || [];
  if (!list.includes(domain)) {
    list.push(domain);
    await browser.storage.local.set({ trustedDomains: list });
  }
  domainInput.value = "";
  await renderList();
};

addBtn.addEventListener("click", addDomain);
domainInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addDomain(); });

// ドメイン削除（イベント委譲）
domainList.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-remove]");
  if (!btn) return;
  const domain = btn.getAttribute("data-remove");
  const stored = await browser.storage.local.get("trustedDomains");
  const list = (stored.trustedDomains || []).filter(d => d !== domain);
  await browser.storage.local.set({ trustedDomains: list });
  await renderList();
});

// エクスポート（行区切りテキスト）
exportBtn.addEventListener("click", async () => {
  const stored = await browser.storage.local.get("trustedDomains");
  const domains = stored.trustedDomains || [];
  domains.sort();
  const text = domains.join("\n") + "\n";
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "maiv-trusted-domains.txt";
  a.click();
  URL.revokeObjectURL(url);
});

// インポート（行区切りテキスト）
importBtn.addEventListener("click", () => importFile.click());
importFile.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const lines = text.split(/[\r\n]+/).map(l => l.trim().toLowerCase()).filter(l => l && l.includes("."));
    if (lines.length === 0) {
      showStatus("No valid domains found");
      return;
    }
    const stored = await browser.storage.local.get("trustedDomains");
    const existing = new Set(stored.trustedDomains || []);
    let added = 0;
    for (const d of lines) {
      if (!existing.has(d)) { existing.add(d); added++; }
    }
    await browser.storage.local.set({ trustedDomains: Array.from(existing) });
    await renderList();
    showStatus(`Imported ${added} new domain(s)`);
  } catch (err) {
    showStatus("Import failed: " + err.message);
  }
  importFile.value = "";
});

// コンパクト表示設定: 起動時に現在値を復元し、変更時に保存する。
// 値は messagedisplay 側と共有する browser.storage.local の compactMode（boolean）。
const loadCompactMode = async () => {
  const stored = await browser.storage.local.get("compactMode");
  compactCheckbox.checked = stored.compactMode === true;
};

compactCheckbox.addEventListener("change", async () => {
  await browser.storage.local.set({ compactMode: compactCheckbox.checked });
  showStatus(msg("optionsSaved"));
});

// 初期表示
renderList();
loadCompactMode();
