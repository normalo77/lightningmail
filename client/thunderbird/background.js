// ⚡-Toolbar-Knopf: öffnet lightningmail als Tab — oder fokussiert den offenen.
// Kein "tabs"-Permission nötig: Tab-Id wird hier gemerkt, tabs.get/update reichen.
let appTabId = null;

browser.tabs.onRemoved.addListener((id) => { if (id === appTabId) appTabId = null; });

browser.browserAction.onClicked.addListener(async () => {
  if (appTabId !== null) {
    try {
      const t = await browser.tabs.get(appTabId);
      await browser.tabs.update(appTabId, { active: true });
      await browser.windows.update(t.windowId, { focused: true });
      return;
    } catch { appTabId = null; } // Tab ist inzwischen weg
  }
  const tab = await browser.tabs.create({ url: browser.runtime.getURL("app/index.html") });
  appTabId = tab.id;
});
