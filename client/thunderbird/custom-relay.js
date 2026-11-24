// External script for Thunderbird WebExtension CSP compliance (no inline <script>).
// Persists user-added custom relay URLs and selects them directly inside the
// extension tab (WebExtension host permissions bypass CORS without navigating away).
(function () {
  var sel = document.getElementById("l-relay");
  var wrap = document.getElementById("l-relay-custom-wrap");
  var inp = document.getElementById("l-relay-custom");
  var goBtn = document.getElementById("l-relay-custom-go");
  if (!sel || !wrap || !inp || !goBtn) return;

  var STORE_KEY = "lm_tb_custom_relays";

  function loadSaved() {
    try {
      var list = JSON.parse(localStorage.getItem(STORE_KEY) || "[]");
      return Array.isArray(list) ? list.filter(function (x) { return typeof x === "string" && x; }) : [];
    } catch (e) {
      return [];
    }
  }

  function saveList(list) {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(list)); } catch (e) {}
  }

  function normalizeOrigin(raw) {
    var s = String(raw || "").trim().replace(/\/+$/, "");
    if (!s) return "";
    if (!/^https?:\/\//i.test(s)) s = "https://" + s;
    try {
      var u = new URL(s);
      if (u.protocol !== "https:" && u.protocol !== "http:") return "";
      return u.origin;
    } catch (e) {
      return "";
    }
  }

  function ensureOption(origin) {
    for (var i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value === origin) return sel.options[i];
    }
    var opt = document.createElement("option");
    opt.value = origin;
    try {
      opt.textContent = "🌐 " + new URL(origin).host;
    } catch (e) {
      opt.textContent = origin;
    }
    var customOpt = sel.querySelector('option[value="__custom__"]');
    if (customOpt) sel.insertBefore(opt, customOpt);
    else sel.appendChild(opt);
    return opt;
  }

  // Restore saved custom relays into the dropdown before user interaction
  var saved = loadSaved();
  for (var i = 0; i < saved.length; i++) {
    ensureOption(saved[i]);
  }
  goBtn.textContent = "Hinzufügen";

  function addCustomRelay(ev) {
    if (ev) {
      ev.preventDefault();
      ev.stopImmediatePropagation();
    }
    var origin = normalizeOrigin(inp.value);
    if (!origin) {
      var err = document.getElementById("l-err");
      if (err) {
        err.textContent = "✗ Ungültige Relay-Adresse (z. B. https://relay.example.org)";
        err.className = "err";
      }
      return;
    }
    var list = loadSaved();
    if (list.indexOf(origin) === -1) {
      list.push(origin);
      saveList(list);
    }
    ensureOption(origin);
    sel.value = origin;
    wrap.style.display = "none";
    inp.value = "";
    sel.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Capture phase runs BEFORE main.ts's navigation-based handler
  goBtn.addEventListener("click", addCustomRelay, true);
  inp.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter") addCustomRelay(ev);
  }, true);
})();
