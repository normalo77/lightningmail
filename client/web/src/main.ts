/**
 * bmail PWA entry point.
 * Registers service worker and initializes the relay client.
 */
import { initApp } from "./client.js";

// Register service worker for offline support
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js");
}

// Auto-init with env vars or URL params (for interop testing)
const urlParams = new URLSearchParams(window.location.search);
const relay = urlParams.get("relay") || "http://127.0.0.1:8443";
const account = urlParams.get("account") || "demo";
const token = urlParams.get("token") || "";

if (token) {
  initApp(relay, account, token);
} else {
  const status = document.getElementById("status");
  if (status) status.textContent = "bitte Token setzen (?token=…)";
}