package app.lightningmail.client;

import android.Manifest;
import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ClipData;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Environment;
import android.provider.OpenableColumns;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Nativer Android-Client: WebView um die eingebettete PWA (assets/) plus
 * window.AndroidNative-Bridge — Hardware-Keystore-Vault (AES/GCM/NoPadding),
 * native Notifications und Datei-Up-/Downloads.
 */
public class MainActivity extends Activity {

    private static final String ALIAS = "lightningmail_vault_key";
    private static final String ALIAS_BIO = "lightningmail_vault_bio_v2";
    private static final String PREFS = "lm_native";
    private static final String DEFAULT_RELAY = "https://lightningmail.app";
    private static final int REQ_UPLOAD = 1001;
    private static final int REQ_NOTIF = 1002;
    private static final int REQ_KEYFILE = 1003;
    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;

    private WebView webView;
    private ValueCallback<Uri[]> uploadCallback;
    private int notifId = 1;

    /** Heim-Relay, den der Nutzer in der App per "Eigenes Relay" gesetzt hat
     *  (Etappe O) — oder der Default. Start-, Navigations- und Fehler-Pfade
     *  richten sich danach. */
    private String homeRelay() {
        try {
            String r = getSharedPreferences(PREFS, MODE_PRIVATE).getString("home_relay", "");
            if (r != null && r.startsWith("http")) return r;
        } catch (Exception ignored) { }
        return DEFAULT_RELAY;
    }

    // Blob-Downloads (.lmkey-Export): Anchor-Click abfangen, Blob als Data-URL
    // zur Java-Seite reichen, die ihn in den App-Downloads-Ordner schreibt.
    private static final String BLOB_HOOK = """
            (function(){ if(window.__lmBlobHook) return; window.__lmBlobHook=1;
             var oc=HTMLAnchorElement.prototype.click;
             HTMLAnchorElement.prototype.click=function(){
               var a=this;
               if(a.href&&a.href.indexOf('blob:')===0&&window.AndroidNative&&AndroidNative.saveDownload){
                 fetch(a.href).then(function(r){return r.blob();}).then(function(b){
                   var fr=new FileReader();
                   fr.onloadend=function(){ AndroidNative.saveDownload(a.download||'lightningmail-download.bin', fr.result); };
                   fr.readAsDataURL(b);
                 }).catch(function(){ oc.apply(a,[]); });
                 return;
               }
               return oc.apply(this,arguments);
             };
            })();""";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        setContentView(webView);

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);   // Pflicht für localStorage/sessionStorage
        s.setDatabaseEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(true);  // Pflicht für <input type="file"> (content://-URIs aus dem Android-Dateipicker)
        webView.setBackgroundColor(0xFF122338); // kein Weiß-Blitz beim Start
        webView.addJavascriptInterface(new NativeBridge(), "AndroidNative");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest r) {
                Uri uri = r.getUrl();
                if (uri != null && "https".equals(uri.getScheme()) && "lightningmail.app".equals(uri.getHost())) {
                    String path = uri.getPath();
                    if (path != null && (path.equals("/app") || path.startsWith("/app/"))) {
                        String rel = path.length() <= 5 ? "index.html" : path.substring(5);
                        if (rel.isEmpty() || rel.endsWith("/")) rel += "index.html";
                        Map<String, String> hdrs = new HashMap<>();
                        hdrs.put("Access-Control-Allow-Origin", "https://lightningmail.app");
                        hdrs.put("Cache-Control", "no-store");
                        try {
                            InputStream in = getAssets().open(rel);
                            String mime = "application/octet-stream";
                            String enc = null;
                            if (rel.endsWith(".html")) { mime = "text/html"; enc = "UTF-8"; }
                            else if (rel.endsWith(".js") || rel.endsWith(".mjs")) { mime = "text/javascript"; enc = "UTF-8"; }
                            else if (rel.endsWith(".css")) { mime = "text/css"; enc = "UTF-8"; }
                            else if (rel.endsWith(".json")) { mime = "application/json"; enc = "UTF-8"; }
                            else if (rel.endsWith(".svg")) { mime = "image/svg+xml"; enc = "UTF-8"; }
                            else if (rel.endsWith(".png")) { mime = "image/png"; }
                            else if (rel.endsWith(".woff")) { mime = "font/woff"; }
                            return new WebResourceResponse(mime, enc, 200, "OK", hdrs, in);
                        } catch (Exception notFound) {
                            return new WebResourceResponse("text/plain", "UTF-8", 404, "Not Found",
                                    hdrs, new ByteArrayInputStream(new byte[0]));
                        }
                    }
                }
                return null;
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                String u = r.getUrl().toString();
                if (u.startsWith(homeRelay() + "/app") || u.startsWith("about:")) return false;
                // externe Links (Impressum etc.) im Systembrowser öffnen
                try { startActivity(new Intent(Intent.ACTION_VIEW, r.getUrl())); } catch (Exception ignored) { }
                return true;
            }

            @Override
            public void onReceivedError(WebView v, WebResourceRequest req, android.webkit.WebResourceError err) {
                // Fremd-Relay weg/offline: sonst hinge die App auf einer leeren
                // Fehlerseite — zurueck auf den eingebauten Default-Relay.
                if (req.isForMainFrame() && !homeRelay().equals(DEFAULT_RELAY)
                        && req.getUrl().toString().startsWith(homeRelay() + "/app")) {
                    getSharedPreferences(PREFS, MODE_PRIVATE).edit().remove("home_relay").apply();
                    Toast.makeText(MainActivity.this,
                            "Eigenes Relay nicht erreichbar — wieder auf lightningmail.app",
                            Toast.LENGTH_LONG).show();
                    v.loadUrl(DEFAULT_RELAY + "/app/index.html");
                }
            }

            @Override
            public void onPageFinished(WebView v, String url) {
                if (url != null && (url.startsWith(homeRelay() + "/app") || url.startsWith("https://lightningmail.app/app"))) {
                    v.evaluateJavascript(BLOB_HOOK, null);
                }
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> cb, FileChooserParams params) {
                if (uploadCallback != null) uploadCallback.onReceiveValue(null);
                uploadCallback = cb;
                try {
                    Intent i = new Intent(Intent.ACTION_GET_CONTENT);
                    i.addCategory(Intent.CATEGORY_OPENABLE);
                    i.setType("*/*");
                    if (params != null && params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE) {
                        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
                    }
                    startActivityForResult(Intent.createChooser(i, "Datei wählen"), REQ_UPLOAD);
                } catch (Exception e) {
                    uploadCallback = null;
                    return false;
                }
                return true;
            }
        });

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
        }

        // Etappe O: gemerktes Heim-Relay (aus "Eigenes Relay") direkt aufschalten;
        // die APK-Assets bleiben nur am Default-Relay gebuendelt (s.o.).
        // ?self=1 schaltet die UI dort synchron auf "dieses Relay" (kein Proxy-Pfad).
        String home = homeRelay();
        webView.loadUrl(home + "/app/index.html" + (home.equals(DEFAULT_RELAY) ? "" : "?self=1"));
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_KEYFILE) {
            if (res == RESULT_OK && data != null && data.getData() != null) {
                Uri uri = data.getData();
                try {
                    String name = "schluessel.lmkey";
                    try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
                        if (c != null && c.moveToFirst()) {
                            int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                            if (idx >= 0 && !c.isNull(idx)) name = c.getString(idx);
                        }
                    } catch (Exception ignored) { }
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    try (InputStream in = getContentResolver().openInputStream(uri)) {
                        if (in == null) throw new Exception("Kein Lesezugriff auf Datei");
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) != -1) {
                            bos.write(buf, 0, n);
                            if (bos.size() > 262144) throw new Exception("Datei zu groß (max. 256 kB)");
                        }
                    }
                    String nb64 = Base64.encodeToString(name.getBytes("UTF-8"), Base64.NO_WRAP);
                    String db64 = Base64.encodeToString(bos.toByteArray(), Base64.NO_WRAP);
                    webView.evaluateJavascript(
                            "window.onNativeKeyFile&&window.onNativeKeyFile('" + nb64 + "','" + db64 + "')", null);
                } catch (Exception e) {
                    String msg = String.valueOf(e.getMessage()).replace("'", "").replace("\n", " ");
                    webView.evaluateJavascript(
                            "window.onNativeKeyFileErr&&window.onNativeKeyFileErr('" + msg + "')", null);
                }
            }
            return;
        }
        if (req == REQ_UPLOAD && uploadCallback != null) {
            Uri[] uris = null;
            if (res == RESULT_OK && data != null) {
                ClipData cd = data.getClipData();
                if (cd != null && cd.getItemCount() > 0) {
                    uris = new Uri[cd.getItemCount()];
                    for (int i = 0; i < cd.getItemCount(); i++) uris[i] = cd.getItemAt(i).getUri();
                } else if (data.getData() != null) {
                    uris = new Uri[]{data.getData()};
                }
            }
            uploadCallback.onReceiveValue(uris);
            uploadCallback = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    // --- Hardware-Keystore (StrongBox -> TEE fallback, optional CryptoObject bio-binding) ---

    private static String jsEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("'", "\\'")
                .replace("\n", " ").replace("\r", " ");
    }

    private boolean hasStrongBox() {
        return Build.VERSION.SDK_INT >= 28
                && getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    /** True if Class-3 (strong) biometrics are enrolled and usable with CryptoObject. */
    private boolean hasStrongBiometric() {
        if (Build.VERSION.SDK_INT >= 30) {
            BiometricManager bm = getSystemService(BiometricManager.class);
            return bm != null
                    && bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    == BiometricManager.BIOMETRIC_SUCCESS;
        }
        if (Build.VERSION.SDK_INT >= 29) {
            BiometricManager bm = getSystemService(BiometricManager.class);
            @SuppressWarnings("deprecation")
            int st = bm != null ? bm.canAuthenticate() : BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE;
            return st == BiometricManager.BIOMETRIC_SUCCESS;
        }
        return false;
    }

    private SecretKey generateVaultKey(String alias, boolean bioBound, boolean tryStrongBox) throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256);
        if (bioBound) {
            b.setUserAuthenticationRequired(true);
            if (Build.VERSION.SDK_INT >= 30) {
                // timeout=0 enforces a fresh hardware CryptoObject auth for every encrypt/decrypt
                b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
            } else {
                @SuppressWarnings("deprecation")
                KeyGenParameterSpec.Builder ignored = b.setUserAuthenticationValidityDurationSeconds(-1);
            }
            b.setInvalidatedByBiometricEnrollment(true);
        }
        if (tryStrongBox && Build.VERSION.SDK_INT >= 28) {
            b.setIsStrongBoxBacked(true);
        }
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(b.build());
        return kg.generateKey();
    }

    private SecretKey getOrCreateKey(String alias, boolean bioBound) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(alias)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(alias, null)).getSecretKey();
        }
        if (hasStrongBox()) {
            try {
                return generateVaultKey(alias, bioBound, true);
            } catch (Exception ignored) {
                // StrongBox unavailable or rejected parameters on this OEM -> fall back to TEE
            }
        }
        return generateVaultKey(alias, bioBound, false);
    }

    private SecretKey getOrCreateKey() throws Exception {
        return getOrCreateKey(ALIAS, false);
    }

    private void deleteKeyAlias(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(alias)) ks.deleteEntry(alias);
        } catch (Exception ignored) { }
    }

    /** Returns "strongbox", "tee", or "software" for an AndroidKeyStore SecretKey. */
    private String detectBackend(SecretKey key) {
        try {
            SecretKeyFactory sf = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            KeyInfo info = (KeyInfo) sf.getKeySpec(key, KeyInfo.class);
            if (Build.VERSION.SDK_INT >= 31) {
                int lvl = info.getSecurityLevel();
                if (lvl == KeyProperties.SECURITY_LEVEL_STRONGBOX) return "strongbox";
                if (lvl == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT) return "tee";
                return "software";
            }
            @SuppressWarnings("deprecation")
            boolean hw = info.isInsideSecureHardware();
            if (!hw) return "software";
            return hasStrongBox() ? "strongbox" : "tee";
        } catch (Exception e) {
            return "tee";
        }
    }

    private BiometricPrompt buildCryptoPrompt(String title, String subtitle, Runnable onCancel) {
        BiometricPrompt.Builder b = new BiometricPrompt.Builder(this)
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButton("Abbrechen", getMainExecutor(), (d, w) -> onCancel.run());
        if (Build.VERSION.SDK_INT >= 30) {
            // CryptoObject requires BIOMETRIC_STRONG (cannot be combined with DEVICE_CREDENTIAL)
            b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        }
        return b.build();
    }

    private void sealVaultBiometricUi(String json, String acct, String base) {
        if (Build.VERSION.SDK_INT >= 29 && hasStrongBiometric()) {
            try {
                SecretKey key = getOrCreateKey(ALIAS_BIO, true);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                try {
                    c.init(Cipher.ENCRYPT_MODE, key);
                } catch (KeyPermanentlyInvalidatedException inv) {
                    deleteKeyAlias(ALIAS_BIO);
                    key = getOrCreateKey(ALIAS_BIO, true);
                    c.init(Cipher.ENCRYPT_MODE, key);
                }
                final String backend = detectBackend(key);
                final String sub = "strongbox".equals(backend)
                        ? "Schlüssel im Sicherheitschip (StrongBox) versiegeln"
                        : "Schlüssel im Hardware-Keystore (TEE) versiegeln";
                CancellationSignal sig = new CancellationSignal();
                BiometricPrompt prompt = buildCryptoPrompt("lightningmail Tresor sichern", sub, () ->
                        webView.evaluateJavascript(
                                "window.onNativeVaultSealed&&window.onNativeVaultSealed(false,'','Abgebrochen')", null));
                prompt.authenticate(new BiometricPrompt.CryptoObject(c), sig, getMainExecutor(),
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override
                            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                                try {
                                    Cipher authed = result.getCryptoObject().getCipher();
                                    byte[] iv = authed.getIV();
                                    byte[] ct = authed.doFinal(json.getBytes("UTF-8"));
                                    byte[] out = new byte[iv.length + ct.length];
                                    System.arraycopy(iv, 0, out, 0, iv.length);
                                    System.arraycopy(ct, 0, out, iv.length, ct.length);
                                    getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                                            .putString("vault_v2", Base64.encodeToString(out, Base64.NO_WRAP))
                                            .putString("vault_backend", backend)
                                            .putBoolean("vault_bio", true)
                                            .putString("vault_acct", acct == null ? "" : acct)
                                            .putString("vault_base", base == null ? "" : base)
                                            .remove("vault")
                                            .apply();
                                    webView.evaluateJavascript(
                                            "window.onNativeVaultSealed&&window.onNativeVaultSealed(true,'"
                                                    + jsEscape(backend) + "','')", null);
                                } catch (Exception e) {
                                    webView.evaluateJavascript(
                                            "window.onNativeVaultSealed&&window.onNativeVaultSealed(false,'','"
                                                    + jsEscape(String.valueOf(e.getMessage())) + "')", null);
                                }
                            }

                            @Override
                            public void onAuthenticationError(int errorCode, CharSequence errString) {
                                webView.evaluateJavascript(
                                        "window.onNativeVaultSealed&&window.onNativeVaultSealed(false,'','"
                                                + jsEscape(String.valueOf(errString)) + "')", null);
                            }
                        });
                return;
            } catch (Exception e) {
                webView.evaluateJavascript(
                        "window.onNativeVaultSealed&&window.onNativeVaultSealed(false,'','"
                                + jsEscape(String.valueOf(e.getMessage())) + "')", null);
                return;
            }
        }
        // Fallback for devices without enrolled strong biometrics or API < 29: StrongBox/TEE without CryptoObject
        try {
            SecretKey key = getOrCreateKey(ALIAS, false);
            String backend = detectBackend(key);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = c.getIV();
            byte[] ct = c.doFinal(json.getBytes("UTF-8"));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString("vault", Base64.encodeToString(out, Base64.NO_WRAP))
                    .putString("vault_backend", backend)
                    .putBoolean("vault_bio", false)
                    .putString("vault_acct", acct == null ? "" : acct)
                    .putString("vault_base", base == null ? "" : base)
                    .remove("vault_v2")
                    .apply();
            webView.evaluateJavascript(
                    "window.onNativeVaultSealed&&window.onNativeVaultSealed(true,'"
                            + jsEscape(backend) + "','')", null);
        } catch (Exception e) {
            webView.evaluateJavascript(
                    "window.onNativeVaultSealed&&window.onNativeVaultSealed(false,'','"
                            + jsEscape(String.valueOf(e.getMessage())) + "')", null);
        }
    }

    private void unlockVaultBiometricUi() {
        SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
        String b64v2 = sp.getString("vault_v2", "");
        if (!b64v2.isEmpty() && Build.VERSION.SDK_INT >= 29) {
            try {
                byte[] raw = Base64.decode(b64v2, Base64.NO_WRAP);
                if (raw.length <= GCM_IV_LEN) throw new Exception("Tresor-Daten beschädigt");
                KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
                if (!ks.containsAlias(ALIAS_BIO)) {
                    clearVaultPrefs();
                    webView.evaluateJavascript(
                            "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(false,'','Tresor-Schlüssel fehlt — bitte neu anmelden.')",
                            null);
                    return;
                }
                SecretKey key = ((KeyStore.SecretKeyEntry) ks.getEntry(ALIAS_BIO, null)).getSecretKey();
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                try {
                    c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, raw, 0, GCM_IV_LEN));
                } catch (KeyPermanentlyInvalidatedException inv) {
                    deleteKeyAlias(ALIAS_BIO);
                    clearVaultPrefs();
                    webView.evaluateJavascript(
                            "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(false,'','Neuer Fingerabdruck erkannt — Tresor aus Sicherheitsgründen zurückgesetzt. Bitte einmalig per Schlüsseldatei oder 24 Wörtern anmelden.')",
                            null);
                    return;
                }
                String backend = sp.getString("vault_backend", "tee");
                String sub = "strongbox".equals(backend)
                        ? "Fingerabdruck für StrongBox-Tresor bestätigen"
                        : "Fingerabdruck für Hardware-Tresor (TEE) bestätigen";
                CancellationSignal sig = new CancellationSignal();
                BiometricPrompt prompt = buildCryptoPrompt("lightningmail entsperren", sub, () ->
                        webView.evaluateJavascript(
                                "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(false,'','Abgebrochen')",
                                null));
                prompt.authenticate(new BiometricPrompt.CryptoObject(c), sig, getMainExecutor(),
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override
                            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                                try {
                                    Cipher authed = result.getCryptoObject().getCipher();
                                    byte[] pt = authed.doFinal(raw, GCM_IV_LEN, raw.length - GCM_IV_LEN);
                                    String pb64 = Base64.encodeToString(pt, Base64.NO_WRAP);
                                    webView.evaluateJavascript(
                                            "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(true,'"
                                                    + pb64 + "','')", null);
                                } catch (Exception e) {
                                    webView.evaluateJavascript(
                                            "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(false,'','"
                                                    + jsEscape(String.valueOf(e.getMessage())) + "')", null);
                                }
                            }

                            @Override
                            public void onAuthenticationError(int errorCode, CharSequence errString) {
                                webView.evaluateJavascript(
                                        "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(false,'','"
                                                + jsEscape(String.valueOf(errString)) + "')", null);
                            }
                        });
                return;
            } catch (Exception e) {
                webView.evaluateJavascript(
                        "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(false,'','"
                                + jsEscape(String.valueOf(e.getMessage())) + "')", null);
                return;
            }
        }
        // Legacy v1 vault fallback (decrypted after optional BiometricPrompt)
        String b64v1 = sp.getString("vault", "");
        if (b64v1.isEmpty()) {
            webView.evaluateJavascript(
                    "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(false,'','')", null);
            return;
        }
        try {
            byte[] raw = Base64.decode(b64v1, Base64.NO_WRAP);
            if (raw.length <= GCM_IV_LEN) throw new Exception("Tresor leer");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, getOrCreateKey(),
                    new GCMParameterSpec(GCM_TAG_BITS, raw, 0, GCM_IV_LEN));
            byte[] pt = c.doFinal(raw, GCM_IV_LEN, raw.length - GCM_IV_LEN);
            String pb64 = Base64.encodeToString(pt, Base64.NO_WRAP);
            webView.evaluateJavascript(
                    "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(true,'" + pb64 + "','')", null);
        } catch (Exception e) {
            webView.evaluateJavascript(
                    "window.onNativeVaultUnlocked&&window.onNativeVaultUnlocked(false,'','"
                            + jsEscape(String.valueOf(e.getMessage())) + "')", null);
        }
    }

    private void clearVaultPrefs() {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .remove("vault").remove("vault_v2")
                .remove("vault_backend").remove("vault_bio")
                .remove("vault_acct").remove("vault_base")
                .apply();
    }

    /** Nativen Android-Fingerabdruck-/PIN-Dialog öffnen (BiometricPrompt, API 28+). */
    private void promptBiometric() {
        if (Build.VERSION.SDK_INT < 28) {
            webView.evaluateJavascript("window.onNativeBioResult&&window.onNativeBioResult(true,'')", null);
            return;
        }
        try {
            android.os.CancellationSignal sig = new android.os.CancellationSignal();
            android.hardware.biometrics.BiometricPrompt.Builder b =
                    new android.hardware.biometrics.BiometricPrompt.Builder(this)
                            .setTitle("lightningmail entsperren")
                            .setSubtitle("Fingerabdruck bestätigen");
            if (Build.VERSION.SDK_INT >= 30) {
                b.setAllowedAuthenticators(
                        android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_WEAK
                      | android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL);
            } else {
                b.setNegativeButton("Abbrechen", getMainExecutor(),
                        (d, w) -> webView.evaluateJavascript(
                                "window.onNativeBioResult&&window.onNativeBioResult(false,'Abgebrochen')", null));
            }
            b.build().authenticate(sig, getMainExecutor(),
                    new android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(
                                android.hardware.biometrics.BiometricPrompt.AuthenticationResult result) {
                            webView.evaluateJavascript(
                                    "window.onNativeBioResult&&window.onNativeBioResult(true,'')", null);
                        }

                        @Override
                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                            String msg = String.valueOf(errString).replace("'", "").replace("\n", " ");
                            webView.evaluateJavascript(
                                    "window.onNativeBioResult&&window.onNativeBioResult(false,'" + msg + "')", null);
                        }
                    });
        } catch (Exception e) {
            String msg = String.valueOf(e.getMessage()).replace("'", "");
            webView.evaluateJavascript(
                    "window.onNativeBioResult&&window.onNativeBioResult(false,'" + msg + "')", null);
        }
    }

    private void postNotification(String title, String text) {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        NotificationChannel ch = new NotificationChannel("lm_mail", "Neue Mails",
                NotificationManager.IMPORTANCE_HIGH);
        nm.createNotificationChannel(ch);
        Notification n = new Notification.Builder(this, "lm_mail")
                .setSmallIcon(android.R.drawable.ic_dialog_email)
                .setContentTitle(title)
                .setContentText(text)
                .setAutoCancel(true)
                .build();
        nm.notify(notifId++, n);
    }

    /** window.AndroidNative — Bridge für die PWA. */
    class NativeBridge {

        /** Nativen Android-Dateipicker öffnen und Schlüsseldatei direkt per ContentResolver lesen. */
        @JavascriptInterface
        public void pickKeyFile() {
            runOnUiThread(() -> {
                try {
                    Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                    i.addCategory(Intent.CATEGORY_OPENABLE);
                    i.setType("*/*");
                    startActivityForResult(i, REQ_KEYFILE);
                } catch (Exception e) {
                    try {
                        Intent i2 = new Intent(Intent.ACTION_GET_CONTENT);
                        i2.addCategory(Intent.CATEGORY_OPENABLE);
                        i2.setType("*/*");
                        startActivityForResult(Intent.createChooser(i2, "Schlüsseldatei wählen"), REQ_KEYFILE);
                    } catch (Exception e2) {
                        String msg = String.valueOf(e2.getMessage()).replace("'", "");
                        webView.evaluateJavascript(
                                "window.onNativeKeyFileErr&&window.onNativeKeyFileErr('" + msg + "')", null);
                    }
                }
            });
        }

        /** Schluessel-JSON verschluesselt im AndroidKeyStore versiegeln. */
        @JavascriptInterface
        public void saveVault(String json) {
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, getOrCreateKey());
                byte[] iv = c.getIV();
                byte[] ct = c.doFinal(json.getBytes("UTF-8"));
                byte[] out = new byte[iv.length + ct.length];
                System.arraycopy(iv, 0, out, 0, iv.length);
                System.arraycopy(ct, 0, out, iv.length, ct.length);
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                        .putString("vault", Base64.encodeToString(out, Base64.NO_WRAP))
                        .apply();
            } catch (Exception ignored) { /* Tresor ist Komfort, Login geht auch ohne */ }
        }

        /** Entschluesseltes Vault-JSON oder "" (leer/kaputt/kein Key). */
        @JavascriptInterface
        public String loadVault() {
            try {
                String b64 = getSharedPreferences(PREFS, MODE_PRIVATE).getString("vault", "");
                if (b64.isEmpty()) return "";
                byte[] raw = Base64.decode(b64, Base64.NO_WRAP);
                if (raw.length <= GCM_IV_LEN) return "";
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, getOrCreateKey(),
                        new GCMParameterSpec(GCM_TAG_BITS, raw, 0, GCM_IV_LEN));
                byte[] pt = c.doFinal(raw, GCM_IV_LEN, raw.length - GCM_IV_LEN);
                return new String(pt, "UTF-8");
            } catch (Exception e) {
                return "";
            }
        }

        /** Return vault metadata without triggering decryption or biometrics. */
        @JavascriptInterface
        public String vaultInfo() {
            try {
                SharedPreferences sp = getSharedPreferences(PREFS, MODE_PRIVATE);
                boolean hasV2 = !sp.getString("vault_v2", "").isEmpty();
                boolean hasV1 = !sp.getString("vault", "").isEmpty();
                JSONObject o = new JSONObject();
                o.put("hasVault", hasV2 || hasV1);
                o.put("bioBound", hasV2 && sp.getBoolean("vault_bio", false));
                o.put("legacy", !hasV2 && hasV1);
                o.put("backend", sp.getString("vault_backend", hasStrongBox() ? "strongbox" : "tee"));
                o.put("strongBox", hasStrongBox());
                o.put("strongBio", hasStrongBiometric());
                o.put("acct", sp.getString("vault_acct", ""));
                o.put("base", sp.getString("vault_base", ""));
                return o.toString();
            } catch (Exception e) {
                return "{\"hasVault\":false}";
            }
        }

        /** Seal key JSON via hardware-bound CryptoObject BiometricPrompt (StrongBox -> TEE). */
        @JavascriptInterface
        public void sealVaultBiometric(String json, String acct, String base) {
            runOnUiThread(() -> sealVaultBiometricUi(json, acct, base));
        }

        /** Unlock sealed vault via hardware-bound CryptoObject BiometricPrompt. */
        @JavascriptInterface
        public void unlockVaultBiometric() {
            runOnUiThread(() -> unlockVaultBiometricUi());
        }

        /** Clear stored hardware vault and biometric keystore entry. */
        @JavascriptInterface
        public void clearVault() {
            try {
                clearVaultPrefs();
                deleteKeyAlias(ALIAS_BIO);
            } catch (Exception ignored) { }
        }

        /** Heim-Relay merken (Etappe O, "Eigenes Relay" in der App): nur
         *  Scheme+Host+Port als Origin, mehr nicht. */
        @JavascriptInterface
        public void setHomeRelay(String url) {
            try {
                Uri u = Uri.parse(url == null ? "" : url);
                String scheme = u.getScheme();
                if (u.getHost() == null || !("https".equals(scheme) || "http".equals(scheme))) return;
                int port = u.getPort();
                String origin = scheme + "://" + u.getHost() + (port > 0 ? ":" + port : "");
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                        .putString("home_relay", origin).apply();
            } catch (Exception ignored) { }
        }

        /** Heim-Relay-Merkung loeschen — zurueck zum eingebauten Default-Relay. */
        @JavascriptInterface
        public void clearHomeRelay() {
            try {
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().remove("home_relay").apply();
            } catch (Exception ignored) { }
        }

        /** Fingerabdruck-/Gerätesperre anfordern -> ruft window.onNativeBioResult(ok, err) auf. */
        @JavascriptInterface
        public void requestBiometricAuth() {
            runOnUiThread(() -> promptBiometric());
        }

        /** Native Notification (Kanal lm_mail). */
        @JavascriptInterface
        public void notifyMail(String title, String text) {
            runOnUiThread(() -> postNotification(title, text));
        }

        /** Data-URL (aus BLOB_HOOK) in den App-Downloads-Ordner schreiben. */
        @JavascriptInterface
        public void saveDownload(String name, String dataUrl) {
            try {
                int comma = dataUrl.indexOf(',');
                byte[] bytes = Base64.decode(dataUrl.substring(comma + 1), Base64.NO_WRAP);
                File dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                File f = new File(dir, name.replaceAll("[^A-Za-z0-9._-]", "_"));
                try (FileOutputStream fo = new FileOutputStream(f)) {
                    fo.write(bytes);
                }
                runOnUiThread(() -> Toast.makeText(MainActivity.this,
                        "Gespeichert: " + f.getAbsolutePath(), Toast.LENGTH_LONG).show());
            } catch (Exception ignored) { }
        }
    }
}
