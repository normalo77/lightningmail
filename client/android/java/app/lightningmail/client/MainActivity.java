package app.lightningmail.client;

import android.Manifest;
import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Nativer Android-Client: WebView um die eingebettete PWA (assets/) plus
 * window.AndroidNative-Bridge — Hardware-Keystore-Vault (AES/GCM/NoPadding),
 * native Notifications und Datei-Up-/Downloads.
 */
public class MainActivity extends Activity {

    private static final String ALIAS = "lightningmail_vault_key";
    private static final String PREFS = "lm_native";
    private static final int REQ_UPLOAD = 1001;
    private static final int REQ_NOTIF = 1002;
    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;

    private WebView webView;
    private ValueCallback<Uri[]> uploadCallback;
    private int notifId = 1;

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
            public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                String u = r.getUrl().toString();
                if (u.startsWith("file:///android_asset/") || u.startsWith("about:")) return false;
                // externe Links (Impressum etc.) im Systembrowser öffnen
                try { startActivity(new Intent(Intent.ACTION_VIEW, r.getUrl())); } catch (Exception ignored) { }
                return true;
            }

            @Override
            public void onPageFinished(WebView v, String url) {
                if (url.startsWith("file:///android_asset/")) v.evaluateJavascript(BLOB_HOOK, null);
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> cb, FileChooserParams params) {
                if (uploadCallback != null) uploadCallback.onReceiveValue(null);
                uploadCallback = cb;
                try {
                    startActivityForResult(params.createIntent(), REQ_UPLOAD);
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

        webView.loadUrl("file:///android_asset/index.html");
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_UPLOAD && uploadCallback != null) {
            uploadCallback.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(res, data));
            uploadCallback = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    // --- Hardware-Keystore (AES/GCM) ---

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(ALIAS, null)).getSecretKey();
        }
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return kg.generateKey();
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

        /** Gespeicherten Hardware-Tresor loeschen. */
        @JavascriptInterface
        public void clearVault() {
            try {
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().remove("vault").apply();
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
