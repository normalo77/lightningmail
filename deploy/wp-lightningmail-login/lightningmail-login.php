<?php
/**
 * Plugin Name: lightningmail Login
 * Description: „Mit lightningmail anmelden“ (OIDC, passwortlos) auf Login- und Registrierungsseite.
 * Version: 0.1
 * License: MIT
 * Author: lightningmail
 */
if (!defined('ABSPATH')) exit;

define('LM_OPT', 'lm_login_settings');
define('LM_TRANS', 'lm_oidc_');

function lm_defaults() {
    return array(
        'issuer' => 'https://relay.lightningmail.app',
        'label' => '⚡ Mit lightningmail anmelden',
        'auto_register' => '1',
        'show_register' => '1',
    );
}
function lm_cfg() { return wp_parse_args(get_option(LM_OPT, array()), lm_defaults()); }

/* ---------------------------------------------------------------- admin */
add_action('admin_menu', 'lm_admin_page');
function lm_admin_page() {
    add_options_page('lightningmail Login', 'lightningmail Login', 'manage_options', 'lm-login', 'lm_admin_html');
}
function lm_admin_html() {
    if (isset($_POST['lm_save']) && current_user_can('manage_options')) {
        check_admin_referer('lm_save');
        update_option(LM_OPT, array(
            'issuer' => esc_url_raw(trim($_POST['lm_issuer'] ?? '')),
            'label' => sanitize_text_field($_POST['lm_label'] ?? ''),
            'auto_register' => !empty($_POST['lm_auto']) ? '1' : '',
            'show_register' => !empty($_POST['lm_showreg']) ? '1' : '',
        ));
        echo '<div class="notice notice-success"><p>Gespeichert.</p></div>';
    }
    $c = lm_cfg(); ?>
    <div class="wrap"><h1>lightningmail Login</h1>
    <form method="post">
    <?php wp_nonce_field('lm_save'); ?>
    <table class="form-table">
    <tr><th>Relay (Issuer)</th><td><input name="lm_issuer" class="regular-text" value="<?php echo esc_attr($c['issuer']); ?>"></td></tr>
    <tr><th>Knopf-Beschriftung</th><td><input name="lm_label" class="regular-text" value="<?php echo esc_attr($c['label']); ?>"></td></tr>
    <tr><th>Neue Nutzer anlegen</th><td><label><input type="checkbox" name="lm_auto" <?php checked($c['auto_register'], '1'); ?>> Erlaubt, wenn die E-Mail noch kein Konto hat</label></td></tr>
    <tr><th>Auf Registrierungsseite</th><td><label><input type="checkbox" name="lm_showreg" <?php checked($c['show_register'], '1'); ?>> Button auch unter register Form</label></td></tr>
    </table>
    <p><button class="button button-primary">Speichern</button></p>
    </form>
    <p class="description">Der Button benötigt <a href="https://lightningmail.app/embed/bmail-login.js">bmail-login.js</a> — dieser Plugin-Flow kommt ohne JavaScript aus und funktioniert auch ohne es.</p>
    </div><?php
}

register_deactivation_hook(__FILE__, 'lm_deactivate');
function lm_deactivate() {
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '" . LM_TRANS . "%'");
}

/* ------------------------------------------------------- button output */
add_action('login_form', 'lm_button');
add_action('register_form', 'lm_button');
function lm_button() {
    $c = lm_cfg();
    if (!empty($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], 'action=register') !== false && $c['show_register'] !== '1') return;
    $url = add_query_arg(array('lm_oidc_start' => '1', '_lmn' => wp_create_nonce('lm_oidc')), wp_login_url());
    echo '<p style="margin:1em 0"><a href="' . esc_url($url) . '" style="display:inline-block;background:#f7931a;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:600">'
        . esc_html($c['label']) . '</a></p>';
}

/* --------------------------------------------------------- flow: start */
add_action('init', 'lm_flow');
function lm_flow() {
    if (isset($_GET['lm_oidc_start'])) { lm_start(); return; }
    if (isset($_GET['code'])) { lm_callback(); return; }
}

function lm_start() {
    if (!wp_verify_nonce($_REQUEST['_lmn'] ?? '', 'lm_oidc')) wp_die('stale link');
    $c = lm_cfg();
    $disc = lm_json($c['issuer'] . '/.well-known/openid-configuration');
    if (!$disc) wp_die('Relay nicht erreichbar');
    $state = bin2hex(random_bytes(12)); $nonce = bin2hex(random_bytes(12));
    $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    set_transient(LM_TRANS . $state, array('verifier' => $verifier, 'nonce' => $nonce, 'issuer' => $c['issuer']), 600);
    $redir = add_query_arg('lm_oidc_cb', '1', wp_login_url());
    wp_redirect($disc['authorization_endpoint'] . '?' . http_build_query(array(
        'response_type' => 'code',
        'client_id' => home_url(),                 // unsere Own-Origin ist die Kennung
        'redirect_uri' => $redir,
        'scope' => 'openid email',
        'state' => $state, 'nonce' => $nonce,
        'code_challenge' => $challenge, 'code_challenge_method' => 'S256')));
    exit;
}

/* ------------------------------------------------------ flow: callback */
function lm_callback() {
    if (!isset($_GET['lm_oidc_cb'], $_GET['code'], $_GET['state'])) return;
    $c = lm_cfg();
    $state = substr($_GET['state'], 0, 128);
    $data = get_transient(LM_TRANS . $state);
    if (!$data) wp_die('Login abgelaufen (state unbekannt)');
    delete_transient(LM_TRANS . $state);
    $disc = lm_json($data['issuer'] . '/.well-known/openid-configuration');
    $tok = wp_remote_post($disc['token_endpoint'], array('timeout' => 15,
        'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
        'body' => array('grant_type' => 'authorization_code', 'code' => $_GET['code'],
            'client_id' => home_url(), 'redirect_uri' => add_query_arg('lm_oidc_cb', '1', wp_login_url()),
            'code_verifier' => $data['verifier'])));
    if (is_wp_error($tok)) wp_die('token endpoint: ' . $tok->get_error_message());
    $body = json_decode(wp_remote_retrieve_body($tok), true);
    if (empty($body['id_token'])) wp_die('id_token fehlt: ' . substr(wp_remote_retrieve_body($tok), 0, 200));
    $claims = lm_verify_jwt($body['id_token'], $data['issuer'], home_url(), $data['nonce']);
    if (!$claims) wp_die('ID-Token ungueltig');

    $email = $claims['email'];
    $user = get_user_by('email', $email);
    if (!$user) {
        if ($c['auto_register'] !== '1') wp_die('Kein Konto fuer ' . esc_html($email));
        $user_id = wp_create_user('lm_' . substr(hash('sha256', $email), 0, 10), wp_generate_password(24, true, true), $email);
        if (is_wp_error($user_id)) wp_die($user_id->get_error_message());
        $user = get_user_by('id', $user_id);
    }
    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID, true, is_ssl());
    do_action('wp_login', $user->user_login, $user);
    wp_redirect( apply_filters('lm_redirect', admin_url()) );
    exit;
}

/* ------------------------------------------ ES256 verify, no libraries */
function lm_json($url) {
    $r = wp_remote_get($url, array('timeout' => 15));
    if (is_wp_error($r)) return null;
    return json_decode(wp_remote_retrieve_body($r), true);
}

function lm_b64u($s) { return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4)); }

function lm_verify_jwt($jwt, $issuer, $client_id, $nonce) {
    $p = explode('.', $jwt);
    if (count($p) !== 3) return null;
    $hdr = json_decode(lm_b64u($p[0]), true); $cl = json_decode(lm_b64u($p[1]), true);
    if (($hdr['alg'] ?? '') !== 'ES256') return null;
    if (($cl['iss'] ?? '') !== $issuer) return null;
    if (($cl['aud'] ?? '') !== $client_id) return null;
    if (($cl['nonce'] ?? '') !== $nonce) return null;
    if (time() - 30 >= ($cl['exp'] ?? 0)) return null;
    if (time() < (($cl['iat'] ?? 0) - 300)) return null;
    $jwks = lm_json($issuer . '/oidc/jwks');
    if (!$jwks) return null;
    foreach ($jwks['keys'] as $k) {
        if (($k['kty'] ?? '') !== 'EC' || ($k['crv'] ?? '') !== 'P-256') continue;
        if (isset($hdr['kid']) && ($k['kid'] ?? '') !== $hdr['kid']) continue;
        $pub = "\x04" . lm_b64u($k['x']) . lm_b64u($k['y']);
        // SPKI DER fuer P-256 public key (fester Praefix, dann Bitstring)
        $spki = hex2bin('3059301306072A8648CE3D020106082A8648CE3D030107034200') . $pub;
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        if (!$key) continue;
        $sig = lm_b64u($p[2]);
        if (strlen($sig) !== 64) continue;
        // JOSE r||s -> DER (openssl will ASN.1 Sequence)
        $der = lm_sig_der(substr($sig, 0, 32), substr($sig, 32, 32));
        $res = openssl_verify($p[0] . '.' . $p[1], $der, $key, OPENSSL_ALGO_SHA256);
        if ($res === 1) return $cl;
    }
    return null;
}

function lm_sig_der($r, $s) {
    foreach (array('r', 's') as $n) {
        $v = ltrim($$n, "\x00");
        if ($v === '') $v = "\x00";
        if (ord($v[0]) > 0x7f) $v = "\x00" . $v;
        $$n = "\x02" . chr(strlen($v)) . $v;
    }
    $seq = $r . $s;
    return "\x30" . chr(strlen($seq)) . $seq;
}
