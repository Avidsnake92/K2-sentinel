<?php
/**
 * K2 Sentinel – Definitions Updater
 *
 * Scarica i pattern di rilevamento da GitHub (raw JSON) ogni 24 ore
 * e li salva in wp_options come cache locale.
 * Se il download fallisce, usa le definizioni builtin come fallback.
 */
if ( ! defined( 'ABSPATH' ) ) exit;

// URL del file JSON su GitHub (raw)
// L'utente può cambiarlo da Impostazioni → Definizioni
define( 'K2S_DEFINITIONS_DEFAULT_URL',
    'https://raw.githubusercontent.com/Avidsnake92/wp-sentinel-definitions/main/definitions.json'
);

// ─── Hook cron giornaliero ────────────────────────────────────────
add_action( 'k2s_daily_definitions_update', 'k2s_fetch_remote_definitions' );

function k2s_schedule_definitions_update() {
    if ( ! wp_next_scheduled( 'k2s_daily_definitions_update' ) ) {
        wp_schedule_event( time(), 'daily', 'k2s_daily_definitions_update' );
    }
}
add_action( 'init', 'k2s_schedule_definitions_update' );

// ─── Scarica definizioni da GitHub ───────────────────────────────
function k2s_fetch_remote_definitions( $force = false ) {
    $url          = get_option( 'k2s_definitions_url', K2S_DEFINITIONS_DEFAULT_URL );
    $last_update  = (int) get_option( 'k2s_definitions_last_update', 0 );
    $cache_secs   = 23 * HOUR_IN_SECONDS; // aggiorna al massimo 1 volta ogni 23 ore

    if ( ! $force && ( time() - $last_update ) < $cache_secs ) {
        return [ 'status' => 'cached', 'message' => 'Definizioni già aggiornate di recente.' ];
    }

    $response = wp_remote_get( $url, [
        'timeout'    => 15,
        'user-agent' => 'WP-Sentinel/' . K2_SENTINEL_VERSION . '; ' . home_url(),
        'sslverify'  => true,
    ] );

    if ( is_wp_error( $response ) ) {
        k2s_log( 'warning', 'definitions_update', 'Download fallito: ' . $response->get_error_message() );
        return [ 'status' => 'error', 'message' => $response->get_error_message() ];
    }

    $code = wp_remote_retrieve_response_code( $response );
    if ( $code !== 200 ) {
        k2s_log( 'warning', 'definitions_update', "Download fallito: HTTP $code da $url" );
        return [ 'status' => 'error', 'message' => "HTTP $code" ];
    }

    $body = wp_remote_retrieve_body( $response );
    $data = json_decode( $body, true );

    if ( json_last_error() !== JSON_ERROR_NONE || empty( $data['version'] ) ) {
        k2s_log( 'warning', 'definitions_update', 'File definizioni non valido o malformato.' );
        return [ 'status' => 'error', 'message' => 'JSON non valido.' ];
    }

    // Salva nel DB
    update_option( 'k2s_remote_definitions',      $data );
    update_option( 'k2s_definitions_last_update', time() );
    update_option( 'k2s_definitions_version',     $data['version'] );

    k2s_log( 'info', 'definitions_update', "Definizioni aggiornate → v{$data['version']} ({$data['release_date']})" );

    return [
        'status'  => 'ok',
        'version' => $data['version'],
        'date'    => $data['release_date'],
        'php_patterns' => count( $data['php_patterns'] ?? [] ),
        'db_patterns'  => count( $data['db_patterns']  ?? [] ),
    ];
}

// ─── Restituisce i pattern attivi (remoti o builtin) ─────────────
function k2s_get_active_definitions() {
    $remote = get_option( 'k2s_remote_definitions', null );

    if ( ! empty( $remote['php_patterns'] ) && ! empty( $remote['db_patterns'] ) ) {
        return [
            'source'       => 'remote',
            'version'      => $remote['version'] ?? '?',
            'php_patterns' => $remote['php_patterns'],
            'db_patterns'  => $remote['db_patterns'],
        ];
    }

    // Fallback builtin
    return [
        'source'  => 'builtin',
        'version' => K2_SENTINEL_VERSION . '-builtin',
        'php_patterns' => k2s_builtin_php_patterns(),
        'db_patterns'  => k2s_builtin_db_patterns(),
    ];
}

// ─── AJAX: aggiornamento manuale ──────────────────────────────────
add_action( 'wp_ajax_k2s_update_definitions', 'k2s_ajax_update_definitions' );

function k2s_ajax_update_definitions() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );

    $result = k2s_fetch_remote_definitions( true ); // force=true
    wp_send_json( $result );
}

// ─── Definizioni builtin (fallback) ──────────────────────────────
function k2s_builtin_php_patterns() {
    return [
        'eval_base64'        => '/eval\s*\(\s*base64_decode/i',
        'eval_gzinflate'     => '/eval\s*\(\s*gzinflate/i',
        'eval_str_rot'       => '/eval\s*\(\s*str_rot13/i',
        'shell_exec'         => '/shell_exec\s*\(/i',
        'exec_call'          => '/\bexec\s*\(/i',
        'system_call'        => '/\bsystem\s*\(/i',
        'passthru'           => '/passthru\s*\(/i',
        'preg_replace_e'     => '/preg_replace\s*\(\s*[\'"].*\/e/i',
        'base64_in_php'      => '/\$\w+\s*=\s*base64_decode\s*\(/i',
        'hex_encoded'        => '/\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}/i',
        'obfuscated_var'     => '/\${\s*[\'"]?\w+[\'"]?\s*}\s*\(/i',
        'create_function'    => '/create_function\s*\(/i',
        'wget_curl'          => '/\b(wget|curl)\s+http/i',
        'chmod_777'          => '/chmod\s*\(\s*\$\w+\s*,\s*0?777\s*\)/i',
        'file_put_php'       => '/file_put_contents\s*\(.*\.php/i',
        'backdoor_c99'       => '/c99|r57|shell\.php|webshell/i',
        'index_defacement'   => '/<meta\s+http-equiv\s*=\s*["\']refresh["\'][^>]*url\s*=/i',
        'prepend_inject'     => '/^<\?php\s+[^\r\n]{0,10}(eval|base64_decode|gzinflate|str_rot13)/i',
        'append_inject'      => '/(eval|base64_decode|gzinflate)\s*\([^\)]{5,}\)\s*;\s*\?>\s*$/i',
        'random_var_concat'  => '/\$[a-z]{1,3}\s*=\s*["\'][a-zA-Z0-9+\/=]{50,}["\']\s*;/i',
        'long_base64_string' => '/["\'][A-Za-z0-9+\/]{200,}={0,2}["\']/i',
        'self_reinstall'     => '/(file_get_contents|fopen|curl_exec)\s*\(.*http.*\)\s*.*eval/is',
        'add_admin_user'     => '/wp_insert_user|wp_create_user.*administrator/i',
        'update_siteurl'     => '/update_option\s*\(\s*["\']siteurl["\']/i',
    ];
}

function k2s_builtin_db_patterns() {
    return [
        'iframe_inject'   => '/<iframe[^>]+src\s*=\s*["\']https?:\/\//i',
        'script_inject'   => '/<script[^>]*src\s*=\s*["\']https?:\/\//i',
        'eval_in_content' => '/eval\s*\(\s*base64_decode/i',
        'hidden_link'     => '/display\s*:\s*none.*<a\s+href/i',
        'spam_keyword'    => '/\b(viagra|cialis|casino|poker|lottery|payday loan)\b/i',
        'phishing_url'    => '/href\s*=\s*["\'][^"\']*\.(ru|cn|tk|ml|ga|cf)\//i',
        'serialized_eval' => '/s:\d+:["\'].*eval\s*\(/i',
        'serialized_b64'  => '/s:\d+:["\'].*base64_decode/i',
        'widget_redirect' => '/header\s*\(\s*["\']Location:/i',
        'long_b64_in_db'  => '/[A-Za-z0-9+\/]{500,}={0,2}/',
        'malicious_cron'  => '/(curl_exec|shell_exec|exec|system|passthru)\s*\(/i',
        'post_js_redirect'=> '/window\.location\s*=\s*["\']https?:\/\//i',
        'courtesy_page'   => '/Sito\s+in\s+manutenzione|Under\s+Construction|Hacked\s+by/i',
    ];
}
