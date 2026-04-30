<?php
/**
 * K2 Sentinel – Security Hardening
 * Misure di sicurezza base attivabili/disattivabili dal pannello
 */
if ( ! defined( 'ABSPATH' ) ) exit;

add_action( 'init', 'k2s_apply_hardening', 1 );

function k2s_apply_hardening() {
    $h = get_option( 'k2s_hardening', [] );

    // ── 1. Nascondi versione WordPress ────────────────────────────
    if ( ! empty( $h['hide_wp_version'] ) ) {
        remove_action( 'wp_head', 'wp_generator' );
        add_filter( 'the_generator', '__return_empty_string' );
        // Rimuovi version dai CSS/JS
        add_filter( 'style_loader_src',  'k2s_remove_ver_query', 9999 );
        add_filter( 'script_loader_src', 'k2s_remove_ver_query', 9999 );
    }

    // ── 2. Disabilita XML-RPC ──────────────────────────────────────
    if ( ! empty( $h['disable_xmlrpc'] ) ) {
        add_filter( 'xmlrpc_enabled', '__return_false' );
        add_filter( 'xmlrpc_methods', function() { return []; } );
        // Blocca a livello di richiesta
        if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
            status_header( 403 );
            die( 'XML-RPC disabilitato da K2 Sentinel.' );
        }
    }

    // ── 3. Disabilita REST API per utenti non loggati ─────────────
    if ( ! empty( $h['restrict_rest_api'] ) ) {
        add_filter( 'rest_authentication_errors', function( $result ) {
            if ( ! is_user_logged_in() ) {
                return new WP_Error(
                    'rest_not_logged_in',
                    'L\'API REST è disponibile solo per utenti autenticati.',
                    [ 'status' => 401 ]
                );
            }
            return $result;
        } );
    }

    // ── 4. Nascondi errori PHP in frontend ─────────────────────────
    if ( ! empty( $h['hide_php_errors'] ) && ! is_admin() ) {
        @ini_set( 'display_errors', 0 );
        @ini_set( 'display_startup_errors', 0 );
    }

    // ── 5. Disabilita file editing dall'admin WP ──────────────────
    if ( ! empty( $h['disable_file_edit'] ) ) {
        if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
            define( 'DISALLOW_FILE_EDIT', true );
        }
    }

    // ── 6. Forza SSL login/admin ───────────────────────────────────
    if ( ! empty( $h['force_ssl_admin'] ) ) {
        if ( ! defined( 'FORCE_SSL_ADMIN' ) ) {
            define( 'FORCE_SSL_ADMIN', true );
        }
    }

    // ── 7. Limita tentativi di login (brute force) ─────────────────
    if ( ! empty( $h['limit_login_attempts'] ) ) {
        add_action( 'wp_login_failed', 'k2s_track_failed_login' );
        add_filter( 'authenticate',    'k2s_check_login_attempts', 30, 3 );
    }

    // ── 8. Disabilita enumerazione utenti (?author=1) ──────────────
    if ( ! empty( $h['disable_user_enum'] ) ) {
        add_action( 'template_redirect', 'k2s_block_user_enum' );
        // Blocca anche via REST
        add_filter( 'rest_endpoints', function( $endpoints ) {
            if ( ! is_user_logged_in() ) {
                unset( $endpoints['/wp/v2/users'] );
                unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
            }
            return $endpoints;
        } );
    }

    // ── 9. Headers di sicurezza HTTP ──────────────────────────────
    if ( ! empty( $h['security_headers'] ) ) {
        add_action( 'send_headers', 'k2s_add_security_headers' );
    }

    // ── 10. Protezione wp-config.php e .htaccess tramite headers ──
    if ( ! empty( $h['protect_sensitive_files'] ) ) {
        add_action( 'send_headers', 'k2s_protect_sensitive_files' );
    }

    // ── 11. Disabilita pingback ────────────────────────────────────
    if ( ! empty( $h['disable_pingback'] ) ) {
        add_filter( 'wp_headers', function( $headers ) {
            unset( $headers['X-Pingback'] );
            return $headers;
        } );
        add_filter( 'xmlrpc_methods', function( $methods ) {
            unset( $methods['pingback.ping'] );
            unset( $methods['pingback.extensions.getPingbacks'] );
            return $methods;
        } );
    }

    // ── 12. Blocca hotlinking immagini ────────────────────────────
    // (gestito via .htaccess – vedi k2s_write_htaccess_rules)
}

// ─── Helpers ─────────────────────────────────────────────────────

function k2s_remove_ver_query( $src ) {
    return $src ? remove_query_arg( 'ver', $src ) : $src;
}

function k2s_block_user_enum() {
    if ( ! is_admin() && isset( $_GET['author'] ) ) {
        wp_redirect( home_url( '/' ), 301 );
        exit;
    }
}

function k2s_add_security_headers() {
    header( 'X-Content-Type-Options: nosniff' );
    header( 'X-Frame-Options: SAMEORIGIN' );
    header( 'X-XSS-Protection: 1; mode=block' );
    header( 'Referrer-Policy: strict-origin-when-cross-origin' );
    header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
    if ( is_ssl() ) {
        header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
    }
}

function k2s_protect_sensitive_files() {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $blocked = [ 'wp-config.php', 'wp-config-sample.php', 'readme.html', 'license.txt', '.htaccess' ];
    foreach ( $blocked as $f ) {
        if ( strpos( $uri, $f ) !== false ) {
            status_header( 403 );
            exit( 'Accesso negato.' );
        }
    }
}

// ── Brute force protection ────────────────────────────────────────
function k2s_track_failed_login( $username ) {
    $ip       = k2s_get_client_ip();
    $key      = 'k2s_login_fails_' . md5( $ip );
    $attempts = (int) get_transient( $key );
    set_transient( $key, $attempts + 1, 15 * MINUTE_IN_SECONDS );

    $max = (int) get_option( 'k2s_max_login_attempts', 5 );
    if ( $attempts + 1 >= $max ) {
        k2s_block_ip( $ip, 'Brute force login' );
        k2s_log( 'critical', 'brute_force', "IP bloccato per brute force login: $ip ($username)" );
    }
}

function k2s_check_login_attempts( $user, $username, $password ) {
    if ( empty( $username ) ) return $user;
    $ip = k2s_get_client_ip();
    if ( k2s_is_ip_blocked( $ip ) ) {
        return new WP_Error( 'k2s_blocked', 'Troppi tentativi di login. Riprova tra 15 minuti.' );
    }
    return $user;
}

// ── Scrive regole .htaccess aggiuntive ───────────────────────────
function k2s_write_htaccess_rules() {
    $h = get_option( 'k2s_hardening', [] );
    $htaccess = ABSPATH . '.htaccess';
    if ( ! is_writable( $htaccess ) ) return false;

    $content = file_get_contents( $htaccess );

    // Rimuovi vecchie regole K2 Sentinel
    $content = preg_replace(
        '/# BEGIN K2 Sentinel.*# END K2 Sentinel\n?/s',
        '',
        $content
    );

    $rules = "# BEGIN K2 Sentinel\n";

    if ( ! empty( $h['block_hotlinking'] ) ) {
        $domain = parse_url( home_url(), PHP_URL_HOST );
        $rules .= "<IfModule mod_rewrite.c>\n";
        $rules .= "RewriteEngine On\n";
        $rules .= "RewriteCond %{HTTP_REFERER} !^$\n";
        $rules .= "RewriteCond %{HTTP_REFERER} !^https?://(www\.)?$domain [NC]\n";
        $rules .= "RewriteRule \.(jpg|jpeg|png|gif|webp|svg)$ - [F,L]\n";
        $rules .= "</IfModule>\n";
    }

    if ( ! empty( $h['protect_sensitive_files'] ) ) {
        $rules .= "<FilesMatch \"(wp-config\\.php|\\.htaccess|readme\\.html|license\\.txt)\">\n";
        $rules .= "Order Deny,Allow\nDeny from all\n</FilesMatch>\n";
    }

    $rules .= "# END K2 Sentinel\n";

    $new_content = $rules . $content;
    return file_put_contents( $htaccess, $new_content ) !== false;
}

// AJAX: salva hardening + scrivi .htaccess
add_action( 'wp_ajax_k2s_save_hardening', 'k2s_ajax_save_hardening' );

function k2s_ajax_save_hardening() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );

    $settings = $_POST['hardening'] ?? [];
    $clean    = [];
    $allowed_keys = [
        'hide_wp_version', 'disable_xmlrpc', 'restrict_rest_api',
        'hide_php_errors', 'disable_file_edit', 'force_ssl_admin',
        'limit_login_attempts', 'disable_user_enum', 'security_headers',
        'protect_sensitive_files', 'disable_pingback', 'block_hotlinking',
    ];

    foreach ( $allowed_keys as $key ) {
        $clean[ $key ] = ! empty( $settings[ $key ] ) ? 1 : 0;
    }

    update_option( 'k2s_hardening', $clean );
    k2s_write_htaccess_rules();
    k2s_log( 'info', 'hardening_updated', 'Impostazioni hardening aggiornate.' );

    wp_send_json_success( [ 'message' => 'Impostazioni salvate.' ] );
}
