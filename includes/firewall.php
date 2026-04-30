<?php
if ( ! defined( 'ABSPATH' ) ) exit;

// ═══════════════════════════════════════════════════════════════════
//  FIREWALL – eseguito il prima possibile (plugins_loaded)
// ═══════════════════════════════════════════════════════════════════
add_action( 'plugins_loaded', 'k2s_firewall_init', 1 );

function k2s_firewall_init() {
    if ( ! get_option( 'k2s_firewall_enabled', 1 ) ) return;
    if ( is_admin() && ! wp_doing_ajax() ) return;

    $ip = k2s_get_client_ip();

    // 1. IP bloccato manualmente o da scansione
    if ( k2s_is_ip_blocked( $ip ) ) {
        k2s_log( 'critical', 'fw_block_ip', "Richiesta bloccata da IP: $ip" );
        k2s_deny_request( 'Il tuo indirizzo IP è stato bloccato.' );
    }

    // 2. Bot malevoli (user agent)
    if ( get_option( 'k2s_block_bad_bots', 1 ) ) {
        k2s_check_bad_bots();
    }

    // 3. SQL Injection
    if ( get_option( 'k2s_block_sql', 1 ) ) {
        k2s_check_sql_injection();
    }

    // 4. XSS
    if ( get_option( 'k2s_block_xss', 1 ) ) {
        k2s_check_xss();
    }
}

// ─── Ottieni IP reale del client ──────────────────────────────────
function k2s_get_client_ip() {
    $keys = [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' ];
    foreach ( $keys as $key ) {
        if ( ! empty( $_SERVER[ $key ] ) ) {
            $ip = trim( explode( ',', $_SERVER[ $key ] )[0] );
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
        }
    }
    return '0.0.0.0';
}

// ─── Bad Bots ────────────────────────────────────────────────────
function k2s_check_bad_bots() {
    $ua = strtolower( $_SERVER['HTTP_USER_AGENT'] ?? '' );
    $bad_bots = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
        'python-requests', 'go-http-client', 'libwww-perl',
        'dirbuster', 'dirb', 'wfuzz', 'hydra', 'acunetix',
        'havij', 'nessus', 'openvas', 'w3af', 'metasploit',
    ];
    foreach ( $bad_bots as $bot ) {
        if ( strpos( $ua, $bot ) !== false ) {
            $ip = k2s_get_client_ip();
            k2s_log( 'warning', 'fw_bad_bot', "Bot bloccato [$bot] da $ip" );
            k2s_block_ip( $ip, "Bot: $bot" );
            k2s_deny_request( 'Accesso negato.' );
        }
    }
}

// ─── SQL Injection ───────────────────────────────────────────────
function k2s_check_sql_injection() {
    $sql_patterns = [
        '/(\bUNION\b.*\bSELECT\b)/i',
        '/(\bSELECT\b.*\bFROM\b.*\bWHERE\b)/i',
        '/(\bINSERT\b.*\bINTO\b)/i',
        '/(\bDROP\b.*\bTABLE\b)/i',
        '/(\bDELETE\b.*\bFROM\b)/i',
        '/(\bUPDATE\b.*\bSET\b)/i',
        "/'.*\bOR\b.*'.*=.*'/i",
        '/--\s*$/',
        '/;\s*(DROP|DELETE|UPDATE|INSERT)/i',
        '/\bxp_cmdshell\b/i',
        '/INFORMATION_SCHEMA/i',
    ];

    $inputs = array_merge(
        array_values( $_GET  ?? [] ),
        array_values( $_POST ?? [] ),
        array_values( $_COOKIE ?? [] )
    );

    foreach ( $inputs as $val ) {
        if ( ! is_string( $val ) ) continue;
        $decoded = urldecode( $val );
        foreach ( $sql_patterns as $pattern ) {
            if ( preg_match( $pattern, $decoded ) ) {
                $ip = k2s_get_client_ip();
                k2s_log( 'critical', 'fw_sql_injection', "SQLi rilevato da $ip — pattern: $pattern" );
                k2s_block_ip( $ip, 'SQL Injection' );
                k2s_deny_request( 'Richiesta non valida.' );
            }
        }
    }
}

// ─── XSS ─────────────────────────────────────────────────────────
function k2s_check_xss() {
    $xss_patterns = [
        '/<script\b[^>]*>/i',
        '/javascript\s*:/i',
        '/on\w+\s*=\s*["\']?[^"\']*["\']?/i',
        '/document\.(cookie|write|location)/i',
        '/eval\s*\(/i',
        '/expression\s*\(/i',
        '/<\s*iframe/i',
        '/<\s*object/i',
        '/<\s*embed/i',
        '/vbscript\s*:/i',
        '/data\s*:\s*text\/html/i',
    ];

    $inputs = array_merge(
        array_values( $_GET  ?? [] ),
        array_values( $_POST ?? [] )
    );

    foreach ( $inputs as $val ) {
        if ( ! is_string( $val ) ) continue;
        $decoded = html_entity_decode( urldecode( $val ) );
        foreach ( $xss_patterns as $pattern ) {
            if ( preg_match( $pattern, $decoded ) ) {
                $ip = k2s_get_client_ip();
                k2s_log( 'warning', 'fw_xss', "XSS rilevato da $ip" );
                k2s_block_ip( $ip, 'XSS' );
                k2s_deny_request( 'Richiesta non valida.' );
            }
        }
    }
}

// ─── Gestione IP bloccati ────────────────────────────────────────
function k2s_is_ip_blocked( $ip ) {
    $blocked = get_option( 'k2s_blocked_ips', [] );
    return isset( $blocked[ $ip ] );
}

function k2s_block_ip( $ip, $reason = 'Auto' ) {
    $blocked = get_option( 'k2s_blocked_ips', [] );
    if ( ! isset( $blocked[ $ip ] ) ) {
        $blocked[ $ip ] = [
            'reason'   => $reason,
            'blocked_at' => current_time( 'mysql' ),
        ];
        update_option( 'k2s_blocked_ips', $blocked );
    }
}

function k2s_unblock_ip( $ip ) {
    $blocked = get_option( 'k2s_blocked_ips', [] );
    unset( $blocked[ $ip ] );
    update_option( 'k2s_blocked_ips', $blocked );
}

function k2s_get_blocked_ips() {
    return get_option( 'k2s_blocked_ips', [] );
}

// ─── Blocca la richiesta ─────────────────────────────────────────
function k2s_deny_request( $message = 'Accesso negato.' ) {
    status_header( 403 );
    nocache_headers();
    wp_die(
        esc_html( $message ),
        'K2 Sentinel – Accesso Negato',
        [ 'response' => 403 ]
    );
}
