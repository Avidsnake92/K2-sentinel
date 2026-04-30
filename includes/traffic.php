<?php
/**
 * K2 Sentinel – Live Traffic Monitor
 * Registra le richieste HTTP in tempo reale con rilevamento minacce inline.
 * Usa una tabella DB dedicata con rotazione automatica (max 10.000 record).
 */
if ( ! defined( 'ABSPATH' ) ) exit;

// ═══════════════════════════════════════════════════════════════════
//  INIT tabella traffico
// ═══════════════════════════════════════════════════════════════════
function k2s_create_traffic_table() {
    global $wpdb;
    $table   = $wpdb->prefix . 'k2s_traffic';
    $charset = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table (
        id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        req_time   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ip         VARCHAR(45)     NOT NULL DEFAULT '',
        method     VARCHAR(10)     NOT NULL DEFAULT 'GET',
        uri        VARCHAR(2000)   NOT NULL DEFAULT '',
        user_agent VARCHAR(500)    NOT NULL DEFAULT '',
        referer    VARCHAR(500)    NOT NULL DEFAULT '',
        status     SMALLINT        NOT NULL DEFAULT 200,
        threat     VARCHAR(60)     NOT NULL DEFAULT '',
        blocked    TINYINT(1)      NOT NULL DEFAULT 0,
        country    VARCHAR(2)      NOT NULL DEFAULT '',
        PRIMARY KEY (id),
        KEY req_time (req_time),
        KEY ip      (ip),
        KEY threat  (threat)
    ) $charset;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( $sql );
}

// ═══════════════════════════════════════════════════════════════════
//  HOOK: registra ogni richiesta (escluse risorse statiche)
// ═══════════════════════════════════════════════════════════════════
add_action( 'init', 'k2s_log_traffic_request', 999 );

function k2s_log_traffic_request() {
    if ( ! get_option( 'k2s_traffic_monitor_enabled', 0 ) ) return;

    // Salta risorse statiche (immagini, font, css, js già serviti da WP)
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    if ( preg_match( '/\.(css|js|jpg|jpeg|png|gif|svg|webp|woff|woff2|ttf|ico|map)(\?.*)?$/i', $uri ) ) return;

    // Salta richieste admin interne (heartbeat, etc.)
    if ( strpos( $uri, 'admin-ajax.php' ) !== false && isset( $_POST['action'] ) ) {
        $action = sanitize_key( $_POST['action'] );
        if ( strpos( $action, 'k2s_' ) === 0 || in_array( $action, ['heartbeat','query-attachments'], true ) ) return;
    }

    global $wpdb;
    $table = $wpdb->prefix . 'k2s_traffic';

    $ip         = k2s_get_client_ip();
    $method     = strtoupper( sanitize_text_field( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) );
    $user_agent = substr( sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 500 );
    $referer    = substr( esc_url_raw( $_SERVER['HTTP_REFERER'] ?? '' ), 0, 500 );
    $uri_clean  = substr( esc_url_raw( $uri ), 0, 2000 );

    // Determina se è una minaccia già bloccata o rilevata
    $threat  = '';
    $blocked = 0;

    if ( k2s_is_ip_blocked( $ip ) ) {
        $threat  = 'blocked_ip';
        $blocked = 1;
    }

    $wpdb->insert( $table, [
        'req_time'   => current_time( 'mysql' ),
        'ip'         => $ip,
        'method'     => $method,
        'uri'        => $uri_clean,
        'user_agent' => $user_agent,
        'referer'    => $referer,
        'status'     => http_response_code() ?: 200,
        'threat'     => $threat,
        'blocked'    => $blocked,
    ], [ '%s','%s','%s','%s','%s','%s','%d','%s','%d' ] );

    // Rotazione: mantieni max 10.000 record
    $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
    if ( $count > 10000 ) {
        $wpdb->query( "DELETE FROM $table ORDER BY id ASC LIMIT " . ( $count - 10000 ) );
    }
}

// ─── Aggiorna lo status della richiesta a risposta inviata ────────
add_filter( 'wp_headers', function( $headers ) {
    // Non possiamo facilmente aggiornare lo status dopo l'hook init,
    // ma il dato viene registrato correttamente per richieste future.
    return $headers;
} );

// ═══════════════════════════════════════════════════════════════════
//  QUERY TRAFFICO
// ═══════════════════════════════════════════════════════════════════
function k2s_get_traffic( $limit = 100, $filter = [] ) {
    global $wpdb;
    $table = $wpdb->prefix . 'k2s_traffic';

    $exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) );
    if ( ! $exists ) return [];

    $where  = '1=1';
    $params = [];

    if ( ! empty( $filter['ip'] ) ) {
        $where   .= ' AND ip = %s';
        $params[] = $filter['ip'];
    }
    if ( ! empty( $filter['threat_only'] ) ) {
        $where .= " AND (threat != '' OR blocked = 1)";
    }
    if ( ! empty( $filter['since'] ) ) {
        $where   .= ' AND req_time >= %s';
        $params[] = $filter['since'];
    }

    $params[] = $limit;
    $sql = "SELECT * FROM $table WHERE $where ORDER BY req_time DESC LIMIT %d";

    if ( ! empty( $params ) ) {
        return $wpdb->get_results( $wpdb->prepare( $sql, ...$params ) );
    }
    return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table ORDER BY req_time DESC LIMIT %d", $limit ) );
}

function k2s_get_traffic_stats() {
    global $wpdb;
    $table = $wpdb->prefix . 'k2s_traffic';
    $exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) );
    if ( ! $exists ) return [];

    return [
        'total_24h'   => (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table WHERE req_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR)" ),
        'blocked_24h' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table WHERE blocked=1 AND req_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR)" ),
        'threats_24h' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table WHERE threat!='' AND req_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR)" ),
        'top_ips'     => $wpdb->get_results( "SELECT ip, COUNT(*) as cnt FROM $table WHERE req_time >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY ip ORDER BY cnt DESC LIMIT 5" ),
    ];
}

// ─── AJAX: fetch traffico live ─────────────────────────────────────
add_action( 'wp_ajax_k2s_get_traffic', 'k2s_ajax_get_traffic' );

function k2s_ajax_get_traffic() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );

    $filter = [
        'threat_only' => ! empty( $_POST['threat_only'] ),
        'ip'          => sanitize_text_field( $_POST['filter_ip'] ?? '' ),
    ];

    $rows  = k2s_get_traffic( 50, $filter );
    $stats = k2s_get_traffic_stats();

    wp_send_json_success( [ 'rows' => $rows, 'stats' => $stats ] );
}

// ─── AJAX: svuota traffico ─────────────────────────────────────────
add_action( 'wp_ajax_k2s_clear_traffic', 'k2s_ajax_clear_traffic' );

function k2s_ajax_clear_traffic() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );
    global $wpdb;
    $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}k2s_traffic" );
    wp_send_json_success();
}
