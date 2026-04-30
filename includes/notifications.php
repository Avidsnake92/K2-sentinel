<?php
/**
 * K2 Sentinel – Smart Notifications
 * Digest orario invece di un'email per ogni minaccia.
 * Raggruppa eventi, priorità critica inviata subito.
 */
if ( ! defined( 'ABSPATH' ) ) exit;

// ─── Cron digest orario ───────────────────────────────────────────
add_action( 'k2s_hourly_digest', 'k2s_send_hourly_digest' );

function k2s_schedule_digest() {
    if ( ! wp_next_scheduled( 'k2s_hourly_digest' ) ) {
        wp_schedule_event( time(), 'hourly', 'k2s_hourly_digest' );
    }
}
add_action( 'init', 'k2s_schedule_digest' );

// ─── Invia il digest (raccoglie eventi dell'ultima ora) ───────────
function k2s_send_hourly_digest() {
    if ( ! get_option( 'k2s_email_alerts', 0 ) ) return;

    global $wpdb;
    $table = $wpdb->prefix . 'sentinel_log';

    // Prendi log dell'ultima ora non ancora inviati
    $since = date( 'Y-m-d H:i:s', time() - HOUR_IN_SECONDS );
    $logs  = $wpdb->get_results( $wpdb->prepare(
        "SELECT * FROM $table WHERE log_time >= %s AND level IN ('critical','warning') ORDER BY log_time DESC",
        $since
    ) );

    if ( empty( $logs ) ) return;

    $critical = array_filter( $logs, fn($l) => $l->level === 'critical' );
    $warnings = array_filter( $logs, fn($l) => $l->level === 'warning' );

    $to      = get_option( 'k2s_alert_email', get_option( 'admin_email' ) );
    $subject = sprintf( '[K2 Sentinel] %d %s – %s',
        count( $logs ),
        count( $logs ) === 1 ? 'evento' : 'eventi',
        get_bloginfo( 'name' )
    );

    $body  = "K2 Sentinel – Digest orario\n";
    $body .= home_url() . " | " . current_time( 'mysql' ) . "\n\n";
    $body .= "━━━━━━━━━━━━━━━━━━━━━━\n";
    $body .= "🔴 Critici  : " . count( $critical ) . "\n";
    $body .= "🟡 Warning  : " . count( $warnings ) . "\n";
    $body .= "━━━━━━━━━━━━━━━━━━━━━━\n\n";

    if ( ! empty( $critical ) ) {
        $body .= "EVENTI CRITICI:\n";
        foreach ( array_slice( $critical, 0, 10 ) as $l ) {
            $body .= "  [{$l->log_time}] {$l->type}\n  {$l->detail}\n\n";
        }
    }

    if ( ! empty( $warnings ) ) {
        $body .= "WARNING:\n";
        foreach ( array_slice( $warnings, 0, 10 ) as $l ) {
            $body .= "  [{$l->log_time}] {$l->type} – {$l->detail}\n";
        }
    }

    if ( count( $logs ) > 20 ) {
        $body .= "\n... e altri " . ( count( $logs ) - 20 ) . " eventi. Vedi il log completo:\n";
    }

    $body .= "\n" . admin_url( 'admin.php?page=k2-sentinel-log' ) . "\n\n";
    $body .= "K2 Sentinel v" . K2_SENTINEL_VERSION . " by K2Tech\n";

    wp_mail( $to, $subject, $body );
}

// ─── Alert immediato solo per eventi ULTRA critici ─────────────────
// (es: file core WP modificato, admin fantasma aggiunto)
function k2s_send_critical_alert( $type, $detail ) {
    if ( ! get_option( 'k2s_email_alerts', 0 ) ) return;

    $urgent_types = [
        'core_modified_file', 'core_extra_file',
        'ghost_admin', 'siteurl_hijack',
        'index_php_redirect', 'htaccess_redirect',
    ];

    if ( ! in_array( $type, $urgent_types, true ) ) return;

    // Anti-flood: non inviare la stessa tipologia più di 1 volta ogni 6 ore
    $flood_key = 'k2s_alert_flood_' . md5( $type );
    if ( get_transient( $flood_key ) ) return;
    set_transient( $flood_key, 1, 6 * HOUR_IN_SECONDS );

    $to      = get_option( 'k2s_alert_email', get_option( 'admin_email' ) );
    $subject = "[K2 Sentinel] 🚨 Allerta critica – $type – " . get_bloginfo( 'name' );

    $body  = "ALLERTA CRITICA IMMEDIATA\n\n";
    $body .= "Sito: " . home_url() . "\n";
    $body .= "Tipo: $type\n";
    $body .= "Dettaglio: $detail\n";
    $body .= "Ora: " . current_time( 'mysql' ) . "\n\n";
    $body .= "Vai al pannello: " . admin_url( 'admin.php?page=k2-sentinel' ) . "\n";

    wp_mail( $to, $subject, $body );
}
