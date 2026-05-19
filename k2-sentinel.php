<?php
/**
 * Plugin Name: K2 Sentinel – Antivirus & Firewall
 * Plugin URI:  https://k2tech.it/k2-sentinel
 * Description: Antivirus, Firewall, 2FA, Traffic Monitor e Integrità Core per WordPress.
 * Version:     1.2.4
 * Author:      K2Tech
 * License:     GPL-2.0+
 * Text Domain: k2-sentinel
 */
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'K2_SENTINEL_VERSION', '1.2.4' );
define( 'K2_SENTINEL_PATH',    plugin_dir_path( __FILE__ ) );
define( 'K2_SENTINEL_URL',     plugin_dir_url( __FILE__ ) );
define( 'K2S_PATH',            K2_SENTINEL_PATH );
define( 'K2S_URL',             K2_SENTINEL_URL );

// ─── Moduli ───────────────────────────────────────────────────────
foreach ( [
    'logger', 'definitions', 'scanner', 'firewall',
    'remediation', 'hardening', 'integrity',
    'traffic', 'two-factor', 'notifications', 'updater',
] as $module ) {
    require_once K2S_PATH . "includes/{$module}.php";
}

// ─── Attivazione ─────────────────────────────────────────────────
register_activation_hook( __FILE__, 'k2s_activate' );
register_deactivation_hook( __FILE__, 'k2s_deactivate' );

function k2s_activate() {
    k2s_create_log_table();
    k2s_create_traffic_table();
    k2s_init_quarantine_dir();
    foreach ( ['k2s_hourly_scan','k2s_hourly_digest'] as $hook ) {
        if ( ! wp_next_scheduled( $hook ) ) wp_schedule_event( time(), 'hourly', $hook );
    }
    k2s_fetch_remote_definitions( true );
}

function k2s_deactivate() {
    foreach ( ['k2s_hourly_scan','k2s_hourly_digest','k2s_daily_definitions_update'] as $hook ) {
        wp_clear_scheduled_hook( $hook );
    }
}

// ─── Scansione oraria ─────────────────────────────────────────────
add_action( 'k2s_hourly_scan', 'k2s_run_full_scan' );

function k2s_run_full_scan() {
    $threats = array_merge(
        k2s_scan_php_files(),
        k2s_scan_database(),
        k2s_check_core_integrity()
    );

    foreach ( $threats as $t ) {
        k2s_log( $t['level'], $t['type'], $t['detail'] );
        // Alert immediato per tipi ultra-critici
        k2s_send_critical_alert( $t['type'], $t['detail'] );
    }

    update_option( 'k2s_last_scan',    current_time( 'mysql' ) );
    update_option( 'k2s_last_threats', count( $threats ) );

    if ( ! empty( $threats ) ) k2s_auto_remediate( $threats );
}

// ─── Menu admin ───────────────────────────────────────────────────
add_action( 'admin_menu', 'k2s_admin_menu' );

function k2s_admin_menu() {
    add_menu_page( 'K2 Sentinel', 'K2 Sentinel', 'manage_options', 'k2-sentinel', 'k2s_dashboard_page', 'dashicons-shield', 80 );

    $pages = [
        [ 'Dashboard',       'Dashboard',       'k2-sentinel',           'k2s_dashboard_page'  ],
        [ 'Log',             'Log Minacce',     'k2-sentinel-log',       'k2s_log_page'        ],
        [ 'Firewall',        'Firewall',        'k2-sentinel-fw',        'k2s_firewall_page'   ],
        [ 'Traffic Monitor', 'Traffic',      'k2-sentinel-traffic',   'k2s_traffic_page'    ],
        [ 'Integrità Core',  'Core Integrity','k2-sentinel-integrity', 'k2s_integrity_page'  ],
        [ 'Hardening',       'Hardening',    'k2-sentinel-hardening', 'k2s_hardening_page'  ],
        [ 'Quarantena',      'Quarantena',   'k2-sentinel-quarantine','k2s_quarantine_page' ],
        [ 'Impostazioni',    'Impostazioni',    'k2-sentinel-settings',  'k2s_settings_page'   ],
    ];

    foreach ( $pages as $p ) {
        add_submenu_page( 'k2-sentinel', $p[0], $p[1], 'manage_options', $p[2], $p[3] );
    }
}

// ─── Assets ───────────────────────────────────────────────────────
add_action( 'admin_enqueue_scripts', 'k2s_enqueue_assets' );

function k2s_enqueue_assets( $hook ) {
    if ( strpos( $hook, 'k2-sentinel' ) === false ) return;
    wp_enqueue_style(  'k2s-style',  K2S_URL . 'admin/css/style.css',  [], K2_SENTINEL_VERSION );
    wp_enqueue_script( 'k2s-script', K2S_URL . 'admin/js/script.js', ['jquery'], K2_SENTINEL_VERSION, true );
    wp_localize_script( 'k2s-script', 'k2s_ajax', [
        'ajax_url' => admin_url( 'admin-ajax.php' ),
        'nonce'    => wp_create_nonce( 'k2s_nonce' ),
    ]);
}

// ─── AJAX handlers ────────────────────────────────────────────────
add_action( 'wp_ajax_k2s_manual_scan', function() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die();
    k2s_run_full_scan();
    wp_send_json_success([
        'last_scan' => get_option( 'k2s_last_scan', '—' ),
        'threats'   => (int) get_option( 'k2s_last_threats', 0 ),
        'log'       => k2s_get_recent_logs( 10 ),
    ]);
});

add_action( 'wp_ajax_k2s_save_option', function() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die();
    $allowed = [
        'k2s_auto_remediation', 'k2s_max_login_attempts',
        'k2s_traffic_monitor_enabled', 'k2s_2fa_enabled',
    ];
    $key = sanitize_key( $_POST['key'] ?? '' );
    if ( in_array( $key, $allowed, true ) ) {
        update_option( $key, intval( $_POST['value'] ) );
        wp_send_json_success();
    }
    wp_send_json_error();
});

// ─── Pagine admin ─────────────────────────────────────────────────
function k2s_dashboard_page() {
    $last_scan    = get_option( 'k2s_last_scan', 'Mai' );
    $last_threats = (int) get_option( 'k2s_last_threats', 0 );
    $next_scan    = wp_next_scheduled( 'k2s_hourly_scan' );
    $fw_enabled   = get_option( 'k2s_firewall_enabled', 1 );
    $blocked_ips  = k2s_get_blocked_ips();
    $recent_logs  = k2s_get_recent_logs( 5 );
    include K2S_PATH . 'admin/dashboard.php';
}

function k2s_log_page() {
    $logs = k2s_get_recent_logs( 50 );
    include K2S_PATH . 'admin/log.php';
}

function k2s_firewall_page() {
    if ( isset( $_POST['k2s_fw_save'] ) && check_admin_referer( 'k2s_fw_nonce' ) ) {
        update_option( 'k2s_firewall_enabled', isset( $_POST['fw_enabled'] ) ? 1 : 0 );
        update_option( 'k2s_block_bad_bots',   isset( $_POST['block_bots'] ) ? 1 : 0 );
        update_option( 'k2s_block_sql',        isset( $_POST['block_sql'] ) ? 1 : 0 );
        update_option( 'k2s_block_xss',        isset( $_POST['block_xss'] ) ? 1 : 0 );
        if ( ! empty( $_POST['new_blocked_ip'] ) ) {
            $ip = sanitize_text_field( $_POST['new_blocked_ip'] );
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) k2s_block_ip( $ip, 'Manuale' );
        }
        echo '<div class="k2s-notice success">✅ Impostazioni salvate.</div>';
    }
    if ( isset( $_GET['unblock'] ) && check_admin_referer( 'k2s_unblock' ) ) {
        k2s_unblock_ip( sanitize_text_field( $_GET['unblock'] ) );
    }
    $fw_enabled  = get_option( 'k2s_firewall_enabled', 1 );
    $block_bots  = get_option( 'k2s_block_bad_bots', 1 );
    $block_sql   = get_option( 'k2s_block_sql', 1 );
    $block_xss   = get_option( 'k2s_block_xss', 1 );
    $blocked_ips = k2s_get_blocked_ips();
    include K2S_PATH . 'admin/firewall.php';
}

function k2s_traffic_page()    { include K2S_PATH . 'admin/traffic.php'; }
function k2s_integrity_page()  { include K2S_PATH . 'admin/integrity.php'; }
function k2s_hardening_page()  { include K2S_PATH . 'admin/hardening.php'; }
function k2s_quarantine_page() { include K2S_PATH . 'admin/quarantine.php'; }

function k2s_settings_page() {
    if ( isset( $_POST['k2s_save_settings'] ) && check_admin_referer( 'k2s_settings_nonce' ) ) {
        update_option( 'k2s_email_alerts',    isset( $_POST['email_alerts'] ) ? 1 : 0 );
        update_option( 'k2s_alert_email',     sanitize_email( $_POST['alert_email'] ) );
        update_option( 'k2s_scan_depth',      intval( $_POST['scan_depth'] ) );
        update_option( 'k2s_definitions_url', esc_url_raw( $_POST['definitions_url'] ?? '' ) );
        update_option( 'k2s_2fa_enabled',     isset( $_POST['2fa_enabled'] ) ? 1 : 0 );
        echo '<div class="k2s-notice success">✅ Impostazioni salvate.</div>';
    }
    $email_alerts    = get_option( 'k2s_email_alerts', 0 );
    $alert_email     = get_option( 'k2s_alert_email', get_option( 'admin_email' ) );
    $scan_depth      = get_option( 'k2s_scan_depth', 3 );
    $def_url         = get_option( 'k2s_definitions_url', K2S_DEFINITIONS_DEFAULT_URL );
    $def_last_update = get_option( 'k2s_definitions_last_update', 0 );
    $defs            = k2s_get_active_definitions();
    $next_def_update = wp_next_scheduled( 'k2s_daily_definitions_update' );
    include K2S_PATH . 'admin/settings.php';
}
