<?php
if ( ! defined( 'ABSPATH' ) ) exit;

function k2s_create_log_table() {
    global $wpdb;
    $table   = $wpdb->prefix . 'sentinel_log';
    $charset = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table (
        id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        log_time   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        level      VARCHAR(20)     NOT NULL DEFAULT 'info',
        type       VARCHAR(60)     NOT NULL DEFAULT '',
        detail     TEXT            NOT NULL,
        PRIMARY KEY (id),
        KEY level   (level),
        KEY log_time (log_time)
    ) $charset;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( $sql );
}

function k2s_log( $level, $type, $detail ) {
    global $wpdb;
    $table = $wpdb->prefix . 'sentinel_log';
    $wpdb->insert( $table, [
        'log_time' => current_time( 'mysql' ),
        'level'    => sanitize_text_field( $level ),
        'type'     => sanitize_text_field( $type ),
        'detail'   => sanitize_textarea_field( $detail ),
    ], [ '%s', '%s', '%s', '%s' ] );
}

function k2s_get_recent_logs( $limit = 20 ) {
    global $wpdb;
    $table = $wpdb->prefix . 'sentinel_log';
    return $wpdb->get_results(
        $wpdb->prepare( "SELECT * FROM $table ORDER BY log_time DESC LIMIT %d", $limit )
    );
}

function k2s_clear_logs() {
    global $wpdb;
    $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}sentinel_log" );
}
