<?php
/**
 * K2 Sentinel – Remediation Engine
 * Bonifica file (quarantena) e record DB (backup + pulizia).
 */
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'K2S_QUARANTINE_DIR', WP_CONTENT_DIR . '/k2s-quarantine/' );

// ─── Pattern fallback per la pulizia DB ───────────────────────────
// Usati quando le definizioni remote non sono disponibili.
// Usa virgolette doppie e delimitatore # per evitare conflitti.
function k2s_get_fallback_db_patterns() {
    return array(
        "iframe_inject"    => "#<iframe[^>]+src#i",
        "script_inject"    => "#<script[^>]*src\s*=\s*https?://#i",
        "eval_in_content"  => "#eval\s*\(\s*base64_decode#i",
        "hidden_link"      => "#display:\s*none#is",
        "spam_keyword"     => "#viagra|cialis|casino|payday#i",
        "phishing_url"     => "#\.(ru|cn|tk|ml|ga|cf)/#i",
        "serialized_eval"  => "#s:\d+:.*eval\s*\(#i",
        "serialized_b64"   => "#s:\d+:.*base64_decode#i",
        "widget_redirect"  => "#Location:\s*https?://#i",
        "long_b64_in_db"   => "#[A-Za-z0-9+/]{500,}={0,2}#",
        "malicious_cron"   => "#curl_exec|shell_exec|passthru#i",
        "post_js_redirect" => "#window\.location\s*=#i",
        "courtesy_page"    => "#Sito in manutenzione|Under Construction|Hacked by#i",
        "siteurl_hijack"   => "#https?://[a-z0-9\-\.]+\.[a-z]{2,}#i",
        "hidden_admin_form"=> "#type.*hidden.*name.*wp_#is",
        "encoded_option"   => "#[A-Za-z0-9+/]{300,}={0,2}#",
    );
}

// ═══════════════════════════════════════════════════════════════════
//  INIT quarantena
// ═══════════════════════════════════════════════════════════════════
function k2s_init_quarantine_dir() {
    if ( ! is_dir( K2S_QUARANTINE_DIR ) ) {
        wp_mkdir_p( K2S_QUARANTINE_DIR );
    }
    $htaccess = K2S_QUARANTINE_DIR . '.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        file_put_contents( $htaccess, "Order Deny,Allow\nDeny from all\n" );
    }
    $index = K2S_QUARANTINE_DIR . 'index.php';
    if ( ! file_exists( $index ) ) {
        file_put_contents( $index, '<?php // Silence is golden.' );
    }
}
add_action( 'init', 'k2s_init_quarantine_dir' );

// ═══════════════════════════════════════════════════════════════════
//  ENTRY POINT — chiamato dopo ogni scansione
// ═══════════════════════════════════════════════════════════════════
function k2s_auto_remediate( array $threats ) {
    if ( ! get_option( 'k2s_auto_remediation', 0 ) ) return [];
    if ( empty( $threats ) ) return [];

    $report = [
        'quarantined' => [],
        'db_cleaned'  => [],
        'failed'      => [],
        'skipped'     => [],
    ];

    // Tipi solo informativi — non bonificabili automaticamente
    $skip_types = [
        'core_modified_file', 'core_missing_file',
        '2fa_failed', '2fa_success', 'brute_force',
        'ghost_admin', 'suspicious_admin_registration',
        'suspicious_cron', 'siteurl_hijack',
        'remediation', 'definitions_update', 'hardening_updated',
        'quarantined', 'db_cleaned', 'cron_removed',
        'quarantine_restored', 'quarantine_deleted',
    ];

    // Tipi file → quarantena
    $file_types = [
        'php_malware', 'php_in_html', 'index_defacement',
        'html_redirect', 'htaccess_redirect', 'htaccess_autoprepend',
        'index_php_redirect', 'index_php_malware',
        'unexpected_index_file', 'core_extra_file',
    ];

    // Tipi DB → backup + pulizia
    $db_types = [
        'db_injection', 'serialized_eval', 'serialized_b64',
        'widget_redirect', 'post_js_redirect', 'courtesy_page',
    ];

    foreach ( $threats as $threat ) {
        $type = $threat['type'] ?? '';

        if ( in_array( $type, $skip_types, true ) ) {
            $report['skipped'][] = $threat['detail'] ?? $type;
            continue;
        }

        if ( in_array( $type, $file_types, true ) ) {
            $result = k2s_quarantine_file( $threat );
            if ( $result['ok'] ) {
                $report['quarantined'][] = $result;
            } else {
                $report['failed'][] = $result;
            }
            continue;
        }

        if ( in_array( $type, $db_types, true ) ) {
            $result = k2s_clean_db_threat( $threat );
            if ( $result['ok'] ) {
                $report['db_cleaned'][] = $result;
            } else {
                $report['failed'][] = $result;
            }
            continue;
        }

        // Tipo non gestito
        $report['skipped'][] = "Tipo non gestito: $type";
    }

    // Log e notifica
    $total = count( $report['quarantined'] ) + count( $report['db_cleaned'] );
    if ( $total > 0 || ! empty( $report['failed'] ) ) {
        update_option( 'k2s_last_remediation', [
            'time'   => current_time( 'mysql' ),
            'report' => $report,
        ] );
        k2s_log( 'info', 'remediation', "Bonifica: {$total} risolti, " . count( $report['failed'] ) . " falliti." );
        k2s_send_remediation_email( $report );
    }

    return $report;
}

// ═══════════════════════════════════════════════════════════════════
//  QUARANTENA FILE
// ═══════════════════════════════════════════════════════════════════
function k2s_quarantine_file( array $threat ) {
    $detail = $threat['detail'] ?? '';

    // Estrai percorso dal dettaglio in vari formati
    $rel_path = '';
    if ( preg_match( '/cartella core:\s*(.+)$/i', $detail, $m ) ) {
        $rel_path = trim( $m[1] );
    } elseif ( preg_match( '/in:\s*(.+?)(?:\s*\(|$)/i', $detail, $m ) ) {
        $rel_path = trim( $m[1] );
    } elseif ( preg_match( '/trovato.*?:\s*(.+?)(?:\s*\(|$)/i', $detail, $m ) ) {
        $rel_path = trim( $m[1] );
    }

    if ( empty( $rel_path ) ) {
        return [ 'ok' => false, 'detail' => "Percorso non trovato nel dettaglio: $detail" ];
    }

    $abs_path = ABSPATH . ltrim( $rel_path, '/' );
    $real     = realpath( $abs_path );

    if ( ! $real ) {
        return [ 'ok' => false, 'detail' => "File non trovato: $rel_path" ];
    }

    // Sicurezza: deve essere dentro ABSPATH
    if ( strpos( $real, realpath( ABSPATH ) ) !== 0 ) {
        return [ 'ok' => false, 'detail' => "Path non valido: $rel_path" ];
    }

    // Non toccare il plugin stesso né la quarantena
    $plugin_real     = realpath( K2S_PATH );
    $quarantine_real = realpath( K2S_QUARANTINE_DIR );

    if ( $plugin_real && strpos( $real, $plugin_real ) === 0 ) {
        return [ 'ok' => false, 'detail' => "File del plugin — non bonificabile" ];
    }
    if ( $quarantine_real && strpos( $real, $quarantine_real ) === 0 ) {
        return [ 'ok' => false, 'detail' => "File già in quarantena" ];
    }

    if ( ! is_readable( $real ) ) {
        return [ 'ok' => false, 'detail' => "File non leggibile: $rel_path" ];
    }

    k2s_init_quarantine_dir();

    $safe_name = date( 'Ymd-His' ) . '_' . substr( md5( $real ), 0, 8 ) . '_' . basename( $real ) . '.quarantine';
    $dest      = K2S_QUARANTINE_DIR . $safe_name;

    // Metadata
    $meta = [
        'original_path'  => $real,
        'quarantined_at' => current_time( 'mysql' ),
        'threat_type'    => $threat['type'] ?? '',
        'threat_detail'  => $detail,
        'sha256'         => hash_file( 'sha256', $real ),
    ];
    file_put_contents( $dest . '.meta.json', json_encode( $meta, JSON_PRETTY_PRINT ) );

    // Sposta il file
    $moved = @rename( $real, $dest );
    if ( ! $moved ) {
        if ( @copy( $real, $dest ) ) {
            @unlink( $real );
        } else {
            return [ 'ok' => false, 'detail' => "Impossibile spostare: $rel_path" ];
        }
    }

    k2s_log( 'critical', 'quarantined', "File in quarantena: $rel_path" );

    return [
        'ok'       => true,
        'type'     => 'file',
        'original' => $rel_path,
        'dest'     => $safe_name,
        'detail'   => $detail,
    ];
}

// ═══════════════════════════════════════════════════════════════════
//  PULIZIA DATABASE
// ═══════════════════════════════════════════════════════════════════
function k2s_clean_db_threat( array $threat ) {
    global $wpdb;
    $detail = $threat['detail'] ?? '';

    // Formato atteso: "Pattern [xxx] trovato in TABLE.COLUMN"
    if ( ! preg_match( '/trovato in\s+(\S+)\.(\S+)/i', $detail, $m ) ) {
        return [ 'ok' => false, 'detail' => "Formato non parsabile: $detail" ];
    }

    $table_raw = $m[1];
    $column    = $m[2];

    // Mappa nome base → tabella WP reale (gestisce qualsiasi prefisso)
    $base_map = [
        'posts'       => $wpdb->posts,
        'postmeta'    => $wpdb->postmeta,
        'options'     => $wpdb->options,
        'comments'    => $wpdb->comments,
        'commentmeta' => $wpdb->commentmeta,
    ];

    $table = null;
    foreach ( $base_map as $base => $full ) {
        if ( substr( $table_raw, -strlen( $base ) ) === $base ) {
            $table = $full;
            break;
        }
    }

    if ( ! $table ) {
        return [ 'ok' => false, 'detail' => "Tabella non gestita: $table_raw" ];
    }

    // Ricava pattern_key
    $pattern_key = '';
    if ( preg_match( '/Pattern \[([^\]]+)\]/i', $detail, $pm ) ) {
        $pattern_key = $pm[1];
    }

    // Cerca il regex: prima nelle definizioni attive, poi nel fallback
    $regex = null;
    if ( function_exists( 'k2s_get_active_definitions' ) ) {
        $defs        = k2s_get_active_definitions();
        $db_patterns = $defs['db_patterns'] ?? [];
        $regex       = $db_patterns[ $pattern_key ] ?? null;
    }
    if ( ! $regex ) {
        $fallback = k2s_get_fallback_db_patterns();
        $regex    = $fallback[ $pattern_key ] ?? null;
    }

    if ( ! $regex ) {
        return [ 'ok' => false, 'detail' => "Pattern regex non trovato per: [$pattern_key]" ];
    }

    // Verifica che il regex sia valido
    if ( @preg_match( $regex, '' ) === false ) {
        return [ 'ok' => false, 'detail' => "Regex non valido per: [$pattern_key]" ];
    }

    // Colonna PK
    $pk_map = [
        $wpdb->posts       => 'ID',
        $wpdb->postmeta    => 'meta_id',
        $wpdb->options     => 'option_id',
        $wpdb->comments    => 'comment_ID',
        $wpdb->commentmeta => 'meta_id',
    ];
    $pk = $pk_map[ $table ] ?? null;
    if ( ! $pk ) {
        return [ 'ok' => false, 'detail' => "PK non trovata per: $table" ];
    }

    // Crea tabella backup se non esiste
    $backup_table = $wpdb->prefix . 'k2s_db_backup';
    k2s_ensure_backup_table( $backup_table );

    // Leggi e pulisci le righe
    $rows    = $wpdb->get_results( "SELECT `$pk`, `$column` FROM `$table`", ARRAY_A );
    $cleaned = 0;

    foreach ( $rows as $row ) {
        $val = $row[ $column ] ?? '';
        if ( ! is_string( $val ) || strlen( $val ) < 5 ) continue;
        if ( ! @preg_match( $regex, $val ) ) continue;

        $pk_val = $row[ $pk ];

        // Backup
        $wpdb->insert( $backup_table, [
            'backup_time'    => current_time( 'mysql' ),
            'source_table'   => $table,
            'source_column'  => $column,
            'source_pk'      => (string) $pk_val,
            'original_value' => $val,
            'threat_type'    => $threat['type'] ?? '',
            'pattern_key'    => $pattern_key,
        ] );

        // Pulizia: rimuove il match dal valore
        $clean_val = @preg_replace( $regex, '', $val );
        if ( $clean_val === null ) $clean_val = '';

        $wpdb->update( $table, [ $column => $clean_val ], [ $pk => $pk_val ], [ '%s' ], [ '%s' ] );
        $cleaned++;
    }

    k2s_log( 'info', 'db_cleaned', "Pulite $cleaned righe in {$table}.{$column} pattern [$pattern_key]" );

    return [
        'ok'      => true,
        'type'    => 'db',
        'table'   => $table,
        'column'  => $column,
        'cleaned' => $cleaned,
        'detail'  => $detail,
    ];
}

// ─── Tabella backup DB ────────────────────────────────────────────
function k2s_ensure_backup_table( $table ) {
    global $wpdb;
    if ( $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) ) ) return;

    $charset = $wpdb->get_charset_collate();
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( "CREATE TABLE $table (
        id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        backup_time    DATETIME        NOT NULL,
        source_table   VARCHAR(100)    NOT NULL,
        source_column  VARCHAR(100)    NOT NULL,
        source_pk      VARCHAR(50)     NOT NULL,
        original_value LONGTEXT        NOT NULL,
        threat_type    VARCHAR(60)     NOT NULL,
        pattern_key    VARCHAR(60)     NOT NULL,
        PRIMARY KEY (id)
    ) $charset;" );
}

// ═══════════════════════════════════════════════════════════════════
//  EMAIL NOTIFICA
// ═══════════════════════════════════════════════════════════════════
function k2s_send_remediation_email( array $report ) {
    if ( ! get_option( 'k2s_email_alerts', 0 ) ) return;

    $to      = get_option( 'k2s_alert_email', get_option( 'admin_email' ) );
    $subject = '[K2 Sentinel] Bonifica completata – ' . get_bloginfo( 'name' );

    $q  = count( $report['quarantined'] );
    $d  = count( $report['db_cleaned'] );
    $f  = count( $report['failed'] );

    $body  = "K2 Sentinel – Bonifica automatica\n";
    $body .= home_url() . " | " . current_time( 'mysql' ) . "\n\n";
    $body .= "File in quarantena : $q\n";
    $body .= "Record DB puliti   : $d\n";
    $body .= "Falliti            : $f\n\n";

    if ( ! empty( $report['quarantined'] ) ) {
        $body .= "FILE IN QUARANTENA:\n";
        foreach ( $report['quarantined'] as $r ) {
            $body .= "  • " . ( $r['original'] ?? '?' ) . "\n";
        }
        $body .= "\n";
    }

    if ( ! empty( $report['failed'] ) ) {
        $body .= "FALLITI (intervento manuale necessario):\n";
        foreach ( $report['failed'] as $r ) {
            $body .= "  ! " . ( $r['detail'] ?? '?' ) . "\n";
        }
    }

    $body .= "\nPannello: " . admin_url( 'admin.php?page=k2-sentinel' ) . "\n";
    wp_mail( $to, $subject, $body );
}

// ═══════════════════════════════════════════════════════════════════
//  QUARANTENA — utility
// ═══════════════════════════════════════════════════════════════════
function k2s_get_quarantine_files() {
    $files = [];
    if ( ! is_dir( K2S_QUARANTINE_DIR ) ) return $files;

    foreach ( glob( K2S_QUARANTINE_DIR . '*.quarantine' ) ?: [] as $f ) {
        $meta_f = $f . '.meta.json';
        $meta   = file_exists( $meta_f ) ? json_decode( file_get_contents( $meta_f ), true ) : [];
        $files[] = [
            'filename'       => basename( $f ),
            'size'           => filesize( $f ),
            'quarantined_at' => $meta['quarantined_at'] ?? '—',
            'original_path'  => str_replace( ABSPATH, '', $meta['original_path'] ?? '?' ),
            'threat_type'    => $meta['threat_type'] ?? '?',
            'threat_detail'  => $meta['threat_detail'] ?? '?',
        ];
    }
    usort( $files, function( $a, $b ) { return strcmp( $b['quarantined_at'], $a['quarantined_at'] ); } );
    return $files;
}

function k2s_get_db_backups( $limit = 50 ) {
    global $wpdb;
    $table = $wpdb->prefix . 'k2s_db_backup';
    if ( ! $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) ) ) return [];
    return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table ORDER BY backup_time DESC LIMIT %d", $limit ) );
}

// ─── AJAX: ripristina dalla quarantena ────────────────────────────
add_action( 'wp_ajax_k2s_restore_quarantine', function() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die();

    $filename = sanitize_file_name( $_POST['filename'] ?? '' );
    $src      = K2S_QUARANTINE_DIR . $filename;
    $meta_f   = $src . '.meta.json';

    if ( ! file_exists( $src ) ) { wp_send_json_error( 'File non trovato.' ); }

    $meta = file_exists( $meta_f ) ? json_decode( file_get_contents( $meta_f ), true ) : [];
    $dest = $meta['original_path'] ?? '';

    if ( empty( $dest ) ) { wp_send_json_error( 'Percorso originale non trovato.' ); }

    $dir = dirname( $dest );
    if ( ! is_dir( $dir ) ) wp_mkdir_p( $dir );

    if ( @rename( $src, $dest ) ) {
        @unlink( $meta_f );
        k2s_log( 'info', 'quarantine_restored', "Ripristinato: $dest" );
        wp_send_json_success( [ 'restored_to' => str_replace( ABSPATH, '', $dest ) ] );
    } else {
        wp_send_json_error( 'Impossibile ripristinare.' );
    }
} );

// ─── AJAX: elimina dalla quarantena ──────────────────────────────
add_action( 'wp_ajax_k2s_delete_quarantine', function() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die();

    $filename = sanitize_file_name( $_POST['filename'] ?? '' );
    @unlink( K2S_QUARANTINE_DIR . $filename );
    @unlink( K2S_QUARANTINE_DIR . $filename . '.meta.json' );
    k2s_log( 'info', 'quarantine_deleted', "Eliminato: $filename" );
    wp_send_json_success();
} );

// ─── AJAX: bonifica manuale da log ────────────────────────────────
add_action( 'wp_ajax_k2s_manual_remediate', function() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die();

    global $wpdb;
    $log_table = $wpdb->prefix . 'sentinel_log';

    // Tipi non bonificabili
    $skip = [ 'core_modified_file','core_missing_file','2fa_failed','2fa_success',
               'brute_force','remediation','definitions_update','hardening_updated',
               'quarantined','db_cleaned','cron_removed','quarantine_restored',
               'quarantine_deleted','ghost_admin','suspicious_admin_registration',
               'core_integrity','suspicious_cron','siteurl_hijack' ];

    $skip_sql = implode( ',', array_map( function($t) { return "'" . esc_sql($t) . "'"; }, $skip ) );

    $logs = $wpdb->get_results(
        "SELECT level, type, detail FROM $log_table
         WHERE level IN ('critical','warning')
         AND type NOT IN ($skip_sql)
         ORDER BY log_time DESC LIMIT 500",
        ARRAY_A
    );

    if ( empty( $logs ) ) {
        wp_send_json_success( [ 'total' => 0, 'quarantined' => 0, 'db_cleaned' => 0, 'failed' => 0, 'skipped' => 0, 'processed' => 0, 'message' => 'Nessuna minaccia bonificabile nel log.' ] );
        return;
    }

    // Deduplicazione
    $seen   = [];
    $unique = [];
    foreach ( $logs as $log ) {
        $key = $log['type'] . '||' . $log['detail'];
        if ( ! isset( $seen[$key] ) ) {
            $seen[$key] = true;
            $unique[]   = $log;
        }
    }

    // Forza auto_remediation ON per questo AJAX
    $prev = get_option( 'k2s_auto_remediation', 0 );
    update_option( 'k2s_auto_remediation', 1 );
    $report = k2s_auto_remediate( $unique );
    update_option( 'k2s_auto_remediation', $prev );

    $q = count( $report['quarantined'] ?? [] );
    $d = count( $report['db_cleaned']  ?? [] );
    $f = count( $report['failed']      ?? [] );
    $s = count( $report['skipped']     ?? [] );

    $failed_details = array_map( function($r) { return $r['detail'] ?? json_encode($r); }, $report['failed'] ?? [] );

    wp_send_json_success( [
        'total'          => $q + $d,
        'quarantined'    => $q,
        'db_cleaned'     => $d,
        'failed'         => $f,
        'failed_details' => $failed_details,
        'skipped'        => $s,
        'processed'      => count( $unique ),
        'message'        => ( $q + $d ) . " bonificati su " . count( $unique ) . " minacce uniche.",
    ] );
} );
