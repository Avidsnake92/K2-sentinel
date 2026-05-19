<?php
/**
 * K2 Sentinel – Remediation Engine
 *
 * Bonifica automatica:
 * - File PHP/HTML infetti → quarantena (spostati in wp-content/k2s-quarantine/)
 * - Database infetto     → backup record + pulizia valore
 * - Notifica email + log dopo ogni operazione
 */
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'K2S_QUARANTINE_DIR', WP_CONTENT_DIR . '/k2s-quarantine/' );

// ═══════════════════════════════════════════════════════════════════
//  INIT – crea cartella quarantena protetta
// ═══════════════════════════════════════════════════════════════════
function k2s_init_quarantine_dir() {
    if ( ! is_dir( K2S_QUARANTINE_DIR ) ) {
        wp_mkdir_p( K2S_QUARANTINE_DIR );
    }
    // Proteggi la cartella con .htaccess
    $htaccess = K2S_QUARANTINE_DIR . '.htaccess';
    if ( ! file_exists( $htaccess ) ) {
        file_put_contents( $htaccess, "Order Deny,Allow\nDeny from all\n" );
    }
    // index.php vuoto anti-listing
    $index = K2S_QUARANTINE_DIR . 'index.php';
    if ( ! file_exists( $index ) ) {
        file_put_contents( $index, '<?php // Silence is golden.' );
    }
}
add_action( 'init', 'k2s_init_quarantine_dir' );

// ═══════════════════════════════════════════════════════════════════
//  ENTRY POINT – chiamato dallo scanner dopo ogni scansione
// ═══════════════════════════════════════════════════════════════════
function k2s_auto_remediate( array $threats ) {
    if ( ! get_option( 'k2s_auto_remediation', 0 ) ) return;
    if ( empty( $threats ) ) return;

    $report = [
        'quarantined' => [],
        'db_cleaned'  => [],
        'failed'      => [],
        'skipped'     => [],
    ];

    foreach ( $threats as $threat ) {
        $type = $threat['type'] ?? '';

        // ── Tipi da saltare (solo informativi, non bonificabili) ──
        if ( in_array( $type, [
            'core_modified_file', 'core_missing_file',
            '2fa_failed', '2fa_success', 'brute_force',
            'ghost_admin', 'suspicious_admin_registration',
        ], true ) ) {
            $report['skipped'][] = $threat['detail'] ?? $type;
            continue;
        }

        // ── File extra in cartella core → quarantena ─────────────
        if ( $type === 'core_extra_file' ) {
            $result = k2s_quarantine_file( $threat );
            if ( $result['ok'] ) {
                $report['quarantined'][] = $result;
            } else {
                $report['failed'][] = $result;
            }

        // ── File PHP/HTML → quarantena ──────────────────────────
        } elseif ( in_array( $type, [
            'php_malware', 'php_in_html', 'index_defacement',
            'html_redirect', 'htaccess_redirect', 'htaccess_autoprepend',
            'index_php_redirect', 'index_php_malware', 'unexpected_index_file',
        ], true ) ) {
            $result = k2s_quarantine_file( $threat );
            if ( $result['ok'] ) {
                $report['quarantined'][] = $result;
            } else {
                $report['failed'][] = $result;
            }

        // ── DB injection → backup + pulizia ────────────────────
        } elseif ( in_array( $type, [
            'db_injection', 'siteurl_hijack', 'serialized_eval',
            'serialized_b64', 'widget_redirect', 'long_b64_in_db',
            'malicious_cron', 'post_js_redirect', 'courtesy_page',
        ], true ) ) {
            $result = k2s_clean_db_threat( $threat );
            if ( $result['ok'] ) {
                $report['db_cleaned'][] = $result;
            } else {
                $report['failed'][] = $result;
            }

        // ── Cron malevolo → rimozione ───────────────────────────
        } elseif ( $type === 'suspicious_cron' || $type === 'malicious_cron_hook' ) {
            $result = k2s_remove_malicious_cron( $threat );
            if ( $result['ok'] ) {
                $report['db_cleaned'][] = $result;
            } else {
                $report['failed'][] = $result;
            }

        } else {
            $report['skipped'][] = $threat['detail'] ?? $type;
        }
    }

    // Salva report + invia email
    $total = count( $report['quarantined'] ) + count( $report['db_cleaned'] );
    if ( $total > 0 || ! empty( $report['failed'] ) ) {
        update_option( 'k2s_last_remediation', [
            'time'   => current_time( 'mysql' ),
            'report' => $report,
        ] );
        k2s_log( 'info', 'remediation', "Bonifica completata: {$total} risolti, " . count( $report['failed'] ) . " falliti." );
        k2s_send_remediation_email( $report );
    }

    return $report;
}

// ═══════════════════════════════════════════════════════════════════
//  QUARANTENA FILE
// ═══════════════════════════════════════════════════════════════════
function k2s_quarantine_file( array $threat ) {
    // Estrai percorso dal dettaglio (es. "Pattern [x] in: wp-content/...")
    $detail  = $threat['detail'] ?? '';
    $rel_path = '';

    // Supporta vari formati di dettaglio:
    // "Pattern [x] in: wp-content/..."       → scanner generico
    // "File non ufficiale trovato in cartella core: wp-includes/..."  → core_extra_file
    // "File messo in quarantena: path → dest" → già bonificato
    if ( preg_match( '/cartella core:\s*(.+)$/i', $detail, $m ) ) {
        $rel_path = trim( $m[1] );
    } elseif ( preg_match( '/in:\s*(.+?)(?:\s*\(|\s*→|$)/i', $detail, $m ) ) {
        $rel_path = trim( $m[1] );
    } elseif ( preg_match( '/trovato.*?:\s*(.+?)(?:\s*\(|$)/i', $detail, $m ) ) {
        $rel_path = trim( $m[1] );
    }

    if ( empty( $rel_path ) ) {
        return [ 'ok' => false, 'detail' => "Percorso non trovato in: $detail" ];
    }

    $abs_path = ABSPATH . ltrim( $rel_path, '/' );

    // Verifica che il file esista e sia dentro ABSPATH (sicurezza path traversal)
    $real = realpath( $abs_path );
    if ( ! $real || strpos( $real, realpath( ABSPATH ) ) !== 0 ) {
        return [ 'ok' => false, 'detail' => "File non trovato o path non valido: $rel_path" ];
    }

    if ( ! is_readable( $real ) ) {
        return [ 'ok' => false, 'detail' => "File non leggibile: $rel_path" ];
    }

    // Non mettere in quarantena i propri file del plugin
    if ( strpos( $real, K2S_QUARANTINE_DIR ) === 0 ) {
        return [ 'ok' => false, 'detail' => "File già in quarantena." ];
    }

    k2s_init_quarantine_dir();

    // Nome file in quarantena: timestamp + hash per evitare collisioni
    $safe_name  = date( 'Ymd-His' ) . '_' . md5( $real ) . '_' . basename( $real ) . '.quarantine';
    $dest       = K2S_QUARANTINE_DIR . $safe_name;

    // Salva metadata accanto al file
    $meta = [
        'original_path' => $real,
        'quarantined_at'=> current_time( 'mysql' ),
        'threat_type'   => $threat['type'],
        'threat_detail' => $detail,
        'sha256'        => hash_file( 'sha256', $real ),
    ];
    file_put_contents( $dest . '.meta.json', json_encode( $meta, JSON_PRETTY_PRINT ) );

    // Sposta il file (rename = atomico, niente copia+delete)
    if ( ! @rename( $real, $dest ) ) {
        // Fallback: copia + cancella
        if ( @copy( $real, $dest ) ) {
            @unlink( $real );
        } else {
            return [ 'ok' => false, 'detail' => "Impossibile spostare: $rel_path" ];
        }
    }

    k2s_log( 'critical', 'quarantined', "File messo in quarantena: $rel_path → $safe_name" );

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

    // Formato: "Pattern [xxx] trovato in QUALSIASI_PREFIX_tablename.column"
    // Funziona con qualsiasi prefisso WP (wp_, p00ZTB_, ecc.)
    if ( ! preg_match( '/trovato in\s+(\S+)\.(\S+)/i', $detail, $m ) ) {
        return [ 'ok' => false, 'detail' => "Tabella/colonna non parsabile: $detail" ];
    }

    $table_raw = $m[1];
    $column    = $m[2];

    // Mappa nome base → nome completo con prefisso WP reale
    $base_map = [
        'posts'       => $wpdb->posts,
        'postmeta'    => $wpdb->postmeta,
        'options'     => $wpdb->options,
        'comments'    => $wpdb->comments,
        'commentmeta' => $wpdb->commentmeta,
    ];

    // Risolvi prefisso personalizzato: p00ZTB_options → options → $wpdb->options
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

    // Recupera le righe con il pattern malevolo
    $pattern_key = '';
    if ( preg_match( '/Pattern \[([^\]]+)\]/i', $detail, $pm ) ) {
        $pattern_key = $pm[1];
    }

    // Carica i pattern attivi
    $defs = k2s_get_active_definitions();
    $db_patterns = $defs['db_patterns'] ?? [];
    $regex = $db_patterns[ $pattern_key ] ?? null;

    if ( ! $regex ) {
        return [ 'ok' => false, 'detail' => "Pattern regex non trovato per: $pattern_key" ];
    }

    // Determina la colonna chiave primaria
    $pk = k2s_get_primary_key( $table );
    if ( ! $pk ) {
        return [ 'ok' => false, 'detail' => "PK non trovata per: $table" ];
    }

    // Leggi tutte le righe infette
    $rows = $wpdb->get_results(
        "SELECT `$pk`, `$column` FROM `$table`",
        ARRAY_A
    );

    $cleaned = 0;
    $backup_table = $wpdb->prefix . 'k2s_db_backup';
    k2s_ensure_backup_table( $backup_table );

    foreach ( $rows as $row ) {
        $value = $row[ $column ] ?? '';
        if ( ! is_string( $value ) || ! preg_match( $regex, $value ) ) continue;

        $pk_val = $row[ $pk ];

        // 1. Backup del record originale
        $wpdb->insert( $backup_table, [
            'backup_time'    => current_time( 'mysql' ),
            'source_table'   => $table,
            'source_column'  => $column,
            'source_pk'      => $pk_val,
            'original_value' => $value,
            'threat_type'    => $threat['type'],
            'pattern_key'    => $pattern_key,
        ] );

        // 2. Pulizia: rimuovi il pattern malevolo dal valore
        $clean_value = k2s_strip_malicious_content( $value, $regex, $pattern_key );

        // 3. Aggiorna il record
        $wpdb->update(
            $table,
            [ $column => $clean_value ],
            [ $pk     => $pk_val ],
            [ '%s' ],
            [ '%s' ]
        );

        $cleaned++;
        k2s_log( 'warning', 'db_cleaned', "Pulita $table.$column (PK=$pk_val) pattern [$pattern_key]" );
    }

    if ( $cleaned === 0 ) {
        return [ 'ok' => false, 'detail' => "Nessuna riga trovata da pulire in $table.$column" ];
    }

    return [
        'ok'      => true,
        'type'    => 'db',
        'table'   => $table,
        'column'  => $column,
        'cleaned' => $cleaned,
        'detail'  => $detail,
    ];
}

// ─── Rimuove il contenuto malevolo da un valore stringa ──────────
function k2s_strip_malicious_content( $value, $regex, $pattern_key ) {
    // Pattern che sostituiamo con stringa vuota (iniezioni aggiunte)
    $strip_patterns = [
        'iframe_inject', 'script_inject', 'eval_in_content',
        'hidden_link', 'spam_keyword', 'post_js_redirect',
        'courtesy_page', 'widget_redirect', 'serialized_eval', 'serialized_b64',
    ];

    if ( in_array( $pattern_key, $strip_patterns, true ) ) {
        // Rimuove il blocco malevolo con preg_replace
        return preg_replace( $regex, '', $value );
    }

    // Per long_b64_in_db e pattern che coprono tutto il valore: svuota
    if ( in_array( $pattern_key, [ 'long_b64_in_db', 'malicious_cron', 'phishing_url' ], true ) ) {
        return '';
    }

    // Default: rimuovi con regex
    return preg_replace( $regex, '', $value );
}

// ─── Rimuove cron job malevoli ────────────────────────────────────
function k2s_remove_malicious_cron( array $threat ) {
    $detail = $threat['detail'] ?? '';

    if ( ! preg_match( '/\[([^\]]+)\]/', $detail, $m ) ) {
        return [ 'ok' => false, 'detail' => "Hook non trovato in: $detail" ];
    }

    $hook = $m[1];
    wp_clear_scheduled_hook( $hook );
    k2s_log( 'warning', 'cron_removed', "Cron job malevolo rimosso: [$hook]" );

    return [
        'ok'    => true,
        'type'  => 'cron',
        'hook'  => $hook,
        'detail'=> $detail,
    ];
}

// ═══════════════════════════════════════════════════════════════════
//  EMAIL DI NOTIFICA
// ═══════════════════════════════════════════════════════════════════
function k2s_send_remediation_email( array $report ) {
    if ( ! get_option( 'k2s_email_alerts', 0 ) ) return;

    $to      = get_option( 'k2s_alert_email', get_option( 'admin_email' ) );
    $subject = '[K2 Sentinel] Bonifica automatica completata – ' . get_bloginfo( 'name' );

    $q_count  = count( $report['quarantined'] );
    $db_count = count( $report['db_cleaned'] );
    $f_count  = count( $report['failed'] );

    $body  = "K2 Sentinel ha completato una bonifica automatica sul sito " . home_url() . "\n";
    $body .= "Data/ora: " . current_time( 'mysql' ) . "\n\n";
    $body .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    $body .= "RIEPILOGO\n";
    $body .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    $body .= "📦 File messi in quarantena : $q_count\n";
    $body .= "🗄️  Record DB puliti         : $db_count\n";
    $body .= "❌ Operazioni fallite        : $f_count\n\n";

    if ( ! empty( $report['quarantined'] ) ) {
        $body .= "FILE IN QUARANTENA:\n";
        foreach ( $report['quarantined'] as $r ) {
            $body .= "  • " . ( $r['original'] ?? '?' ) . "\n";
            $body .= "    → " . ( $r['dest'] ?? '?' ) . "\n";
        }
        $body .= "\n";
    }

    if ( ! empty( $report['db_cleaned'] ) ) {
        $body .= "RECORD DB PULITI:\n";
        foreach ( $report['db_cleaned'] as $r ) {
            if ( $r['type'] === 'db' ) {
                $body .= "  • {$r['table']}.{$r['column']} – {$r['cleaned']} riga/e\n";
            } elseif ( $r['type'] === 'cron' ) {
                $body .= "  • Cron rimosso: [{$r['hook']}]\n";
            }
        }
        $body .= "\n";
    }

    if ( ! empty( $report['failed'] ) ) {
        $body .= "OPERAZIONI FALLITE (richiedono intervento manuale):\n";
        foreach ( $report['failed'] as $r ) {
            $body .= "  ⚠️  " . ( $r['detail'] ?? json_encode( $r ) ) . "\n";
        }
        $body .= "\n";
    }

    $body .= "I file in quarantena si trovano in:\n";
    $body .= str_replace( ABSPATH, '/', K2S_QUARANTINE_DIR ) . "\n\n";
    $body .= "Puoi ripristinarli dalla sezione Quarantena nel pannello K2 Sentinel.\n\n";
    $body .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
    $body .= "K2 Sentinel – by K2Tech | " . home_url( '/wp-admin' ) . "\n";

    wp_mail( $to, $subject, $body );
}

// ═══════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════
function k2s_get_primary_key( $table ) {
    global $wpdb;
    $pk_map = [
        $wpdb->posts       => 'ID',
        $wpdb->postmeta    => 'meta_id',
        $wpdb->options     => 'option_id',
        $wpdb->comments    => 'comment_ID',
        $wpdb->commentmeta => 'meta_id',
    ];
    return $pk_map[ $table ] ?? null;
}

function k2s_ensure_backup_table( $table ) {
    global $wpdb;
    $exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) );
    if ( $exists ) return;

    $charset = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE $table (
        id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        backup_time    DATETIME        NOT NULL,
        source_table   VARCHAR(100)    NOT NULL,
        source_column  VARCHAR(100)    NOT NULL,
        source_pk      VARCHAR(50)     NOT NULL,
        original_value LONGTEXT        NOT NULL,
        threat_type    VARCHAR(60)     NOT NULL,
        pattern_key    VARCHAR(60)     NOT NULL,
        PRIMARY KEY (id),
        KEY backup_time (backup_time)
    ) $charset;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( $sql );
}

// ═══════════════════════════════════════════════════════════════════
//  AJAX – ripristina file dalla quarantena
// ═══════════════════════════════════════════════════════════════════
add_action( 'wp_ajax_k2s_restore_quarantine', 'k2s_ajax_restore_quarantine' );

function k2s_ajax_restore_quarantine() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );

    $filename = sanitize_file_name( $_POST['filename'] ?? '' );
    $src      = K2S_QUARANTINE_DIR . $filename;
    $meta_f   = $src . '.meta.json';

    if ( ! file_exists( $src ) || ! file_exists( $meta_f ) ) {
        wp_send_json_error( 'File non trovato.' );
    }

    $meta = json_decode( file_get_contents( $meta_f ), true );
    $dest = $meta['original_path'] ?? '';

    if ( empty( $dest ) ) {
        wp_send_json_error( 'Percorso originale non trovato nel metadata.' );
    }

    // Ricrea la cartella se necessario
    $dir = dirname( $dest );
    if ( ! is_dir( $dir ) ) wp_mkdir_p( $dir );

    if ( @rename( $src, $dest ) ) {
        @unlink( $meta_f );
        k2s_log( 'info', 'quarantine_restored', "File ripristinato: $dest" );
        wp_send_json_success( [ 'restored_to' => str_replace( ABSPATH, '', $dest ) ] );
    } else {
        wp_send_json_error( 'Impossibile ripristinare il file.' );
    }
}

// ═══════════════════════════════════════════════════════════════════
//  AJAX – elimina definitivamente dalla quarantena
// ═══════════════════════════════════════════════════════════════════
add_action( 'wp_ajax_k2s_delete_quarantine', 'k2s_ajax_delete_quarantine' );

function k2s_ajax_delete_quarantine() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );

    $filename = sanitize_file_name( $_POST['filename'] ?? '' );
    $src      = K2S_QUARANTINE_DIR . $filename;
    $meta_f   = $src . '.meta.json';

    @unlink( $src );
    @unlink( $meta_f );

    k2s_log( 'info', 'quarantine_deleted', "File eliminato definitivamente: $filename" );
    wp_send_json_success();
}

// ═══════════════════════════════════════════════════════════════════
//  GET FILES IN QUARANTENA
// ═══════════════════════════════════════════════════════════════════
function k2s_get_quarantine_files() {
    $files = [];
    if ( ! is_dir( K2S_QUARANTINE_DIR ) ) return $files;

    foreach ( glob( K2S_QUARANTINE_DIR . '*.quarantine' ) as $f ) {
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

    usort( $files, fn( $a, $b ) => strcmp( $b['quarantined_at'], $a['quarantined_at'] ) );
    return $files;
}

// ═══════════════════════════════════════════════════════════════════
//  GET BACKUP DB
// ═══════════════════════════════════════════════════════════════════
function k2s_get_db_backups( $limit = 50 ) {
    global $wpdb;
    $table = $wpdb->prefix . 'k2s_db_backup';
    $exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) );
    if ( ! $exists ) return [];
    return $wpdb->get_results(
        $wpdb->prepare( "SELECT * FROM $table ORDER BY backup_time DESC LIMIT %d", $limit )
    );
}

// ═══════════════════════════════════════════════════════════════════
//  AJAX – bonifica manuale (agisce sui log esistenti)
// ═══════════════════════════════════════════════════════════════════
add_action( 'wp_ajax_k2s_manual_remediate', 'k2s_ajax_manual_remediate' );

function k2s_ajax_manual_remediate() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );

    global $wpdb;
    $table = $wpdb->prefix . 'sentinel_log';

    // Tipi solo informativi — non bonificabili
    $skip_types = [
        'core_modified_file', 'core_missing_file',
        '2fa_failed', '2fa_success', 'brute_force',
        'remediation', 'definitions_update', 'hardening_updated',
        'quarantined', 'db_cleaned', 'cron_removed',
        'quarantine_restored', 'quarantine_deleted',
        'ghost_admin', 'suspicious_admin_registration',
        'core_integrity', 'suspicious_cron',
    ];

    $skip_in = implode( ',', array_map( fn($t) => "'$t'", $skip_types ) );

    // Leggi le ultime minacce bonificabili dal log
    $logs = $wpdb->get_results(
        "SELECT * FROM $table
         WHERE level IN ('critical','warning')
         AND type NOT IN ($skip_in)
         ORDER BY log_time DESC
         LIMIT 500",
        ARRAY_A
    );

    if ( empty( $logs ) ) {
        wp_send_json_success( [
            'message'  => 'Nessuna minaccia bonificabile trovata nel log.',
            'total'    => 0,
            'hint'     => 'Avvia una scansione manuale per rilevare nuove minacce.',
        ] );
        return;
    }

    // Deduplicazione per tipo+dettaglio
    $seen           = [];
    $unique_threats = [];
    foreach ( $logs as $log ) {
        $key = $log['type'] . '||' . $log['detail'];
        if ( ! isset( $seen[ $key ] ) ) {
            $seen[ $key ]     = true;
            $unique_threats[] = [
                'level'  => $log['level'],
                'type'   => $log['type'],
                'detail' => $log['detail'],
            ];
        }
    }

    $report = k2s_auto_remediate( $unique_threats );

    $quarantined = count( $report['quarantined'] ?? [] );
    $db_cleaned  = count( $report['db_cleaned']  ?? [] );
    $failed      = count( $report['failed']      ?? [] );
    $skipped     = count( $report['skipped']     ?? [] );
    $total       = $quarantined + $db_cleaned;

    // Dettaglio falliti per debug
    $failed_details = [];
    foreach ( $report['failed'] ?? [] as $f ) {
        $failed_details[] = $f['detail'] ?? json_encode( $f );
    }

    wp_send_json_success( [
        'total'          => $total,
        'quarantined'    => $quarantined,
        'db_cleaned'     => $db_cleaned,
        'failed'         => $failed,
        'failed_details' => $failed_details,
        'skipped'        => $skipped,
        'processed'      => count( $unique_threats ),
        'message'        => "$total bonificati su " . count( $unique_threats ) . " minacce uniche.",
    ] );
}
