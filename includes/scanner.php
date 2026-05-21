<?php
/**
 * K2 Sentinel – Scanner AV v1.4.0
 *
 * PRINCIPIO DI SICUREZZA:
 * I pattern devono essere CERTI al 100% — nessun falso positivo accettabile.
 * Un pattern che colpisce codice legittimo è più pericoloso di non averlo.
 *
 * PATTERN RIMOSSI perché troppo generici:
 *  - exec_call        → \bexec\s*\( colpisce mysqli_exec, preg_match, ecc.
 *  - system_call      → \bsystem\s*\( colpisce system() legittimo in molti plugin
 *  - base64_in_php    → base64_decode() usato da centinaia di plugin legittimi
 *  - long_base64      → base64 lungo usato da backup, crypto, Elementor, WooCommerce
 *  - add_admin_user   → wp_insert_user usato da plugin di importazione utenti
 *  - window.location  → usato da ogni tema/plugin per navigazione normale
 *  - spam_keyword     → "casino" può essere il nome di un cliente legittimo
 *  - long_b64_in_db   → Elementor, WooCommerce, ACF salvano dati base64 lunghi
 */
if ( ! defined( 'ABSPATH' ) ) exit;

global $K2S_PHP_PATTERNS, $K2S_DB_PATTERNS;

// ── Pattern PHP — solo malware CERTO, zero falsi positivi ─────────
$K2S_PHP_PATTERNS = [
    // eval() che decodifica base64: firma classica di malware offuscato
    'eval_base64'      => '/eval\s*\(\s*base64_decode\s*\(/i',

    // eval() con decompressione: altro metodo di offuscamento malware
    'eval_gzinflate'   => '/eval\s*\(\s*gzinflate\s*\(/i',
    'eval_str_rot'     => '/eval\s*\(\s*str_rot13\s*\(/i',

    // shell_exec() — non ha uso legittimo in plugin WP normali
    'shell_exec'       => '/shell_exec\s*\(/i',

    // passthru() — equivalente a shell_exec, non usato da plugin legittimi
    'passthru'         => '/passthru\s*\(/i',

    // preg_replace con flag /e (esegue codice) — deprecato e malware
    'preg_replace_e'   => '/preg_replace\s*\(\s*[\'"].*\/e[\'"\s]/i',

    // create_function() — deprecato, usato quasi solo da malware
    'create_function'  => '/create_function\s*\(\s*[\'"][^\'"]*[\'"]\s*,/i',

    // File PHP scritto runtime su percorso .php — classico dropper
    'file_put_php'     => '/file_put_contents\s*\(\s*[^,]+\.php[\'"\s]/i',

    // Backdoor note: c99shell, r57shell, webshell.php
    'backdoor_shell'   => '/c99shell|r57shell|webshell\.php/i',

    // Codice iniettato all'inizio del file (prepend inject)
    // Pattern: <?php seguito da eval/base64 sulla STESSA riga
    'prepend_inject'   => '/^<\?php\s*(eval|base64_decode|gzinflate|str_rot13)\s*\(/im',

    // Meta refresh redirect in file PHP — usato per dirottare pagine
    'php_meta_redirect'=> '/<meta\s+http-equiv\s*=\s*["\']refresh["\'][^>]*url\s*=\s*https?:\/\//i',
];

// ── Pattern DB — solo iniezioni CERTE ────────────────────────────
$K2S_DB_PATTERNS = [
    // iframe con src esterno — classica iniezione malware
    'iframe_inject'    => '/<iframe[^>]+src\s*=\s*["\']https?:\/\//i',

    // script con src esterno — iniezione JS malware
    'script_inject'    => '/<script[^>]*src\s*=\s*["\']https?:\/\//i',

    // eval(base64_decode nel DB — malware offuscato
    'eval_in_content'  => '/eval\s*\(\s*base64_decode\s*\(/i',

    // Link nascosto con display:none — spam SEO injection
    'hidden_link'      => '/display\s*:\s*none[^"\']*<a\s+href\s*=\s*["\']https?:\/\//i',

    // PHP serializzato con eval() — malware in opzioni WP
    'serialized_eval'  => '/s:\d+:"[^"]*eval\s*\(/i',

    // PHP serializzato con base64_decode — malware in opzioni WP
    'serialized_b64'   => '/s:\d+:"[^"]*base64_decode\s*\(/i',
];

// ── Sovrascrive con definizioni remote se disponibili ────────────
add_action( 'init', function() {
    global $K2S_PHP_PATTERNS, $K2S_DB_PATTERNS;
    if ( function_exists( 'k2s_get_active_definitions' ) ) {
        $defs = k2s_get_active_definitions();
        if ( ! empty( $defs['php_patterns'] ) ) $K2S_PHP_PATTERNS = $defs['php_patterns'];
        if ( ! empty( $defs['db_patterns'] ) )  $K2S_DB_PATTERNS  = $defs['db_patterns'];
    }
}, 5 );

// ═══════════════════════════════════════════════════════════════════
//  SCANNER FILE
// ═══════════════════════════════════════════════════════════════════
function k2s_scan_php_files() {
    global $K2S_PHP_PATTERNS;

    $threats      = [];
    $depth        = (int) get_option( 'k2s_scan_depth', 3 );
    $last_scan_ts = (int) get_option( 'k2s_last_scan_ts', 0 );

    $scan_dirs = [
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/uploads',
        ABSPATH,
    ];

    // Percorsi sempre esclusi
    $exclude_paths = array_filter( [
        realpath( K2S_PATH ),
        realpath( K2S_QUARANTINE_DIR ),
        realpath( WP_CONTENT_DIR . '/cache' ),
        realpath( WP_CONTENT_DIR . '/backup' ),
        realpath( WP_CONTENT_DIR . '/backups' ),
    ] );

    foreach ( $scan_dirs as $scan_dir ) {
        if ( ! is_dir( $scan_dir ) ) continue;

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $scan_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::SELF_FIRST,
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            $iterator->setMaxDepth( $depth );
        } catch ( Exception $e ) {
            continue;
        }

        foreach ( $iterator as $file_obj ) {
            if ( ! $file_obj->isFile() ) continue;

            $ext         = strtolower( $file_obj->getExtension() );
            $basename    = $file_obj->getFilename();
            $is_htaccess = ( $basename === '.htaccess' );

            // Solo PHP e .htaccess — JS/HTML hanno troppi falsi positivi
            if ( $ext !== 'php' && ! $is_htaccess ) continue;
            if ( $file_obj->getMTime() < $last_scan_ts ) continue;

            $filepath = $file_obj->getRealPath();
            if ( ! $filepath ) continue;

            // Salta percorsi esclusi
            foreach ( $exclude_paths as $excl ) {
                if ( $excl && strpos( $filepath, $excl ) === 0 ) continue 2;
            }

            $rel_path    = str_replace( ABSPATH, '', $filepath );
            $file_source = @file_get_contents( $filepath );
            if ( $file_source === false || strlen( $file_source ) === 0 ) continue;

            // .htaccess: cerca redirect verso domini esterni
            if ( $is_htaccess ) {
                $site_host = (string) parse_url( home_url(), PHP_URL_HOST );
                if ( $site_host && preg_match( '/RewriteRule.*https?:\/\/(?!' . preg_quote( $site_host, '/' ) . ')/i', $file_source ) ) {
                    $threats[] = [ 'level' => 'critical', 'type' => 'htaccess_redirect', 'detail' => "Redirect esterno in .htaccess: $rel_path" ];
                }
                if ( preg_match( '/php_value\s+auto_prepend_file/i', $file_source ) ) {
                    $threats[] = [ 'level' => 'critical', 'type' => 'htaccess_autoprepend', 'detail' => "auto_prepend_file in .htaccess: $rel_path" ];
                }
                continue;
            }

            // PHP: applica pattern
            foreach ( $K2S_PHP_PATTERNS as $pname => $pregex ) {
                if ( @preg_match( $pregex, $file_source ) ) {
                    $threats[] = [ 'level' => 'critical', 'type' => 'php_malware', 'detail' => "Pattern [$pname] in: $rel_path" ];
                    break;
                }
            }
        }
    }

    // File index inattesi in uploads (non in plugins/themes)
    $threats = array_merge( $threats, k2s_scan_unexpected_index_files() );

    update_option( 'k2s_last_scan_ts', time() );
    return $threats;
}

// ── Index file inattesi — solo in uploads, non in plugin/temi ────
function k2s_scan_unexpected_index_files() {
    $threats = [];

    // Controlla SOLO uploads — i plugin/temi possono avere index.html legittimi
    $check_dirs = [
        WP_CONTENT_DIR . '/uploads',
    ];

    foreach ( $check_dirs as $dir ) {
        foreach ( [ 'index.html', 'index.htm' ] as $fname ) {
            $fpath = trailingslashit( $dir ) . $fname;
            if ( ! file_exists( $fpath ) ) continue;

            $src = (string) @file_get_contents( $fpath );

            // File vuoto o quasi vuoto → stub di protezione legittimo
            if ( strlen( trim( $src ) ) < 10 ) continue;

            $rel = str_replace( ABSPATH, '', $fpath );
            $threats[] = [
                'level'  => 'warning',
                'type'   => 'unexpected_index_file',
                'detail' => "File index HTML con contenuto in uploads: $rel",
            ];
        }
    }
    return $threats;
}

// ═══════════════════════════════════════════════════════════════════
//  SCANNER DATABASE
// ═══════════════════════════════════════════════════════════════════
function k2s_scan_database() {
    global $wpdb, $K2S_DB_PATTERNS;

    $threats = [];

    $scan_targets = [
        $wpdb->posts       => [ 'post_content' ],
        $wpdb->options     => [ 'option_value' ],
        $wpdb->comments    => [ 'comment_content' ],
    ];

    foreach ( $scan_targets as $table => $columns ) {
        if ( ! $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) ) ) continue;

        foreach ( $columns as $col ) {
            $offset = 0;
            $batch  = 100;

            do {
                $rows = $wpdb->get_results(
                    $wpdb->prepare( "SELECT `$col` FROM `$table` LIMIT %d OFFSET %d", $batch, $offset ),
                    ARRAY_A
                );
                if ( empty( $rows ) ) break;

                foreach ( $rows as $row ) {
                    $val = $row[ $col ] ?? '';
                    if ( ! is_string( $val ) || strlen( $val ) < 20 ) continue;

                    foreach ( $K2S_DB_PATTERNS as $pname => $pregex ) {
                        if ( @preg_match( $pregex, $val ) ) {
                            $threats[] = [
                                'level'  => 'warning',
                                'type'   => 'db_injection',
                                'detail' => "Pattern [$pname] trovato in {$table}.{$col}",
                            ];
                            break;
                        }
                    }
                }

                $offset += $batch;
            } while ( count( $rows ) === $batch );
        }
    }

    $threats = array_merge( $threats, k2s_scan_ghost_admins() );
    $threats = array_merge( $threats, k2s_scan_siteurl_hijack() );
    $threats = array_merge( $threats, k2s_scan_malicious_crons() );
    return $threats;
}

// ── Admin fantasma ────────────────────────────────────────────────
function k2s_scan_ghost_admins() {
    global $wpdb;
    $threats     = [];
    $admin_ids   = $wpdb->get_col(
        "SELECT user_id FROM {$wpdb->usermeta}
         WHERE meta_key = '{$wpdb->prefix}capabilities'
         AND meta_value LIKE '%administrator%'"
    );
    $bad_domains = [ 'mailinator', 'guerrillamail', 'tempmail', 'yopmail', 'throwam' ];

    foreach ( $admin_ids as $uid ) {
        $user = get_userdata( (int) $uid );
        if ( ! $user ) continue;
        $email_domain = strtolower( (string) strrchr( $user->user_email, '@' ) );
        foreach ( $bad_domains as $bad ) {
            if ( strpos( $email_domain, $bad ) !== false ) {
                $threats[] = [
                    'level'  => 'critical',
                    'type'   => 'ghost_admin',
                    'detail' => "Admin con email sospetta: {$user->user_login} ({$user->user_email})",
                ];
                break;
            }
        }
    }
    return $threats;
}

// ── Siteurl hijack ────────────────────────────────────────────────
function k2s_scan_siteurl_hijack() {
    global $wpdb;
    $threats   = [];
    $real_host = strtolower( (string) parse_url( get_option( 'siteurl' ), PHP_URL_HOST ) );
    if ( ! $real_host ) return $threats;

    foreach ( [ 'siteurl', 'home' ] as $opt ) {
        $val = $wpdb->get_var(
            $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $opt )
        );
        if ( ! $val ) continue;
        if ( preg_match( '/https?:\/\/([a-z0-9\-\.]+)/i', $val, $m ) ) {
            if ( strtolower( $m[1] ) !== $real_host ) {
                $threats[] = [
                    'level'  => 'critical',
                    'type'   => 'siteurl_hijack',
                    'detail' => "Opzione [$opt] punta a host diverso: {$m[1]}",
                ];
            }
        }
    }
    return $threats;
}

// ── Cron malevoli ─────────────────────────────────────────────────
function k2s_scan_malicious_crons() {
    $threats  = [];
    $crons    = _get_cron_array();
    if ( empty( $crons ) ) return $threats;

    $whitelist = [
        'wp_scheduled_delete', 'wp_update_user_counts', 'wp_version_check',
        'wp_update_plugins', 'wp_update_themes', 'delete_expired_transients',
        'k2s_hourly_scan', 'k2s_hourly_digest', 'k2s_daily_definitions_update',
        'wp_scheduled_auto_draft_delete', 'recovery_mode_clean_expired_keys',
        'wp_privacy_delete_old_export_files', 'wp_site_health_scheduled_check',
    ];

    foreach ( $crons as $timestamp => $hooks ) {
        foreach ( $hooks as $hook => $events ) {
            if ( in_array( $hook, $whitelist, true ) ) continue;
            // Solo hook con nomi sospetti (molto corti o solo cifre)
            if ( strlen( $hook ) < 4 || preg_match( '/^\d+$/', $hook ) ) {
                $threats[] = [
                    'level'  => 'warning',
                    'type'   => 'suspicious_cron',
                    'detail' => "Cron con nome sospetto: [$hook]",
                ];
            }
        }
    }
    return $threats;
}
