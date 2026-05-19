<?php
/**
 * K2 Sentinel – Scanner AV
 * Scansiona file PHP/HTML/JS/.htaccess e database alla ricerca di malware.
 */
if ( ! defined( 'ABSPATH' ) ) exit;

// ── Pattern globali (sovrascrivibili da definitions.php) ──────────
global $K2S_PHP_PATTERNS, $K2S_DB_PATTERNS;

$K2S_PHP_PATTERNS = [
    'eval_base64'      => '/eval\s*\(\s*base64_decode/i',
    'eval_gzinflate'   => '/eval\s*\(\s*gzinflate/i',
    'eval_str_rot'     => '/eval\s*\(\s*str_rot13/i',
    'shell_exec'       => '/shell_exec\s*\(/i',
    'exec_call'        => '/\bexec\s*\(/i',
    'system_call'      => '/\bsystem\s*\(/i',
    'passthru'         => '/passthru\s*\(/i',
    'preg_replace_e'   => '/preg_replace\s*\(\s*[\'"].*\/e/i',
    'base64_in_php'    => '/\$\w+\s*=\s*base64_decode\s*\(/i',
    'create_function'  => '/create_function\s*\(/i',
    'file_put_php'     => '/file_put_contents\s*\(.*\.php/i',
    'backdoor_c99'     => '/c99shell|r57shell|webshell\.php/i',
    'index_defacement' => '/<meta\s+http-equiv\s*=\s*["\']refresh["\'][^>]*url\s*=/i',
    'prepend_inject'   => '/^<\?php\s+[^\r\n]{0,10}(eval|base64_decode|gzinflate)/i',
    'long_base64'      => '/[A-Za-z0-9+\/]{300,}={0,2}/',
    'add_admin_user'   => '/wp_insert_user|wp_create_user.*administrator/i',
];

$K2S_DB_PATTERNS = [
    'iframe_inject'   => '/<iframe[^>]+src\s*=\s*["\']https?:\/\//i',
    'script_inject'   => '/<script[^>]*src\s*=\s*["\']https?:\/\//i',
    'eval_in_content' => '/eval\s*\(\s*base64_decode/i',
    'hidden_link'     => '/display\s*:\s*none.{0,500}<a\s+href/is',
    'spam_keyword'    => '/viagra|cialis|casino|payday.?loan/i',
    'phishing_url'    => '/\.(ru|cn|tk|ml|ga|cf)\//i',
    'serialized_eval' => '/s:\d+:.*eval\s*\(/i',
    'serialized_b64'  => '/s:\d+:.*base64_decode/i',
    'widget_redirect' => '/Location:\s*https?:\/\//i',
    'long_b64_in_db'  => '/[A-Za-z0-9+\/]{500,}={0,2}/',
    'post_js_redirect'=> '/window\.location\s*=/i',
    'courtesy_page'   => '/Sito in manutenzione|Under Construction|Hacked by/i',
];

// ── Sovrascrive con definizioni remote se disponibili ─────────────
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
    $scan_exts    = [ 'php', 'html', 'htm', 'js' ];

    $scan_dirs = [
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/uploads',
        ABSPATH,
    ];

    // Escludi plugin stesso e quarantena
    $exclude_paths = array_filter( [
        realpath( K2S_PATH ),
        realpath( K2S_QUARANTINE_DIR ),
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

            if ( ! in_array( $ext, $scan_exts, true ) && ! $is_htaccess ) continue;
            if ( $file_obj->getMTime() < $last_scan_ts ) continue;

            $filepath = $file_obj->getRealPath();
            if ( ! $filepath ) continue;

            // Salta plugin stesso e quarantena
            $should_skip = false;
            foreach ( $exclude_paths as $excl ) {
                if ( strpos( $filepath, $excl ) === 0 ) {
                    $should_skip = true;
                    break;
                }
            }
            if ( $should_skip ) continue;

            $rel_path    = str_replace( ABSPATH, '', $filepath );
            $file_source = @file_get_contents( $filepath );
            if ( $file_source === false || strlen( $file_source ) === 0 ) continue;

            // .htaccess
            if ( $is_htaccess ) {
                $site_host = (string) parse_url( home_url(), PHP_URL_HOST );
                if ( $site_host && preg_match( '/RewriteRule.*https?:\/\/(?!' . preg_quote( $site_host, '/' ) . ')/i', $file_source ) ) {
                    $threats[] = [ 'level' => 'critical', 'type' => 'htaccess_redirect', 'detail' => "Redirect esterno in .htaccess: $rel_path" ];
                }
                continue;
            }

            // HTML/HTM
            if ( in_array( $ext, [ 'html', 'htm' ], true ) ) {
                if ( preg_match( '/<\?php/i', $file_source ) ) {
                    $threats[] = [ 'level' => 'critical', 'type' => 'php_in_html', 'detail' => "PHP in file HTML: $rel_path" ];
                }
                continue;
            }

            // PHP / JS — applica pattern
            foreach ( $K2S_PHP_PATTERNS as $pname => $pregex ) {
                if ( @preg_match( $pregex, $file_source ) ) {
                    $threats[] = [ 'level' => 'critical', 'type' => 'php_malware', 'detail' => "Pattern [$pname] in: $rel_path" ];
                    break;
                }
            }
        }
    }

    $threats = array_merge( $threats, k2s_scan_unexpected_index_files() );
    update_option( 'k2s_last_scan_ts', time() );
    return $threats;
}

// ── Index file inattesi in wp-content ────────────────────────────
function k2s_scan_unexpected_index_files() {
    $threats = [];
    $dirs    = [
        WP_CONTENT_DIR,
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/uploads',
    ];

    foreach ( $dirs as $dir ) {
        foreach ( [ 'index.html', 'index.htm', 'index.php' ] as $fname ) {
            $fpath = trailingslashit( $dir ) . $fname;
            if ( ! file_exists( $fpath ) ) continue;

            $src     = (string) @file_get_contents( $fpath );
            $trimmed = trim( $src );

            if ( $fname === 'index.php' && preg_match( '/^<\?php\s*(\/\/\s*Silence is golden\.?\s*)?$/i', $trimmed ) ) continue;
            if ( $fname === 'index.php' && strlen( $trimmed ) === 0 ) continue;

            $rel = str_replace( ABSPATH, '', $fpath );

            if ( in_array( $fname, [ 'index.html', 'index.htm' ], true ) ) {
                $threats[] = [ 'level' => 'critical', 'type' => 'unexpected_index_file', 'detail' => "File index inatteso: $rel" ];
            } elseif ( strlen( $trimmed ) > 50 && preg_match( '/header.*Location:|<meta.*refresh.*url=/i', $src ) ) {
                $threats[] = [ 'level' => 'critical', 'type' => 'index_php_redirect', 'detail' => "Redirect in index.php: $rel" ];
            }
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
        $wpdb->posts       => [ 'post_content', 'post_excerpt' ],
        $wpdb->postmeta    => [ 'meta_value' ],
        $wpdb->options     => [ 'option_value' ],
        $wpdb->comments    => [ 'comment_content', 'comment_author_url' ],
        $wpdb->commentmeta => [ 'meta_value' ],
    ];

    foreach ( $scan_targets as $table => $columns ) {
        if ( ! $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) ) ) continue;

        foreach ( $columns as $col ) {
            $offset = 0;
            $batch  = 200;

            do {
                $rows = $wpdb->get_results(
                    $wpdb->prepare( "SELECT `$col` FROM `$table` LIMIT %d OFFSET %d", $batch, $offset ),
                    ARRAY_A
                );
                if ( empty( $rows ) ) break;

                foreach ( $rows as $row ) {
                    $val = $row[ $col ] ?? '';
                    if ( ! is_string( $val ) || strlen( $val ) < 10 ) continue;

                    foreach ( $K2S_DB_PATTERNS as $pname => $pregex ) {
                        if ( @preg_match( $pregex, $val ) ) {
                            $threats[] = [ 'level' => 'warning', 'type' => 'db_injection', 'detail' => "Pattern [$pname] trovato in {$table}.{$col}" ];
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
        $user = get_userdata( $uid );
        if ( ! $user ) continue;
        $email_domain = strtolower( substr( strrchr( $user->user_email, '@' ), 1 ) );
        foreach ( $bad_domains as $bad ) {
            if ( strpos( $email_domain, $bad ) !== false ) {
                $threats[] = [ 'level' => 'critical', 'type' => 'ghost_admin', 'detail' => "Admin sospetto: {$user->user_login} ({$user->user_email})" ];
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
    $real_host = (string) parse_url( get_option( 'siteurl' ), PHP_URL_HOST );

    foreach ( [ 'siteurl', 'home' ] as $opt ) {
        $val = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $opt ) );
        if ( ! $val ) continue;
        if ( preg_match( '/https?:\/\/([a-z0-9\-\.]+)/i', $val, $m ) ) {
            if ( strtolower( $m[1] ) !== strtolower( $real_host ) ) {
                $threats[] = [ 'level' => 'critical', 'type' => 'siteurl_hijack', 'detail' => "Opzione [$opt] punta a host diverso: {$m[1]}" ];
            }
        }
    }
    return $threats;
}

// ── Cron malevoli ─────────────────────────────────────────────────
function k2s_scan_malicious_crons() {
    $threats   = [];
    $crons     = _get_cron_array();
    if ( empty( $crons ) ) return $threats;

    $whitelist = [
        'wp_scheduled_delete', 'wp_update_user_counts', 'wp_version_check',
        'wp_update_plugins', 'wp_update_themes', 'delete_expired_transients',
        'k2s_hourly_scan', 'k2s_hourly_digest', 'k2s_daily_definitions_update',
        'wp_scheduled_auto_draft_delete', 'recovery_mode_clean_expired_keys',
    ];

    foreach ( $crons as $timestamp => $hooks ) {
        foreach ( $hooks as $hook => $events ) {
            if ( in_array( $hook, $whitelist, true ) ) continue;
            if ( strlen( $hook ) < 5 || preg_match( '/^[a-z]{1,4}\d{3,}$/', $hook ) ) {
                $threats[] = [ 'level' => 'warning', 'type' => 'suspicious_cron', 'detail' => "Cron sospetto: [$hook]" ];
            }
        }
    }
    return $threats;
}
