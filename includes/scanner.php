<?php
if ( ! defined( 'ABSPATH' ) ) exit;

// ═══════════════════════════════════════════════════════════════════
//  PATTERN MALEVOLI – file PHP
// ═══════════════════════════════════════════════════════════════════
$K2S_PHP_PATTERNS = [
    // Generici
    'eval_base64'     => '/eval\s*\(\s*base64_decode/i',
    'eval_gzinflate'  => '/eval\s*\(\s*gzinflate/i',
    'eval_str_rot'    => '/eval\s*\(\s*str_rot13/i',
    'shell_exec'      => '/shell_exec\s*\(/i',
    'exec_call'       => '/\bexec\s*\(/i',
    'system_call'     => '/\bsystem\s*\(/i',
    'passthru'        => '/passthru\s*\(/i',
    'preg_replace_e'  => '/preg_replace\s*\(\s*[\'"].*\/e/i',
    'base64_in_php'   => '/\$\w+\s*=\s*base64_decode\s*\(/i',
    'hex_encoded'     => '/\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}/i',
    'obfuscated_var'  => '/\${\s*[\'"]?\w+[\'"]?\s*}\s*\(/i',
    'create_function' => '/create_function\s*\(/i',
    'wget_curl'       => '/\b(wget|curl)\s+http/i',
    'chmod_777'       => '/chmod\s*\(\s*\$\w+\s*,\s*0?777\s*\)/i',
    'file_put_php'    => '/file_put_contents\s*\(.*\.php/i',
    'backdoor_c99'    => '/c99|r57|shell\.php|webshell/i',

    // ── Specifici attacco "index replace" (tipo 17/03) ──────────────
    // Pagina di cortesia / defacement injettata in index.php
    'index_defacement'   => '/<meta\s+http-equiv\s*=\s*["\']refresh["\'][^>]*url\s*=/i',
    'index_redirect_php' => '/header\s*\(\s*["\']Location:\s*https?:\/\/(?!'.preg_quote( home_url(), '/' ).')/i',
    // Codice inserito a inizio/fine file (tipica firma dell'iniezione automatica)
    'prepend_inject'     => '/^<\?php\s+[^\r\n]{0,10}(eval|base64_decode|gzinflate|str_rot13)/i',
    'append_inject'      => '/(eval|base64_decode|gzinflate)\s*\([^\)]{5,}\)\s*;\s*\?>\s*$/i',
    // Righe di codice "a caso" tipiche degli script automatizzati
    'random_var_concat'  => '/\$[a-z]{1,3}\s*=\s*["\'][a-zA-Z0-9+\/=]{50,}["\']\s*;/i',
    'long_base64_string' => '/["\'][A-Za-z0-9+\/]{200,}={0,2}["\']/i',
    // PHP in file .html/.htm (file creati dall'attaccante)
    'php_in_html'        => '/<\?php/i',  // usato solo su .html/.htm
    // Reinfection loop: script che scarica ed esegue se stesso
    'self_reinstall'     => '/(file_get_contents|fopen|curl_exec)\s*\(.*http.*\)\s*.*eval/is',
    // Aggiunta utenti admin via PHP
    'add_admin_user'     => '/wp_insert_user|wp_create_user.*administrator/i',
    // Modifica siteurl/home tramite codice (sposta tutto il sito)
    'update_siteurl'     => '/update_option\s*\(\s*["\']siteurl["\']/i',
];

// ═══════════════════════════════════════════════════════════════════
//  PATTERN MALEVOLI – database
// ═══════════════════════════════════════════════════════════════════
$K2S_DB_PATTERNS = [
    // Generici
    'iframe_inject'   => '/<iframe[^>]+src\s*=\s*["\']https?:\/\//i',
    'script_inject'   => '/<script[^>]*src\s*=\s*["\']https?:\/\//i',
    'eval_in_content' => '/eval\s*\(\s*base64_decode/i',
    'hidden_link'     => '/display\s*:\s*none.*<a\s+href/i',
    'spam_keyword'    => '/\b(viagra|cialis|casino|poker|lottery|payday loan)\b/i',
    'phishing_url'    => '/href\s*=\s*["\'][^"\']*\.(ru|cn|tk|ml|ga|cf)\//i',

    // ── Specifici attacco "index replace" (tipo 17/03) ──────────────
    // siteurl/home dirottati verso dominio diverso
    'siteurl_hijack'  => '/https?:\/\/(?!'.preg_quote( rtrim( home_url(), '/' ), '/' ).')[a-z0-9\-\.]+\.[a-z]{2,}/i',
    // Serialized PHP con codice malevolo in wp_options / widget
    'serialized_eval' => '/s:\d+:["\'].*eval\s*\(/i',
    'serialized_b64'  => '/s:\d+:["\'].*base64_decode/i',
    // Utenti admin fantasma aggiunti nel DB
    // (scansionato separatamente in k2s_scan_ghost_admins)
    // Redirect nei widget o nel tema via db
    'widget_redirect' => '/header\s*\(\s*["\']Location:/i',
    // Long base64 nascosta in option_value
    'long_b64_in_db'  => '/[A-Za-z0-9+\/]{500,}={0,2}/',
    // Cron job WordPress malevolo registrato via DB
    'malicious_cron'  => '/(curl_exec|shell_exec|exec|system|passthru)\s*\(/i',
    // Pagine/post con redirect nascosto inseriti dall'attaccante
    'post_js_redirect'=> '/window\.location\s*=\s*["\']https?:\/\//i',
    // File index.html/htm inseriti come pagina di cortesia nei post
    'courtesy_page'   => '/Sito\s+in\s+manutenzione|Under\s+Construction|Hacked\s+by/i',
];

// ═══════════════════════════════════════════════════════════════════
//  Sovrascrive i pattern builtin con quelli remoti se disponibili
// ═══════════════════════════════════════════════════════════════════
add_action( 'init', function() {
    global $K2S_PHP_PATTERNS, $K2S_DB_PATTERNS;
    if ( function_exists( 'k2s_get_active_definitions' ) ) {
        $defs = k2s_get_active_definitions();
        if ( ! empty( $defs['php_patterns'] ) ) $K2S_PHP_PATTERNS = $defs['php_patterns'];
        if ( ! empty( $defs['db_patterns'] ) )  $K2S_DB_PATTERNS  = $defs['db_patterns'];
    }
}, 5 );

// ═══════════════════════════════════════════════════════════════════
//  SCANNER FILE (PHP + HTML/HTM – attacco tipo "index replace")
// ═══════════════════════════════════════════════════════════════════
function k2s_scan_php_files() {
    global $K2S_PHP_PATTERNS;

    $threats      = [];
    $depth        = (int) get_option( 'k2s_scan_depth', 3 );
    $wp_root      = ABSPATH;
    $scan_dirs    = [
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/uploads',
        $wp_root,
    ];
    $last_scan_ts = get_option( 'k2s_last_scan_ts', 0 );

    // Estensioni da analizzare
    $scan_exts = [ 'php', 'html', 'htm', 'js', 'htaccess' ];

    foreach ( $scan_dirs as $dir ) {
        if ( ! is_dir( $dir ) ) continue;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        $iterator->setMaxDepth( $depth );

        foreach ( $iterator as $file ) {
            if ( ! $file->isFile() ) continue;

            $ext = strtolower( $file->getExtension() );
            // Per .htaccess l'estensione è vuota, controlliamo il basename
            $basename = $file->getFilename();
            $is_htaccess = ( $basename === '.htaccess' );

            if ( ! in_array( $ext, $scan_exts, true ) && ! $is_htaccess ) continue;
            if ( $file->getMTime() < $last_scan_ts ) continue;

            $path    = $file->getRealPath();
            $rel     = str_replace( ABSPATH, '', $path );
            $content = @file_get_contents( $path );
            if ( $content === false ) continue;

            // ── File HTML/HTM: non dovrebbero MAI contenere <?php ──
            if ( in_array( $ext, [ 'html', 'htm' ], true ) ) {
                if ( preg_match( '/\<\?php/i', $content ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'php_in_html',
                        'detail' => "Codice PHP trovato in file HTML: $rel",
                    ];
                }
                // Pagina di cortesia / defacement
                if ( preg_match( '/Sito\s+in\s+manutenzione|Under\s+Construction|Hacked\s+by|maintenance/i', $content ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'index_defacement',
                        'detail' => "Possibile pagina di defacement: $rel",
                    ];
                }
                // Redirect in HTML
                if ( preg_match( '/<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]*url\s*=/i', $content ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'html_redirect',
                        'detail' => "Meta-redirect sospetto in: $rel",
                    ];
                }
                continue; // non applicare i pattern PHP a file html
            }

            // ── .htaccess: cerca redirect anomali ──────────────────
            if ( $is_htaccess ) {
                if ( preg_match( '/RewriteRule.*https?:\/\/(?!' . preg_quote( parse_url( home_url(), PHP_URL_HOST ), '/' ) . ')/i', $content ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'htaccess_redirect',
                        'detail' => "RewriteRule verso dominio esterno in: $rel",
                    ];
                }
                if ( preg_match( '/php_value\s+auto_prepend_file|php_value\s+auto_append_file/i', $content ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'htaccess_autoprepend',
                        'detail' => "auto_prepend/append_file in .htaccess: $rel",
                    ];
                }
                continue;
            }

            // ── PHP / JS: pattern generici + specifici ─────────────
            foreach ( $K2S_PHP_PATTERNS as $pattern_key => $pattern ) {
                // php_in_html si applica solo a html/htm, già gestito sopra
                if ( $pattern_key === 'php_in_html' ) continue;

                if ( preg_match( $pattern, $content ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'php_malware',
                        'detail' => "Pattern [$pattern_key] in: $rel",
                    ];
                    break;
                }
            }
        }
    }

    // ── Scansione file "anomali" nella root wp-content ─────────────
    $threats = array_merge( $threats, k2s_scan_unexpected_index_files() );

    update_option( 'k2s_last_scan_ts', time() );
    return $threats;
}

// ─── Cerca index.html/htm/php creati dentro wp-content ─────────────
// (non dovrebbero esistere file index.html o index.htm lì dentro
//  a meno che non li abbia messi l'attaccante)
function k2s_scan_unexpected_index_files() {
    $threats    = [];
    $check_dirs = [
        WP_CONTENT_DIR,
        WP_CONTENT_DIR . '/themes',
        WP_CONTENT_DIR . '/plugins',
        WP_CONTENT_DIR . '/uploads',
    ];

    // File index "leciti" che WP crea da solo (stub vuoti)
    $wp_stub = "<?php\n// Silence is golden.\n";

    foreach ( $check_dirs as $dir ) {
        foreach ( [ 'index.html', 'index.htm', 'index.php' ] as $fname ) {
            $fpath = trailingslashit( $dir ) . $fname;
            if ( ! file_exists( $fpath ) ) continue;

            $content = @file_get_contents( $fpath );
            if ( $content === false ) continue;

            // index.php vuoto/stub è normale in WP — skip
            if ( $fname === 'index.php' && trim( $content ) === trim( $wp_stub ) ) continue;
            if ( $fname === 'index.php' && trim( $content ) === '' ) continue;

            // index.html / index.htm NON dovrebbero esistere in queste dir
            if ( in_array( $fname, [ 'index.html', 'index.htm' ], true ) ) {
                $threats[] = [
                    'level'  => 'critical',
                    'type'   => 'unexpected_index_file',
                    'detail' => "File non atteso trovato (tipico defacement): " . str_replace( ABSPATH, '', $fpath ),
                ];
                continue;
            }

            // index.php con contenuto non-stub: analizza
            if ( strlen( trim( $content ) ) > 100 ) {
                // Controlla se contiene redirect o codice malevolo
                if ( preg_match( '/header\s*\(\s*["\']Location:|<meta.*refresh.*url=/i', $content ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'index_php_redirect',
                        'detail' => "index.php contiene redirect: " . str_replace( ABSPATH, '', $fpath ),
                    ];
                } elseif ( preg_match( '/eval|base64_decode|gzinflate|shell_exec/i', $content ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'index_php_malware',
                        'detail' => "index.php contiene codice malevolo: " . str_replace( ABSPATH, '', $fpath ),
                    ];
                }
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

    // Tabelle da scansionare e colonne di testo libero
    $scan_targets = [
        $wpdb->posts         => [ 'post_content', 'post_excerpt', 'guid' ],
        $wpdb->postmeta      => [ 'meta_value' ],
        $wpdb->options       => [ 'option_value' ],
        $wpdb->comments      => [ 'comment_content', 'comment_author_url' ],
        $wpdb->commentmeta   => [ 'meta_value' ],
    ];

    foreach ( $scan_targets as $table => $columns ) {
        $exists = $wpdb->get_var( $wpdb->prepare( "SHOW TABLES LIKE %s", $table ) );
        if ( ! $exists ) continue;

        foreach ( $columns as $col ) {
            $offset = 0;
            $batch  = 200;
            do {
                $rows = $wpdb->get_results(
                    $wpdb->prepare(
                        "SELECT `$col` FROM `$table` LIMIT %d OFFSET %d",
                        $batch, $offset
                    ),
                    ARRAY_A
                );
                if ( empty( $rows ) ) break;

                foreach ( $rows as $row ) {
                    $value = $row[ $col ] ?? '';
                    if ( empty( $value ) || ! is_string( $value ) ) continue;

                    foreach ( $K2S_DB_PATTERNS as $pattern_key => $pattern ) {
                        if ( preg_match( $pattern, $value ) ) {
                            $threats[] = [
                                'level'  => 'warning',
                                'type'   => 'db_injection',
                                'detail' => "Pattern [$pattern_key] trovato in $table.$col",
                            ];
                            break;
                        }
                    }
                }

                $offset += $batch;
            } while ( count( $rows ) === $batch );
        }
    }

    // ── Check specifici per attacco "index replace" (17/03) ────────
    $threats = array_merge( $threats, k2s_scan_ghost_admins() );
    $threats = array_merge( $threats, k2s_scan_siteurl_hijack() );
    $threats = array_merge( $threats, k2s_scan_malicious_crons() );

    return $threats;
}

// ─── Utenti admin "fantasma" aggiunti dall'attaccante ──────────────
function k2s_scan_ghost_admins() {
    global $wpdb;
    $threats = [];

    // Prende tutti gli admin registrati (capability = administrator)
    $admin_ids = $wpdb->get_col(
        "SELECT user_id FROM {$wpdb->usermeta}
         WHERE meta_key = '{$wpdb->prefix}capabilities'
         AND meta_value LIKE '%administrator%'"
    );

    if ( empty( $admin_ids ) ) return $threats;

    foreach ( $admin_ids as $uid ) {
        $user = get_userdata( $uid );
        if ( ! $user ) continue;

        // Flag: email con domini usa-e-getta o TLD sospetti
        $suspicious_email_domains = [ 'mailinator.com', 'guerrillamail.com', 'tempmail', 'throwam.com', 'sharklasers.com', 'yopmail.com' ];
        $email_domain = strtolower( substr( strrchr( $user->user_email, '@' ), 1 ) );
        foreach ( $suspicious_email_domains as $bad ) {
            if ( strpos( $email_domain, $bad ) !== false ) {
                $threats[] = [
                    'level'  => 'critical',
                    'type'   => 'ghost_admin',
                    'detail' => "Utente admin con email sospetta: {$user->user_login} ({$user->user_email})",
                ];
                break;
            }
        }

        // Flag: registrato di notte (00:00–05:00) — possibile bot
        $hour = (int) date( 'H', strtotime( $user->user_registered ) );
        if ( $hour >= 0 && $hour <= 5 ) {
            $threats[] = [
                'level'  => 'warning',
                'type'   => 'suspicious_admin_registration',
                'detail' => "Admin registrato di notte ({$user->user_registered}): {$user->user_login}",
            ];
        }
    }

    return $threats;
}

// ─── siteurl/home dirottati verso dominio diverso ──────────────────
function k2s_scan_siteurl_hijack() {
    global $wpdb;
    $threats    = [];
    $real_host  = parse_url( get_option( 'siteurl' ), PHP_URL_HOST );

    $options_to_check = [ 'siteurl', 'home', 'upload_url_path', 'template', 'stylesheet' ];

    foreach ( $options_to_check as $opt ) {
        $val = $wpdb->get_var( $wpdb->prepare(
            "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
            $opt
        ) );
        if ( ! $val ) continue;

        // Cerca URL con host diverso da quello del sito
        if ( preg_match( '/https?:\/\/([a-z0-9\-\.]+)/i', $val, $m ) ) {
            $found_host = strtolower( $m[1] );
            if ( $found_host && $found_host !== strtolower( $real_host ) ) {
                $threats[] = [
                    'level'  => 'critical',
                    'type'   => 'siteurl_hijack',
                    'detail' => "Opzione [$opt] punta a host diverso: $found_host (atteso: $real_host)",
                ];
            }
        }
    }

    return $threats;
}

// ─── Cron job WordPress malevoli ───────────────────────────────────
function k2s_scan_malicious_crons() {
    $threats  = [];
    $crons    = _get_cron_array();
    if ( empty( $crons ) ) return $threats;

    // Hook legittimi WP + plugin comuni
    $whitelist = [
        'wp_scheduled_delete', 'wp_update_user_counts', 'wp_privacy_delete_old_export_files',
        'wp_version_check', 'wp_update_plugins', 'wp_update_themes',
        'recovery_mode_clean_expired_keys', 'delete_expired_transients',
        'k2s_hourly_scan', 'wp_scheduled_auto_draft_delete',
    ];

    foreach ( $crons as $timestamp => $cron_hooks ) {
        foreach ( $cron_hooks as $hook => $events ) {
            if ( in_array( $hook, $whitelist, true ) ) continue;

            // Hook con nomi casuali o molto corti (segnale di malware)
            if ( strlen( $hook ) < 5 || preg_match( '/^[a-z]{1,4}\d{3,}$/', $hook ) ) {
                $threats[] = [
                    'level'  => 'warning',
                    'type'   => 'suspicious_cron',
                    'detail' => "Cron job con nome sospetto: [$hook] schedulato per " . date( 'd/m/Y H:i', $timestamp ),
                ];
            }

            // Callback del cron che richiama funzioni pericolose
            foreach ( $events as $event ) {
                $args = maybe_serialize( $event['args'] ?? [] );
                if ( preg_match( '/eval|base64_decode|shell_exec|exec\(|system\(/i', $args ) ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'malicious_cron',
                        'detail' => "Cron job con argomenti malevoli: [$hook]",
                    ];
                }
            }
        }
    }

    return $threats;
}
