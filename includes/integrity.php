<?php
/**
 * K2 Sentinel – Core Integrity Checker
 * Confronta i file core di WordPress con i checksum ufficiali di wordpress.org
 * e segnala qualsiasi file modificato, aggiunto o mancante.
 */
if ( ! defined( 'ABSPATH' ) ) exit;

// ═══════════════════════════════════════════════════════════════════
//  ENTRY POINT principale
// ═══════════════════════════════════════════════════════════════════
function k2s_check_core_integrity() {
    $wp_version = get_bloginfo( 'version' );
    $locale     = get_locale();

    // Scarica i checksum ufficiali da wordpress.org
    $checksums = k2s_fetch_wp_checksums( $wp_version, $locale );

    if ( is_wp_error( $checksums ) ) {
        k2s_log( 'warning', 'core_integrity', 'Impossibile scaricare checksum: ' . $checksums->get_error_message() );
        return [];
    }

    $threats  = [];
    $abspath  = realpath( ABSPATH );

    // File e cartelle da escludere dal confronto
    $exclude_paths = [
        'wp-content',
        'wp-config.php',
        '.htaccess',
        'robots.txt',
        'sitemap.xml',
        'favicon.ico',
        'index.php', // può essere modificato legittimamente
    ];

    $checked  = 0;
    $modified = [];
    $extra    = [];

    // ── 1. Controlla ogni file nei checksum ufficiali ─────────────
    foreach ( $checksums as $rel_path => $expected_md5 ) {

        // Salta wp-content (gestito separatamente)
        $parts = explode( '/', $rel_path );
        if ( in_array( $parts[0], $exclude_paths, true ) ) continue;

        $abs_path = $abspath . DIRECTORY_SEPARATOR . str_replace( '/', DIRECTORY_SEPARATOR, $rel_path );

        if ( ! file_exists( $abs_path ) ) {
            $threats[] = [
                'level'  => 'warning',
                'type'   => 'core_missing_file',
                'detail' => "File core mancante: $rel_path",
            ];
            continue;
        }

        $actual_md5 = md5_file( $abs_path );
        if ( $actual_md5 !== $expected_md5 ) {
            $modified[] = $rel_path;
            $threats[] = [
                'level'  => 'critical',
                'type'   => 'core_modified_file',
                'detail' => "File core modificato: $rel_path (atteso: {$expected_md5}, trovato: {$actual_md5})",
            ];
        }

        $checked++;
    }

    // ── 2. Cerca file PHP "extra" in cartelle core (non dovrebbero esserci) ──
    $core_dirs = [ ABSPATH . 'wp-admin', ABSPATH . 'wp-includes' ];
    foreach ( $core_dirs as $dir ) {
        if ( ! is_dir( $dir ) ) continue;

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        foreach ( $iterator as $file ) {
            if ( ! $file->isFile() ) continue;
            $ext = strtolower( $file->getExtension() );
            if ( ! in_array( $ext, [ 'php', 'js', 'css' ], true ) ) continue;

            $rel = str_replace( $abspath . DIRECTORY_SEPARATOR, '', $file->getRealPath() );
            $rel = str_replace( DIRECTORY_SEPARATOR, '/', $rel );

            // Se non è nei checksum ufficiali, verifica se è un file legittimo WP
            if ( ! isset( $checksums[ $rel ] ) ) {
                $is_legitimate = false;

                // 1. WordPress mette index.php stub (Silence is golden) in ogni cartella
                if ( basename( $rel ) === 'index.php' ) {
                    $file_content = @file_get_contents( $file->getRealPath() );
                    $trimmed      = trim( $file_content ?? '' );
                    if ( strlen( $trimmed ) < 60 &&
                         ( strpos( $trimmed, '<?php' ) === 0 ) &&
                         ( strpos( $trimmed, 'eval' ) === false ) &&
                         ( strpos( $trimmed, 'base64' ) === false )
                    ) {
                        $is_legitimate = true; // stub vuoto o silence
                    }
                }

                // 2. Cartelle con ID numerico (asset versioning: /pomo/325273/, /css/dist/995685/)
                //    WP genera queste cartelle per il cache-busting degli asset — sono normali
                if ( preg_match( '/\/\d{4,}\//', $rel ) ) {
                    $is_legitimate = true;
                }

                // 3. File nei percorsi di build noti (generati automaticamente da WP)
                $known_generated = [
                    'wp-includes/css/dist/',
                    'wp-includes/js/dist/',
                    'wp-admin/css/colors/',
                    'wp-includes/certificates/',
                    'wp-includes/pomo/',
                    'wp-includes/sodium_compat/',
                    'wp-includes/Text/',
                    'wp-includes/ID3/',
                    'wp-includes/SimplePie/',
                    'wp-includes/PHPMailer/',
                    'wp-includes/Requests/',
                    'wp-includes/IXR/',
                ];
                foreach ( $known_generated as $path ) {
                    if ( strpos( $rel, $path ) === 0 ) {
                        $is_legitimate = true;
                        break;
                    }
                }

                if ( ! $is_legitimate ) {
                    $threats[] = [
                        'level'  => 'critical',
                        'type'   => 'core_extra_file',
                        'detail' => "File non ufficiale trovato in cartella core: $rel",
                    ];
                    $extra[] = $rel;
                }
            }
        }
    }

    // Salva il risultato dell'ultima verifica
    update_option( 'k2s_core_integrity_last', [
        'time'     => current_time( 'mysql' ),
        'version'  => $wp_version,
        'checked'  => $checked,
        'modified' => count( $modified ),
        'extra'    => count( $extra ),
        'threats'  => count( $threats ),
    ] );

    if ( ! empty( $threats ) ) {
        k2s_log( 'critical', 'core_integrity',
            sprintf( 'Integrità core: %d modificati, %d extra, %d mancanti su %d file controllati.',
                count( $modified ), count( $extra ), count( $threats ) - count( $modified ) - count( $extra ), $checked )
        );
    }

    return $threats;
}

// ─── Scarica i checksum da wordpress.org ─────────────────────────
function k2s_fetch_wp_checksums( $version, $locale = 'en_US' ) {
    // Cache locale: non scaricare più di una volta al giorno per stessa versione
    $cache_key = 'k2s_checksums_' . md5( $version . $locale );
    $cached    = get_transient( $cache_key );
    if ( $cached !== false ) return $cached;

    // Prova prima con la locale del sito, poi fallback en_US
    $locales = array_unique( [ $locale, 'en_US' ] );

    foreach ( $locales as $loc ) {
        $url = "https://api.wordpress.org/core/checksums/1.0/?version={$version}&locale={$loc}";
        $response = wp_remote_get( $url, [
            'timeout'    => 20,
            'user-agent' => 'K2-Sentinel/' . K2_SENTINEL_VERSION,
            'sslverify'  => true,
        ] );

        if ( is_wp_error( $response ) ) continue;
        if ( wp_remote_retrieve_response_code( $response ) !== 200 ) continue;

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $body['checksums'] ) ) continue;

        $checksums = $body['checksums'];
        // Cache per 24 ore
        set_transient( $cache_key, $checksums, DAY_IN_SECONDS );
        return $checksums;
    }

    return new WP_Error( 'checksums_unavailable', 'Impossibile scaricare i checksum da wordpress.org' );
}

// ─── AJAX: verifica manuale ────────────────────────────────────────
add_action( 'wp_ajax_k2s_check_core', 'k2s_ajax_check_core' );

function k2s_ajax_check_core() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );

    // Invalida cache per forzare il re-download
    $version = get_bloginfo( 'version' );
    $locale  = get_locale();
    delete_transient( 'k2s_checksums_' . md5( $version . $locale ) );

    $threats = k2s_check_core_integrity();

    wp_send_json_success([
        'threats' => count( $threats ),
        'details' => array_map( fn($t) => $t['detail'], $threats ),
        'summary' => get_option( 'k2s_core_integrity_last', [] ),
    ]);
}
