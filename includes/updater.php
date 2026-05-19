<?php
/**
 * K2 Sentinel – Auto Updater
 *
 * Aggancia il sistema di aggiornamento nativo di WordPress
 * alle GitHub Releases del repo Avidsnake92/k2-sentinel.
 *
 * Flusso:
 *  1. WP chiama il filtro pre_set_site_transient_update_plugins ogni 12h
 *  2. Noi interroghiamo l'API GitHub per l'ultima release
 *  3. Se il tag è più nuovo della versione installata, iniettiamo i dati
 *  4. WP mostra la notifica "Aggiornamento disponibile" e il pulsante Aggiorna
 *  5. Il download avviene dallo zip allegato alla GitHub Release
 */
if ( ! defined( 'ABSPATH' ) ) exit;

define( 'K2S_GITHUB_USER',   'Avidsnake92' );
define( 'K2S_GITHUB_REPO',   'k2-sentinel' );
define( 'K2S_PLUGIN_SLUG',   'k2-sentinel/k2-sentinel.php' );
define( 'K2S_GITHUB_API',    'https://api.github.com/repos/' . K2S_GITHUB_USER . '/' . K2S_GITHUB_REPO . '/releases/latest' );
define( 'K2S_PLUGIN_SLUG',   'k2-sentinel/k2-sentinel.php' );

/**
 * Normalizza qualsiasi formato di tag GitHub in un version_compare-safe string.
 * Esempi:
 *   K2-Sentinel_v1.0  → 1.0.0
 *   v1.2.0            → 1.2.0
 *   release-2.1       → 2.1.0
 *   1.3               → 1.3.0
 */
function k2s_normalize_version( $tag ) {
    // Estrai solo la parte numerica con punti
    if ( preg_match( '/(\d+\.\d+(?:\.\d+)?)/', $tag, $m ) ) {
        $ver   = $m[1];
        $parts = explode( '.', $ver );
        // Assicura sempre tre parti (major.minor.patch)
        while ( count( $parts ) < 3 ) {
            $parts[] = '0';
        }
        return implode( '.', $parts );
    }
    return '0.0.0';
}

class K2S_Updater {

    private static $instance = null;

    public static function init() {
        if ( self::$instance === null ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_filter( 'pre_set_site_transient_update_plugins', [ $this, 'check_update' ] );
        add_filter( 'plugins_api',                           [ $this, 'plugin_info' ], 20, 3 );
        add_filter( 'upgrader_post_install',                 [ $this, 'after_install' ], 10, 3 );
        add_action( 'admin_notices',                         [ $this, 'maybe_show_notice' ] );
    }

    // ── 1. Controlla se c'è una versione più recente ──────────────
    public function check_update( $transient ) {
        if ( empty( $transient->checked ) ) return $transient;

        $release = $this->get_latest_release();
        if ( ! $release || is_wp_error( $release ) ) return $transient;

        $latest_version = k2s_normalize_version( $release['tag_name'] );

        if ( version_compare( $latest_version, K2_SENTINEL_VERSION, '>' ) ) {
            $download_url = $release['zipball_url'] ?? '';

            // Preferisci lo zip allegato alla release se esiste
            if ( ! empty( $release['assets'] ) ) {
                foreach ( $release['assets'] as $asset ) {
                    if ( str_ends_with( $asset['name'], '.zip' ) ) {
                        $download_url = $asset['browser_download_url'];
                        break;
                    }
                }
            }

            $transient->response[ K2S_PLUGIN_SLUG ] = (object) [
                'slug'        => 'k2-sentinel',
                'plugin'      => K2S_PLUGIN_SLUG,
                'new_version' => $latest_version,
                'url'         => 'https://github.com/' . K2S_GITHUB_USER . '/' . K2S_GITHUB_REPO,
                'package'     => $download_url,
                'icons'       => [],
                'banners'     => [],
                'tested'      => get_bloginfo('version'),
                'requires_php'=> '7.4',
            ];
        }

        return $transient;
    }

    // ── 2. Info plugin nel popup "Visualizza dettagli versione" ───
    public function plugin_info( $result, $action, $args ) {
        if ( $action !== 'plugin_information' ) return $result;
        if ( ( $args->slug ?? '' ) !== 'k2-sentinel' ) return $result;

        $release = $this->get_latest_release();
        if ( ! $release || is_wp_error( $release ) ) return $result;

        $latest_version = k2s_normalize_version( $release['tag_name'] );
        $changelog      = $this->parse_changelog( $release['body'] ?? '' );
        $download_url   = $release['zipball_url'] ?? '';

        if ( ! empty( $release['assets'] ) ) {
            foreach ( $release['assets'] as $asset ) {
                if ( str_ends_with( $asset['name'], '.zip' ) ) {
                    $download_url = $asset['browser_download_url'];
                    break;
                }
            }
        }

        return (object) [
            'name'          => 'K2 Sentinel',
            'slug'          => 'k2-sentinel',
            'version'       => $latest_version,
            'author'        => '<a href="https://k2tech.it">K2Tech</a>',
            'homepage'      => 'https://github.com/' . K2S_GITHUB_USER . '/' . K2S_GITHUB_REPO,
            'short_description' => 'Antivirus, Firewall, 2FA, Traffic Monitor e Integrità Core per WordPress.',
            'sections'      => [
                'description' => '<p>K2 Sentinel protegge il tuo sito WordPress con scanner antivirus, firewall in tempo reale, 2FA, traffic monitor e verifica integrità core.</p>',
                'changelog'   => $changelog,
            ],
            'download_link' => $download_url,
            'tested'        => get_bloginfo('version'),
            'requires'      => '5.8',
            'requires_php'  => '7.4',
            'last_updated'  => $release['published_at'] ?? '',
        ];
    }

    // ── 3. Rinomina cartella dopo installazione ────────────────────
    // GitHub estrae lo zip come "Avidsnake92-k2-sentinel-{hash}/"
    // WP si aspetta "k2-sentinel/" — lo rinominiamo.
    public function after_install( $response, $hook_extra, $result ) {
        if ( ( $hook_extra['plugin'] ?? '' ) !== K2S_PLUGIN_SLUG ) return $response;

        global $wp_filesystem;
        $plugin_dir    = WP_PLUGIN_DIR . '/k2-sentinel';
        $extracted_dir = $result['destination'] ?? '';

        if ( $extracted_dir !== $plugin_dir ) {
            $wp_filesystem->move( $extracted_dir, $plugin_dir, true );
            $result['destination'] = $plugin_dir;
        }

        // Riattiva il plugin dopo l'aggiornamento
        activate_plugin( K2S_PLUGIN_SLUG );

        return $result;
    }

    // ── 4. Avviso admin se c'è un aggiornamento disponibile ───────
    public function maybe_show_notice() {
        if ( ! current_user_can( 'update_plugins' ) ) return;
        $screen = get_current_screen();
        if ( ! $screen || $screen->id !== 'plugins' ) return;

        $release = $this->get_latest_release();
        if ( ! $release || is_wp_error( $release ) ) return;

        $latest = k2s_normalize_version( $release['tag_name'] );
        if ( ! version_compare( $latest, K2_SENTINEL_VERSION, '>' ) ) return;

        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>K2 Sentinel:</strong> è disponibile la versione <strong>' . esc_html( $latest ) . '</strong>. ';
        echo '<a href="' . esc_url( admin_url( 'update-core.php' ) ) . '">Aggiorna ora</a></p>';
        echo '</div>';
    }

    // ── Fetch API GitHub con cache 6 ore ──────────────────────────
    private function get_latest_release() {
        $cached = get_transient( 'k2s_github_release' );
        if ( $cached !== false ) return $cached;

        $response = wp_remote_get( K2S_GITHUB_API, [
            'timeout'    => 12,
            'user-agent' => 'K2-Sentinel-Updater/' . K2_SENTINEL_VERSION . '; ' . home_url(),
            'headers'    => [ 'Accept' => 'application/vnd.github.v3+json' ],
        ] );

        if ( is_wp_error( $response ) ) return $response;
        if ( wp_remote_retrieve_response_code( $response ) !== 200 ) {
            return new WP_Error( 'github_api_error', 'GitHub API: HTTP ' . wp_remote_retrieve_response_code( $response ) );
        }

        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $data['tag_name'] ) ) return null;

        set_transient( 'k2s_github_release', $data, 6 * HOUR_IN_SECONDS );
        return $data;
    }

    // ── Converte il corpo Markdown della release in HTML ──────────
    private function parse_changelog( $body ) {
        if ( empty( $body ) ) return '<p>Nessun changelog disponibile.</p>';

        // Converti Markdown base in HTML
        $html = esc_html( $body );
        $html = preg_replace( '/^### (.+)$/m',  '<h4>$1</h4>', $html );
        $html = preg_replace( '/^## (.+)$/m',   '<h3>$1</h3>', $html );
        $html = preg_replace( '/^# (.+)$/m',    '<h2>$1</h2>', $html );
        $html = preg_replace( '/^\* (.+)$/m',   '<li>$1</li>', $html );
        $html = preg_replace( '/^- (.+)$/m',    '<li>$1</li>', $html );
        $html = preg_replace( '/(<li>.*<\/li>)/s', '<ul>$1</ul>', $html );
        $html = preg_replace( '/`([^`]+)`/',    '<code>$1</code>', $html );
        $html = nl2br( $html );

        return $html;
    }

    // ── Forza controllo aggiornamenti (cancella cache) ─────────────
    public static function force_check() {
        delete_transient( 'k2s_github_release' );
        delete_site_transient( 'update_plugins' );
    }
}

// Inizializza solo nell'area admin
if ( is_admin() ) {
    K2S_Updater::init();
}

// AJAX: forza controllo aggiornamenti
add_action( 'wp_ajax_k2s_force_update_check', function() {
    check_ajax_referer( 'k2s_nonce', 'nonce' );
    if ( ! current_user_can( 'update_plugins' ) ) wp_die();

    K2S_Updater::force_check();

    // Recupera info release
    $response = wp_remote_get( K2S_GITHUB_API, [
        'timeout'    => 12,
        'user-agent' => 'K2-Sentinel-Updater/' . K2_SENTINEL_VERSION,
        'headers'    => [ 'Accept' => 'application/vnd.github.v3+json' ],
    ]);

    if ( is_wp_error( $response ) ) {
        wp_send_json_error( $response->get_error_message() );
    }

    $data    = json_decode( wp_remote_retrieve_body( $response ), true );
    $latest  = k2s_normalize_version( $data['tag_name'] ?? '0.0.0' );
    $current = K2_SENTINEL_VERSION;
    $has_update = version_compare( $latest, $current, '>' );

    set_transient( 'k2s_github_release', $data, 6 * HOUR_IN_SECONDS );

    wp_send_json_success([
        'current'    => $current,
        'latest'     => $latest,
        'has_update' => $has_update,
        'update_url' => admin_url( 'update-core.php' ),
        'release_url'=> $data['html_url'] ?? '',
        'published'  => $data['published_at'] ?? '',
    ]);
});
