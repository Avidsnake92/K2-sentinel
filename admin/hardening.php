<?php if ( ! defined( 'ABSPATH' ) ) exit;
// admin/hardening.php

$hardening = get_option( 'k2s_hardening', [] );

$measures = [
    'hide_wp_version'       => [ 'icon' => '🏷️',  'title' => 'Nascondi versione WordPress',      'desc' => 'Rimuove il meta generator e il parametro ?ver= da CSS/JS. Rende più difficile identificare la versione WP.' ],
    'disable_xmlrpc'        => [ 'icon' => '🔌',  'title' => 'Disabilita XML-RPC',               'desc' => 'Blocca completamente xmlrpc.php, spesso sfruttato per brute force e DDoS amplification.' ],
    'restrict_rest_api'     => [ 'icon' => '🔒',  'title' => 'Proteggi REST API',                'desc' => 'Limita l\'accesso alla REST API agli utenti autenticati. Previene la lettura di dati da utenti anonimi.' ],
    'disable_user_enum'     => [ 'icon' => '👤',  'title' => 'Blocca enumerazione utenti',       'desc' => 'Impedisce di scoprire username via ?author=1 e via REST API /wp/v2/users.' ],
    'limit_login_attempts'  => [ 'icon' => '🔑',  'title' => 'Limita tentativi di login',        'desc' => 'Blocca automaticamente gli IP dopo troppi tentativi di login falliti (default: 5 in 15 minuti).' ],
    'security_headers'      => [ 'icon' => '',  'title' => 'Header di sicurezza HTTP',         'desc' => 'Aggiunge X-Frame-Options, X-Content-Type-Options, CSP base, HSTS (su HTTPS) e altri header di protezione.' ],
    'hide_php_errors'       => [ 'icon' => '',  'title' => 'Nascondi errori PHP in frontend',  'desc' => 'Disattiva la visualizzazione di errori PHP per i visitatori. Evita di esporre informazioni sul server.' ],
    'disable_file_edit'     => [ 'icon' => '✏️',  'title' => 'Disabilita editor file in WP',     'desc' => 'Disattiva l\'editor di temi e plugin nell\'admin WP (DISALLOW_FILE_EDIT). Consigliato sempre.' ],
    'force_ssl_admin'       => [ 'icon' => '',  'title' => 'Forza SSL nell\'area admin',       'desc' => 'Obbliga HTTPS per login e pannello admin (FORCE_SSL_ADMIN). Richiede certificato SSL attivo.' ],
    'protect_sensitive_files'=> [ 'icon' => '', 'title' => 'Proteggi file sensibili',          'desc' => 'Blocca l\'accesso diretto a wp-config.php, .htaccess, readme.html e license.txt via .htaccess.' ],
    'disable_pingback'      => [ 'icon' => '',  'title' => 'Disabilita Pingback',              'desc' => 'Rimuove il supporto pingback, spesso usato per DDoS amplification verso altri siti.' ],
    'block_hotlinking'      => [ 'icon' => '🖼️',  'title' => 'Blocca hotlinking immagini',       'desc' => 'Impedisce ad altri siti di usare le tue immagini direttamente (salva banda). Configurato via .htaccess.' ],
];
?>
<div class="k2s-wrap">
    <div class="k2s-header">
        <div class="k2s-logo">
            <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
            <div class="k2s-logo__text">
                <span class="k2s-logo__name">Hardening</span>
                <span class="k2s-logo__sub">Misure di sicurezza base</span>
            </div>
        </div>
        <button id="k2s-save-hardening" class="k2s-btn k2s-btn--primary">Salva tutto</button>
    </div>

    <div id="k2s-hardening-notice" style="display:none" class="k2s-notice success"></div>

    <div class="k2s-section">
        <h2 class="k2s-section__title">Misure di Sicurezza</h2>
        <p style="font-size:13px;color:var(--k2-muted);margin:0 0 20px;">
            Attiva o disattiva le misure di sicurezza. Le modifiche vengono applicate immediatamente e, dove necessario, aggiornano il file <code>.htaccess</code>.
        </p>

        <div class="k2s-hardening-grid">
        <?php foreach ( $measures as $key => $m ) :
            $active = ! empty( $hardening[ $key ] );
        ?>
            <div class="k2s-hardening-card <?php echo $active ? 'k2s-hardening-card--active' : ''; ?>" data-key="<?php echo esc_attr( $key ); ?>">
                <div class="k2s-hardening-card__top">
                    <div class="k2s-hardening-card__icon"><?php echo $m['icon']; ?></div>
                    <label class="k2s-toggle">
                        <input type="checkbox" class="k2s-hardening-toggle" name="<?php echo esc_attr( $key ); ?>" <?php checked( $active ); ?>>
                        <span class="k2s-toggle__slider"></span>
                    </label>
                </div>
                <div class="k2s-hardening-card__title"><?php echo esc_html( $m['title'] ); ?></div>
                <div class="k2s-hardening-card__desc"><?php echo esc_html( $m['desc'] ); ?></div>
                <div class="k2s-hardening-card__status">
                    <?php echo $active
                        ? '<span class="k2s-badge k2s-badge--ok">ATTIVO</span>'
                        : '<span class="k2s-badge k2s-badge--off">DISATTIVO</span>'; ?>
                </div>
            </div>
        <?php endforeach; ?>
        </div>
    </div>

    <!-- Bonifica automatica -->
    <div class="k2s-section">
        <h2 class="k2s-section__title">Bonifica Automatica</h2>
        <p style="font-size:13px;color:var(--k2-muted);margin:0 0 16px;">
            Quando abilitata, K2 Sentinel bonifica automaticamente le minacce trovate durante ogni scansione: i file infetti vengono messi in quarantena e i record DB vengono ripuliti dopo backup.
        </p>

        <div class="k2s-toggle-row" style="border:none;padding:0;margin-bottom:16px;">
            <label class="k2s-toggle">
                <input type="checkbox" id="k2s-auto-remediation"
                    <?php checked( get_option( 'k2s_auto_remediation', 0 ), 1 ); ?>>
                <span class="k2s-toggle__slider"></span>
            </label>
            <span style="font-weight:600;">Abilita bonifica automatica</span>
        </div>

        <div class="k2s-remediation-info">
            <div class="k2s-rem-step">
                <div class="k2s-rem-step__num">1</div>
                <div>
                    <strong>Scanner rileva minaccia</strong><br>
                    <span>Ogni ora, o manualmente dalla dashboard</span>
                </div>
            </div>
            <div class="k2s-rem-arrow">→</div>
            <div class="k2s-rem-step">
                <div class="k2s-rem-step__num">2</div>
                <div>
                    <strong>Bonifica automatica</strong><br>
                    <span>File → quarantena · DB → backup + pulizia</span>
                </div>
            </div>
            <div class="k2s-rem-arrow">→</div>
            <div class="k2s-rem-step">
                <div class="k2s-rem-step__num">3</div>
                <div>
                    <strong>Notifica email + log</strong><br>
                    <span>Report completo inviato all'admin</span>
                </div>
            </div>
        </div>
    </div>

    <div class="k2s-footer">
        <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
        K2 Sentinel è un prodotto K2Tech
    </div>
</div>

<style>
.k2s-hardening-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
}
@media(max-width:900px){ .k2s-hardening-grid{ grid-template-columns: repeat(2,1fr); } }

.k2s-hardening-card {
    background: var(--k2-bg);
    border: 1px solid var(--k2-border);
    border-radius: 10px;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    transition: border-color .2s, box-shadow .2s;
}
.k2s-hardening-card--active {
    border-color: rgba(214,59,47,.3);
    background: #fff8f7;
    box-shadow: 0 2px 10px rgba(214,59,47,.08);
}
.k2s-hardening-card__top { display:flex; justify-content:space-between; align-items:flex-start; }
.k2s-hardening-card__icon { font-size:24px; }
.k2s-hardening-card__title { font-size:13px; font-weight:700; color:var(--k2-text); }
.k2s-hardening-card__desc { font-size:12px; color:var(--k2-muted); line-height:1.6; flex:1; }
.k2s-hardening-card__status { margin-top:4px; }

.k2s-badge--ok  { background:#f0fdf4; color:#166534; border:1px solid #86efac; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:700; font-family:var(--k2-mono); }
.k2s-badge--off { background:#f5f5f7; color:#6e6e82; border:1px solid #d0d0d8; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:700; font-family:var(--k2-mono); }

/* Remediation flow */
.k2s-remediation-info {
    display: flex;
    align-items: center;
    gap: 12px;
    background: var(--k2-bg);
    border: 1px solid var(--k2-border);
    border-radius: 10px;
    padding: 20px;
    margin-top: 4px;
}
.k2s-rem-step {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    flex: 1;
    font-size: 13px;
}
.k2s-rem-step span { font-size:11px; color:var(--k2-muted); }
.k2s-rem-step__num {
    width: 28px; height: 28px;
    background: var(--k2-gradient);
    color: white;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-weight: 800;
    font-size: 13px;
    flex-shrink: 0;
}
.k2s-rem-arrow { font-size:20px; color:var(--k2-muted); flex-shrink:0; }
</style>

<script>
jQuery(function($){
    // Toggle card active state visually
    $('.k2s-hardening-toggle').on('change', function(){
        var $card = $(this).closest('.k2s-hardening-card');
        var active = $(this).is(':checked');
        $card.toggleClass('k2s-hardening-card--active', active);
        $card.find('.k2s-hardening-card__status').html(
            active
            ? '<span class="k2s-badge k2s-badge--ok">ATTIVO</span>'
            : '<span class="k2s-badge k2s-badge--off">DISATTIVO</span>'
        );
    });

    // Save hardening
    $('#k2s-save-hardening').on('click', function(){
        var $btn = $(this);
        $btn.prop('disabled', true).text('Salvataggio…');

        var hardening = {};
        $('.k2s-hardening-toggle').each(function(){
            hardening[$(this).attr('name')] = $(this).is(':checked') ? 1 : 0;
        });

        // Salva anche auto-remediation
        var autoRem = $('#k2s-auto-remediation').is(':checked') ? 1 : 0;

        $.post(k2s_ajax.ajax_url, {
            action:    'k2s_save_hardening',
            nonce:     k2s_ajax.nonce,
            hardening: hardening,
        }, function(r){
            // Salva auto-remediation separatamente
            $.post(k2s_ajax.ajax_url, {
                action: 'k2s_save_option',
                nonce:  k2s_ajax.nonce,
                key:    'k2s_auto_remediation',
                value:  autoRem,
            });

            var $notice = $('#k2s-hardening-notice');
            if(r.success){
                $notice.removeClass('error').addClass('success')
                    .text('' + r.data.message).show();
            } else {
                $notice.removeClass('success').addClass('error')
                    .text('Errore nel salvataggio.').show();
            }
            setTimeout(function(){ $notice.fadeOut(); }, 4000);
        }).always(function(){ $btn.prop('disabled',false).text('Salva tutto'); });
    });
});
</script>
<?php
