<?php if ( ! defined( 'ABSPATH' ) ) exit;

if ( isset( $_POST['k2s_save_settings'] ) && check_admin_referer( 'k2s_settings_nonce' ) ) {
    update_option( 'k2s_email_alerts',    isset( $_POST['email_alerts'] ) ? 1 : 0 );
    update_option( 'k2s_alert_email',     sanitize_email( $_POST['alert_email'] ) );
    update_option( 'k2s_scan_depth',      intval( $_POST['scan_depth'] ) );
    update_option( 'k2s_definitions_url', esc_url_raw( $_POST['definitions_url'] ) );
    echo '<div class="k2s-notice success">Impostazioni salvate.</div>';
}

$email_alerts    = get_option( 'k2s_email_alerts', 0 );
$alert_email     = get_option( 'k2s_alert_email', get_option( 'admin_email' ) );
$scan_depth      = get_option( 'k2s_scan_depth', 3 );
$def_url         = get_option( 'k2s_definitions_url', K2S_DEFINITIONS_DEFAULT_URL );
$def_last_update = get_option( 'k2s_definitions_last_update', 0 );
$defs            = k2s_get_active_definitions();
$next_def_update = wp_next_scheduled( 'k2s_daily_definitions_update' );
?>
<div class="k2s-wrap">
    <div class="k2s-header">
        <div class="k2s-logo">Impostazioni</div>
    </div>

    <form method="post">
        <?php wp_nonce_field( 'k2s_settings_nonce' ); ?>

        <div class="k2s-section">
            <h2 class="k2s-section__title">Notifiche Email</h2>
            <div class="k2s-toggle-row">
                <label class="k2s-toggle">
                    <input type="checkbox" name="email_alerts" <?php checked( $email_alerts, 1 ); ?>>
                    <span class="k2s-toggle__slider"></span>
                </label>
                <span>Invia email quando vengono rilevate minacce</span>
            </div>
            <div class="k2s-form-row">
                <label>Email destinatario</label>
                <input type="email" name="alert_email" value="<?php echo esc_attr( $alert_email ); ?>" class="k2s-input">
            </div>
        </div>

        <div class="k2s-section">
            <h2 class="k2s-section__title">Scanner</h2>
            <div class="k2s-form-row">
                <label>Profondità scansione cartelle (livelli)</label>
                <select name="scan_depth" class="k2s-input k2s-input--sm">
                    <?php foreach ( [1,2,3,4,5] as $d ) : ?>
                        <option value="<?php echo $d; ?>" <?php selected( $scan_depth, $d ); ?>><?php echo $d; ?></option>
                    <?php endforeach; ?>
                </select>
                <small>Livello 3 consigliato. Più alto = più accurato ma più lento.</small>
            </div>
        </div>

        <!-- Definizioni -->
        <div class="k2s-section">
            <h2 class="k2s-section__title">Aggiornamento Definizioni</h2>

            <div class="k2s-def-grid">
                <div class="k2s-def-card">
                    <div class="k2s-def-card__label">Sorgente</div>
                    <div class="k2s-def-card__value <?php echo $defs['source'] === 'remote' ? 'ok' : 'warn'; ?>">
                        <?php echo $defs['source'] === 'remote' ? 'GitHub (remoto)' : 'Builtin (fallback)'; ?>
                    </div>
                </div>
                <div class="k2s-def-card">
                    <div class="k2s-def-card__label">Versione</div>
                    <div class="k2s-def-card__value"><?php echo esc_html( $defs['version'] ); ?></div>
                </div>
                <div class="k2s-def-card">
                    <div class="k2s-def-card__label">Ultimo aggiornamento</div>
                    <div class="k2s-def-card__value"><?php echo $def_last_update ? date_i18n( 'd/m/Y H:i', $def_last_update ) : 'Mai'; ?></div>
                </div>
                <div class="k2s-def-card">
                    <div class="k2s-def-card__label">Prossimo aggiornamento</div>
                    <div class="k2s-def-card__value"><?php echo $next_def_update ? date_i18n( 'd/m/Y H:i', $next_def_update ) : '—'; ?></div>
                </div>
                <div class="k2s-def-card">
                    <div class="k2s-def-card__label">Pattern PHP attivi</div>
                    <div class="k2s-def-card__value ok"><?php echo count( $defs['php_patterns'] ); ?></div>
                </div>
                <div class="k2s-def-card">
                    <div class="k2s-def-card__label">Pattern DB attivi</div>
                    <div class="k2s-def-card__value ok"><?php echo count( $defs['db_patterns'] ); ?></div>
                </div>
            </div>

            <div class="k2s-form-row" style="margin-top:16px">
                <label>URL file definizioni (GitHub raw JSON)</label>
                <input type="url" name="definitions_url"
                       value="<?php echo esc_attr( $def_url ); ?>"
                       class="k2s-input" style="max-width:100%">
                <small>Punta al tuo <code>definitions.json</code> su GitHub. Aggiornamento automatico ogni 24 ore.</small>
            </div>

            <div style="display:flex;align-items:center;gap:16px;margin-top:14px;">
                <button type="button" id="k2s-update-defs" class="k2s-btn">Aggiorna Ora</button>
                <span id="k2s-def-result" style="font-size:13px;font-family:var(--k2s-mono);"></span>
            </div>

            <div class="k2s-howto">
                <strong>Come configurare GitHub:</strong>
                <ol>
                    <li>Crea un repo pubblico GitHub (es. <code>k2-sentinel-definitions</code>)</li>
                    <li>Carica il file <code>definitions.json</code> incluso nel plugin nella root del repo</li>
                    <li>URL raw da usare: <code>https://raw.githubusercontent.com/TUO-USERNAME/k2-sentinel-definitions/main/definitions.json</code></li>
                    <li>Incollalo sopra e salva — il plugin si aggiorna da solo ogni 24 ore</li>
                    <li>Per aggiornare le definizioni: modifica il JSON su GitHub, bumpa il campo <code>"version"</code></li>
                </ol>
            </div>
        </div>


        <!-- Aggiornamento plugin da GitHub -->
        <div class="wps-section" style="border-left:3px solid var(--k2-blue,#1558A8);background:#f0f6ff;">
            <h2 class="k2s-section__title">Aggiornamento Plugin</h2>
            <div id="k2s-update-status" style="margin-bottom:16px;">
                <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;">
                    <div class="k2s-def-card">
                        <div class="k2s-def-card__label">Versione installata</div>
                        <div class="k2s-def-card__value"><?php echo K2_SENTINEL_VERSION; ?></div>
                    </div>
                    <div class="k2s-def-card">
                        <div class="k2s-def-card__label">Ultima versione GitHub</div>
                        <div class="k2s-def-card__value" id="k2s-latest-version">—</div>
                    </div>
                    <div class="k2s-def-card">
                        <div class="k2s-def-card__label">Stato</div>
                        <div class="k2s-def-card__value" id="k2s-update-state" style="font-size:13px;">Non verificato</div>
                    </div>
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <button type="button" id="k2s-check-update" class="k2s-btn k2s-btn--secondary">Controlla aggiornamenti</button>
                <a id="k2s-go-update" href="<?php echo admin_url('update-core.php'); ?>" class="k2s-btn" style="display:none;">Aggiorna ora</a>
                <span id="k2s-update-msg" style="font-size:12px;color:var(--k2-muted);font-family:var(--k2-mono);"></span>
            </div>
            <p style="font-size:12px;color:var(--k2-muted);margin:12px 0 0;">
                Gli aggiornamenti vengono scaricati direttamente da
                <a href="https://github.com/Avidsnake92/k2-sentinel/releases" target="_blank" style="color:var(--k2-red);">GitHub Releases</a>
                e installati tramite il sistema nativo di WordPress — nessuno ZIP manuale necessario.
            </p>
        </div>

<script>
jQuery(function($){
    $('#k2s-check-update').on('click', function(){
        var $btn = $(this);
        var $msg = $('#k2s-update-msg');
        $btn.prop('disabled', true).text('Controllo in corso…');
        $msg.text('');

        $.post(k2s_ajax.ajax_url, {
            action: 'k2s_force_update_check',
            nonce:  k2s_ajax.nonce
        }, function(r){
            if(r.success){
                var d = r.data;
                $('#k2s-latest-version').text(d.latest);
                if(d.has_update){
                    $('#k2s-update-state').css('color','var(--k2-red)').text('Aggiornamento disponibile');
                    $('#k2s-go-update').show();
                    $msg.text('Versione ' + d.latest + ' disponibile — clicca "Aggiorna ora"');
                } else {
                    $('#k2s-update-state').css('color','var(--k2-green)').text('Aggiornato');
                    $('#k2s-go-update').hide();
                    $msg.text('Sei già alla versione più recente.');
                }
            } else {
                $('#k2s-update-state').text('Errore controllo');
                $msg.text('Impossibile contattare GitHub. Riprova.');
            }
        }).always(function(){
            $btn.prop('disabled', false).text('Controlla aggiornamenti');
        });
    });
});
</script>

        <button type="submit" name="k2s_save_settings" class="k2s-btn k2s-btn--primary">Salva Impostazioni</button>
    </form>
</div>

<style>
.k2s-def-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;}
.k2s-def-card{background:var(--k2s-bg);border:1px solid var(--k2s-border);border-radius:6px;padding:12px 14px;}
.k2s-def-card__label{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--k2s-muted);margin-bottom:4px;}
.k2s-def-card__value{font-family:var(--k2s-mono);font-size:13px;font-weight:600;}
.k2s-def-card__value.ok{color:var(--k2s-green);}
.k2s-def-card__value.warn{color:var(--k2s-orange);}
.k2s-howto{margin-top:18px;background:var(--k2s-bg);border:1px solid var(--k2s-border);border-left:3px solid var(--k2s-blue);border-radius:6px;padding:14px 18px;font-size:13px;line-height:1.9;}
.k2s-howto ol{margin:8px 0 0 16px;padding:0;}
</style>

<script>
jQuery(function($){
    $('#k2s-update-defs').on('click',function(){
        var $btn=$(this),$res=$('#k2s-def-result');
        $btn.prop('disabled',true).text('Aggiornamento…');
        $res.text('');
        $.post(k2s_ajax.ajax_url,{action:'k2s_update_definitions',nonce:k2s_ajax.nonce},function(r){
            if(r.status==='ok'){
                $res.css('color','var(--k2s-green)').text('Aggiornato v'+r.version+' ('+r.date+') — '+r.php_patterns+' pattern PHP, '+r.db_patterns+' pattern DB');
            }else if(r.status==='cached'){
                $res.css('color','var(--k2s-orange)').text(r.message);
            }else{
                $res.css('color','var(--k2s-red)').text('Errore: '+r.message);
            }
        }).always(function(){$btn.prop('disabled',false).text('Aggiorna Ora');});
    });
});
</script>
