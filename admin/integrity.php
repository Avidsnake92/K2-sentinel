<?php if ( ! defined( 'ABSPATH' ) ) exit;
$last = get_option( 'k2s_core_integrity_last', [] );
$wp_version = get_bloginfo( 'version' );
?>
<div class="k2s-wrap">
    <div class="k2s-header">
        <div class="k2s-logo">
            <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
            <div class="k2s-logo__text">
                <span class="k2s-logo__name">Integrità Core</span>
                <span class="k2s-logo__sub">Confronto con wordpress.org</span>
            </div>
        </div>
        <button id="k2s-check-core" class="k2s-btn">Verifica ora</button>
    </div>

    <div id="k2s-core-notice" style="display:none" class="k2s-notice"></div>

    <!-- Stato -->
    <div class="k2s-grid-3" style="margin-bottom:20px;">
        <div class="k2s-card">
            <div class="k2s-card__icon">🗂️</div>
            <div class="k2s-card__label">Versione WP</div>
            <div class="k2s-card__value"><?php echo esc_html( $wp_version ); ?></div>
        </div>
        <div class="k2s-card">
            <div class="k2s-card__icon"></div>
            <div class="k2s-card__label">File controllati</div>
            <div class="k2s-card__value" id="core-checked"><?php echo esc_html( $last['checked'] ?? '—' ); ?></div>
        </div>
        <div class="k2s-card <?php echo ( ($last['threats'] ?? 0) > 0 ) ? 'k2s-card--danger' : ( $last ? 'k2s-card--safe' : '' ); ?>">
            <div class="k2s-card__icon"><?php echo ( ($last['threats'] ?? 0) > 0 ) ? '' : ( $last ? '' : '❓'); ?></div>
            <div class="k2s-card__label">Anomalie trovate</div>
            <div class="k2s-card__value" id="core-threats"><?php echo esc_html( $last['threats'] ?? '—' ); ?></div>
        </div>
    </div>

    <div class="k2s-section">
        <h2 class="k2s-section__title">Come funziona</h2>
        <p style="font-size:13px;line-height:1.8;margin:0;">
            Il sistema scarica i checksum MD5 ufficiali da <code>api.wordpress.org/core/checksums</code>
            per la versione WP <strong><?php echo esc_html( $wp_version ); ?></strong> e confronta
            ogni file core installato. Qualsiasi file modificato, aggiunto o mancante rispetto
            all'installazione originale viene segnalato. La verifica esclude <code>wp-content</code>
            e <code>wp-config.php</code>.
        </p>
    </div>

    <div class="k2s-section">
        <h2 class="k2s-section__title">Risultati ultima verifica
            <span style="font-weight:400;font-size:11px;margin-left:8px;">
                <?php echo $last ? esc_html( $last['time'] ) : 'Mai eseguita'; ?>
            </span>
        </h2>

        <div id="k2s-core-results">
            <?php if ( empty( $last ) ) : ?>
                <p class="k2s-empty">Nessuna verifica eseguita. Clicca "Verifica ora" per iniziare.</p>
            <?php elseif ( $last['threats'] === 0 ) : ?>
                <p style="color:#1a8a3a;font-size:14px;font-weight:600;">
                    Tutti i <?php echo $last['checked']; ?> file core sono integri.
                </p>
            <?php else : ?>
                <p style="color:#D63B2F;font-size:14px;font-weight:600;">
                    <?php echo $last['threats']; ?> anomalie trovate su <?php echo $last['checked']; ?> file.
                    (<strong><?php echo $last['modified']; ?></strong> modificati,
                    <strong><?php echo $last['extra']; ?></strong> file extra nelle cartelle core)
                </p>
                <p style="font-size:13px;color:var(--k2-muted);">Clicca "Verifica ora" per vedere i dettagli aggiornati.</p>
            <?php endif; ?>
            <div id="k2s-core-detail-list"></div>
        </div>
    </div>

    <div class="k2s-footer">
        <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
        K2 Sentinel è un prodotto K2Tech
    </div>
</div>

<script>
jQuery(function($){
    $('#k2s-check-core').on('click', function(){
        var $btn=$(this);
        $btn.prop('disabled',true).text('Verifica in corso…');
        $('#k2s-core-notice').hide();
        $('#k2s-core-detail-list').html('');

        $.post(k2s_ajax.ajax_url,{action:'k2s_check_core',nonce:k2s_ajax.nonce},function(r){
            $btn.prop('disabled',false).text('Verifica ora');
            if(!r.success){ $('#k2s-core-notice').removeClass('success').addClass('error k2s-notice').text('Errore nella verifica.').show(); return; }
            var d=r.data;
            $('#core-checked').text(d.summary.checked||'—');
            $('#core-threats').text(d.threats);

            var $notice=$('#k2s-core-notice');
            if(d.threats===0){
                $notice.removeClass('error').addClass('success k2s-notice').text('Tutti i file core sono integri.').show();
            } else {
                $notice.removeClass('success').addClass('error k2s-notice').text(''+d.threats+' anomalie rilevate!').show();
                var html='<ul style="margin:12px 0;font-size:12px;font-family:monospace;line-height:1.8;">';
                $.each(d.details, function(i,det){ html+='<li>'+det+'</li>'; });
                html+='</ul>';
                $('#k2s-core-detail-list').html(html);
            }
        });
    });
});
</script>
