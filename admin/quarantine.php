<?php if ( ! defined( 'ABSPATH' ) ) exit;

$quarantine_files = k2s_get_quarantine_files();
$db_backups       = k2s_get_db_backups( 30 );
?>
<div class="k2s-wrap">
    <div class="k2s-header">
        <div class="k2s-logo">
            <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
            <div class="k2s-logo__text">
                <span class="k2s-logo__name">Quarantena</span>
                <span class="k2s-logo__sub">File isolati e backup DB</span>
            </div>
        </div>
        <div style="display:flex;gap:10px;align-items:center;">
            <span style="font-size:13px;color:var(--k2-muted);">
                <?php echo count( $quarantine_files ); ?> file · <?php echo count( $db_backups ); ?> backup DB
            </span>
        </div>
    </div>

    <div id="k2s-quarantine-notice" style="display:none;" class="k2s-notice success"></div>

    <!-- File in quarantena -->
    <div class="k2s-section">
        <h2 class="k2s-section__title">File in Quarantena</h2>

        <?php if ( empty( $quarantine_files ) ) : ?>
            <p class="k2s-empty">Nessun file in quarantena. </p>
        <?php else : ?>
            <p style="font-size:12px;color:var(--k2-muted);margin:0 0 16px;">
                I file sono stati spostati in <code>wp-content/k2s-quarantine/</code> e non sono accessibili dal web.
                Puoi ripristinarli nella posizione originale o eliminarli definitivamente.
            </p>
            <table class="k2s-table">
                <thead>
                    <tr>
                        <th>Data quarantena</th>
                        <th>File originale</th>
                        <th>Tipo minaccia</th>
                        <th>Dimensione</th>
                        <th>Azioni</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ( $quarantine_files as $qf ) : ?>
                    <tr>
                        <td><?php echo esc_html( date_i18n( 'd/m/Y H:i', strtotime( $qf['quarantined_at'] ) ) ); ?></td>
                        <td>
                            <code style="font-size:11px;"><?php echo esc_html( $qf['original_path'] ); ?></code>
                            <div style="font-size:11px;color:var(--k2-muted);margin-top:3px;"><?php echo esc_html( $qf['threat_detail'] ); ?></div>
                        </td>
                        <td><span class="k2s-badge k2s-badge--critical"><?php echo esc_html( $qf['threat_type'] ); ?></span></td>
                        <td><?php echo esc_html( size_format( $qf['size'] ) ); ?></td>
                        <td style="white-space:nowrap;">
                            <button class="k2s-btn k2s-btn--sm k2s-restore-file"
                                    data-filename="<?php echo esc_attr( $qf['filename'] ); ?>">
                                Ripristina
                            </button>
                            <button class="k2s-btn k2s-btn--sm k2s-btn--danger k2s-delete-file"
                                    data-filename="<?php echo esc_attr( $qf['filename'] ); ?>"
                                    style="margin-left:6px;">
                                Elimina
                            </button>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Backup DB -->
    <div class="k2s-section">
        <h2 class="k2s-section__title">Backup Record Database</h2>

        <?php if ( empty( $db_backups ) ) : ?>
            <p class="k2s-empty">Nessun backup DB presente. I record vengono salvati automaticamente prima di ogni pulizia.</p>
        <?php else : ?>
            <p style="font-size:12px;color:var(--k2-muted);margin:0 0 16px;">
                Backup automatici dei record puliti dalla bonifica. Utili per ripristinare dati in caso di falso positivo.
            </p>
            <table class="k2s-table">
                <thead>
                    <tr>
                        <th>Data</th>
                        <th>Tabella / Colonna</th>
                        <th>PK</th>
                        <th>Pattern</th>
                        <th>Valore originale</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ( $db_backups as $bk ) : ?>
                    <tr>
                        <td><?php echo esc_html( date_i18n( 'd/m/Y H:i', strtotime( $bk->backup_time ) ) ); ?></td>
                        <td><code><?php echo esc_html( $bk->source_table . '.' . $bk->source_column ); ?></code></td>
                        <td><?php echo esc_html( $bk->source_pk ); ?></td>
                        <td><span class="k2s-badge k2s-badge--warning"><?php echo esc_html( $bk->pattern_key ); ?></span></td>
                        <td>
                            <details>
                                <summary style="cursor:pointer;font-size:11px;color:var(--k2-muted);">Mostra valore</summary>
                                <pre style="font-size:10px;max-height:80px;overflow:auto;margin:4px 0 0;background:var(--k2-bg);padding:6px;border-radius:4px;"><?php echo esc_html( mb_substr( $bk->original_value, 0, 500 ) ); ?><?php echo strlen( $bk->original_value ) > 500 ? '…' : ''; ?></pre>
                            </details>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <div class="k2s-footer">
        <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
        K2 Sentinel è un prodotto K2Tech
    </div>
</div>

<script>
jQuery(function($){
    function notify(msg, type){
        var $n = $('#k2s-quarantine-notice');
        $n.removeClass('success error').addClass(type).text(msg).show();
        setTimeout(function(){ $n.fadeOut(); }, 5000);
    }

    // Ripristina file
    $(document).on('click', '.k2s-restore-file', function(){
        var $btn = $(this);
        var filename = $btn.data('filename');
        if(!confirm('Ripristinare il file nella posizione originale?\nAttenzione: se era infetto potrebbe reinfettare il sito.')) return;

        $btn.prop('disabled',true).text('…');
        $.post(k2s_ajax.ajax_url, {
            action:   'k2s_restore_quarantine',
            nonce:    k2s_ajax.nonce,
            filename: filename,
        }, function(r){
            if(r.success){
                notify('File ripristinato in: ' + r.data.restored_to, 'success');
                $btn.closest('tr').fadeOut(400, function(){ $(this).remove(); });
            } else {
                notify('' + (r.data || 'Errore'), 'error');
                $btn.prop('disabled',false).text('Ripristina');
            }
        });
    });

    // Elimina file
    $(document).on('click', '.k2s-delete-file', function(){
        var $btn = $(this);
        var filename = $btn.data('filename');
        if(!confirm('Eliminare definitivamente il file? Questa azione non è reversibile.')) return;

        $btn.prop('disabled',true).text('…');
        $.post(k2s_ajax.ajax_url, {
            action:   'k2s_delete_quarantine',
            nonce:    k2s_ajax.nonce,
            filename: filename,
        }, function(r){
            if(r.success){
                notify('File eliminato definitivamente.', 'success');
                $btn.closest('tr').fadeOut(400, function(){ $(this).remove(); });
            } else {
                notify('Errore eliminazione.', 'error');
                $btn.prop('disabled',false).text('Elimina');
            }
        });
    });
});
</script>
