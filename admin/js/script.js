/* K2 Sentinel – Admin JS */
(function ($) {
    'use strict';

    // ── Scan manuale ─────────────────────────────────────────────
    $('#k2s-scan-now').on('click', function () {
        var $btn      = $(this);
        var $progress = $('#k2s-scan-progress');
        var $result   = $('#k2s-scan-result');

        $btn.prop('disabled', true).text('Scansione in corso…');
        $progress.show();
        $result.hide().removeClass('ok threats');

        $.ajax({
            url:  k2s_ajax.ajax_url,
            type: 'POST',
            data: { action: 'k2s_manual_scan', nonce: k2s_ajax.nonce },
            success: function (res) {
                if ( res.success ) {
                    var d       = res.data;
                    var threats = parseInt( d.threats, 10 );
                    var html;

                    if ( threats === 0 ) {
                        $result.addClass('ok');
                        html = 'Scansione completata — nessuna minaccia rilevata.\n';
                        html += 'Ora: ' + d.last_scan;
                    } else {
                        $result.addClass('threats');
                        html = 'Scansione completata — ' + threats + ' minaccia/e rilevata/e.\n';
                        html += 'Ora: ' + d.last_scan + '\n\n';
                        $.each( d.log, function (i, log) {
                            html += '[' + log.level.toUpperCase() + '] ' + log.type + ' — ' + log.detail + '\n';
                        });
                    }

                    $result.html( '<pre style="margin:0;white-space:pre-wrap;">' + html + '</pre>' ).show();
                } else {
                    $result.addClass('threats').html('Errore durante la scansione.').show();
                }
            },
            error: function () {
                $result.addClass('threats').html('Errore di connessione.').show();
            },
            complete: function () {
                $progress.hide();
                $btn.prop('disabled', false).html(
                    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Avvia ora'
                );
            },
        });
    });

    // ── Aggiornamento definizioni ─────────────────────────────────
    $('#k2s-update-defs').on('click', function () {
        var $btn = $(this);
        var $res = $('#k2s-def-result');
        $btn.prop('disabled', true).text('Aggiornamento…');
        $res.text('').css('color','');

        $.post(k2s_ajax.ajax_url, {
            action: 'k2s_update_definitions',
            nonce:  k2s_ajax.nonce
        }, function (r) {
            if ( r.status === 'ok' ) {
                $res.css('color','var(--k2-green)').text(
                    'Aggiornato v' + r.version + ' (' + r.date + ') — ' +
                    r.php_patterns + ' pattern PHP, ' + r.db_patterns + ' pattern DB'
                );
            } else if ( r.status === 'cached' ) {
                $res.css('color','var(--k2-amber)').text( r.message );
            } else {
                $res.css('color','var(--k2-red)').text( 'Errore: ' + r.message );
            }
        }).always(function () {
            $btn.prop('disabled', false).text('Aggiorna ora');
        });
    });

})(jQuery);
