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

    // ── Bonifica manuale ──────────────────────────────────────────
    $(document).on('click', '#k2s-remediate-now', function () {
        var $btn = $(this);
        var $res = $('#k2s-remediate-result');
        $btn.prop('disabled', true).text('Bonifica in corso…');
        $res.hide().removeClass('ok threats');

        $.ajax({
            url:  k2s_ajax.ajax_url,
            type: 'POST',
            data: { action: 'k2s_manual_remediate', nonce: k2s_ajax.nonce },
            success: function (res) {
                if ( res.success ) {
                    var d = res.data;
                    if ( d.total === 0 && d.processed === 0 ) {
                        $res.addClass('ok').html(
                            '<pre style="margin:0;">' + (d.message || 'Nessuna minaccia bonificabile nel log.') + '\n' +
                            (d.hint ? d.hint : 'Avvia una scansione manuale per rilevare nuove minacce.') + '</pre>'
                        ).show();
                    } else {
                        var html = 'Minacce processate  : ' + (d.processed || 0) + '\n';
                        html    += 'File in quarantena  : ' + d.quarantined + '\n';
                        html    += 'Record DB puliti    : ' + d.db_cleaned + '\n';
                        if ( d.skipped > 0 ) html += 'Saltati (info-only) : ' + d.skipped + '\n';
                        if ( d.failed > 0 ) {
                            html += 'Falliti             : ' + d.failed + '\n';
                            if ( d.failed_details && d.failed_details.length ) {
                                html += '\nDettaglio falliti:\n';
                                $.each( d.failed_details, function(i, det) {
                                    html += '  • ' + det + '\n';
                                });
                            }
                        }
                        $res.addClass( d.failed > 0 && d.total === 0 ? 'threats' : 'ok' )
                            .html( '<pre style="margin:0;">' + html + '</pre>' ).show();
                    }
                } else {
                    $res.addClass('threats').html('<pre style="margin:0;">Errore durante la bonifica. Controlla i log.</pre>').show();
                }
            },
            error: function (xhr) {
                $res.addClass('threats').html(
                    '<pre style="margin:0;">Errore di connessione: ' + xhr.status + ' ' + xhr.statusText + '</pre>'
                ).show();
            },
            complete: function () {
                $btn.prop('disabled', false).text('Bonifica ora');
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

    // ── Debug pattern DB ─────────────────────────────────────────
    $(document).on('click', '#k2s-debug-remediate', function () {
        var $res = $('#k2s-remediate-result');
        $res.hide().removeClass('ok threats');

        var patterns = ['spam_keyword','long_b64_in_db','courtesy_page','hidden_link','iframe_inject'];
        var results  = '';
        var done     = 0;

        $.each(patterns, function(i, pk) {
            $.post(k2s_ajax.ajax_url, {
                action:      'k2s_debug_remediate',
                nonce:       k2s_ajax.nonce,
                pattern_key: pk,
            }, function(r) {
                done++;
                if (r.success) {
                    var d = r.data;
                    results += '[' + pk + ']
';
                    results += '  Regex valido  : ' + (d.regex_valid ? 'SI' : 'NO') + '
';
                    results += '  Righe totali  : ' + d.total_rows + '
';
                    results += '  Match trovati : ' + d.matches_found + '
';
                    if (d.matches_found > 0) {
                        $.each(d.matches, function(j, m) {
                            results += '  → PK=' + m.pk + ' | ' + m.preview.substr(0,60) + '...
';
                        });
                    }
                    results += '
';
                } else {
                    results += '[' + pk + '] ERRORE: ' + (r.data || 'sconosciuto') + '

';
                }
                if (done === patterns.length) {
                    $res.addClass('ok').html('<pre style="margin:0;font-size:11px;">' + results + '</pre>').show();
                }
            });
        });
    });

})(jQuery);
