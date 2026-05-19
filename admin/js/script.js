/* K2 Sentinel – Admin JS v1.3.0 */
(function ($) {
    'use strict';

    // ── Scan manuale ─────────────────────────────────────────────
    $(document).on('click', '#k2s-scan-now', function () {
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
                    var lines   = [];

                    if ( threats === 0 ) {
                        $result.addClass('ok');
                        lines.push('Scansione completata — nessuna minaccia rilevata.');
                        lines.push('Ora: ' + d.last_scan);
                    } else {
                        $result.addClass('threats');
                        lines.push('Scansione completata — ' + threats + ' minaccia/e rilevata/e.');
                        lines.push('Ora: ' + d.last_scan);
                        lines.push('');
                        $.each( d.log, function (i, log) {
                            lines.push('[' + log.level.toUpperCase() + '] ' + log.type + ' — ' + log.detail);
                        });
                    }

                    $result.html('<pre style="margin:0;white-space:pre-wrap;">' + lines.join('\n') + '</pre>').show();
                } else {
                    $result.addClass('threats').html('<pre style="margin:0;">Errore durante la scansione.</pre>').show();
                }
            },
            error: function (xhr) {
                $result.addClass('threats').html('<pre style="margin:0;">Errore: ' + xhr.status + ' ' + xhr.statusText + '</pre>').show();
            },
            complete: function () {
                $progress.hide();
                $btn.prop('disabled', false).text('Avvia ora');
            }
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
                    var d     = res.data;
                    var lines = [];

                    if ( d.total === 0 && d.processed === 0 ) {
                        lines.push(d.message || 'Nessuna minaccia bonificabile nel log.');
                        lines.push('Avvia una scansione manuale per aggiornare il log.');
                        $res.addClass('ok');
                    } else {
                        lines.push('Minacce processate  : ' + (d.processed || 0));
                        lines.push('File in quarantena  : ' + d.quarantined);
                        lines.push('Record DB puliti    : ' + d.db_cleaned);
                        if ( d.skipped > 0 ) { lines.push('Saltati (info-only) : ' + d.skipped); }
                        if ( d.failed > 0 ) {
                            lines.push('Falliti             : ' + d.failed);
                            if ( d.failed_details && d.failed_details.length ) {
                                lines.push('');
                                lines.push('Dettaglio falliti:');
                                $.each(d.failed_details, function(i, det) {
                                    lines.push('  • ' + det);
                                });
                            }
                        }
                        $res.addClass( (d.failed > 0 && d.total === 0) ? 'threats' : 'ok' );
                    }

                    $res.html('<pre style="margin:0;white-space:pre-wrap;">' + lines.join('\n') + '</pre>').show();
                } else {
                    $res.addClass('threats').html('<pre style="margin:0;">Errore durante la bonifica.</pre>').show();
                }
            },
            error: function (xhr) {
                $res.addClass('threats').html('<pre style="margin:0;">Errore: ' + xhr.status + ' ' + xhr.statusText + '</pre>').show();
            },
            complete: function () {
                $btn.prop('disabled', false).text('Bonifica ora');
            }
        });
    });

    // ── Aggiornamento definizioni ─────────────────────────────────
    $(document).on('click', '#k2s-update-defs', function () {
        var $btn = $(this);
        var $res = $('#k2s-def-result');

        $btn.prop('disabled', true).text('Aggiornamento…');
        $res.text('').css('color', '');

        $.post(k2s_ajax.ajax_url, { action: 'k2s_update_definitions', nonce: k2s_ajax.nonce },
        function (r) {
            if ( r.status === 'ok' ) {
                $res.css('color', 'var(--k2-green)').text('Aggiornato v' + r.version + ' (' + r.date + ') — ' + r.php_patterns + ' PHP, ' + r.db_patterns + ' DB');
            } else if ( r.status === 'cached' ) {
                $res.css('color', 'var(--k2-amber)').text(r.message);
            } else {
                $res.css('color', 'var(--k2-red)').text('Errore: ' + r.message);
            }
        }).always(function () {
            $btn.prop('disabled', false).text('Aggiorna ora');
        });
    });

    // ── Controlla aggiornamenti GitHub ────────────────────────────
    $(document).on('click', '#k2s-check-update', function () {
        var $btn = $(this);
        var $msg = $('#k2s-update-msg');

        $btn.prop('disabled', true).text('Controllo in corso…');
        $msg.text('');

        $.post(k2s_ajax.ajax_url, { action: 'k2s_force_update_check', nonce: k2s_ajax.nonce },
        function (r) {
            if ( r.success ) {
                var d = r.data;
                $('#k2s-latest-version').text(d.latest);
                if ( d.has_update ) {
                    $('#k2s-update-state').css('color', 'var(--k2-red)').text('Aggiornamento disponibile');
                    $('#k2s-go-update').show();
                    $msg.text('Versione ' + d.latest + ' disponibile.');
                } else {
                    $('#k2s-update-state').css('color', 'var(--k2-green)').text('Aggiornato');
                    $('#k2s-go-update').hide();
                    $msg.text('Sei già alla versione più recente.');
                }
            } else {
                $('#k2s-update-state').text('Errore');
                $msg.text('Impossibile contattare GitHub.');
            }
        }).always(function () {
            $btn.prop('disabled', false).text('Controlla aggiornamenti');
        });
    });

    // ── Hardening — salva impostazioni ───────────────────────────
    $(document).on('click', '#k2s-save-hardening', function () {
        var $btn    = $(this);
        var $notice = $('#k2s-hardening-notice');
        var hardening = {};

        $btn.prop('disabled', true).text('Salvataggio…');

        $('.k2s-hardening-toggle').each(function () {
            hardening[$(this).attr('name')] = $(this).is(':checked') ? 1 : 0;
        });

        var autoRem = $('#k2s-auto-remediation').is(':checked') ? 1 : 0;

        $.post(k2s_ajax.ajax_url, { action: 'k2s_save_hardening', nonce: k2s_ajax.nonce, hardening: hardening },
        function (r) {
            $.post(k2s_ajax.ajax_url, { action: 'k2s_save_option', nonce: k2s_ajax.nonce, key: 'k2s_auto_remediation', value: autoRem });

            $notice.removeClass('error').addClass('success k2s-notice')
                   .text(r.success ? (r.data.message || 'Impostazioni salvate.') : 'Errore nel salvataggio.')
                   .show();
            setTimeout(function () { $notice.fadeOut(); }, 4000);
        }).always(function () {
            $btn.prop('disabled', false).text('Salva tutto');
        });
    });

    // ── Hardening — toggle card highlight ────────────────────────
    $(document).on('change', '.k2s-hardening-toggle', function () {
        var $card  = $(this).closest('.k2s-hardening-card');
        var active = $(this).is(':checked');
        $card.toggleClass('k2s-hardening-card--active', active);
        $card.find('.k2s-hardening-card__status').html(
            active
            ? '<span class="k2s-badge k2s-badge--ok">ATTIVO</span>'
            : '<span class="k2s-badge k2s-badge--off">DISATTIVO</span>'
        );
    });

    // ── Traffic Monitor ───────────────────────────────────────────
    $(document).on('click', '#k2s-traffic-refresh, #k2s-apply-filter', function () {
        k2s_load_traffic();
    });

    $(document).on('click', '#k2s-traffic-clear', function () {
        if ( ! confirm('Svuotare tutti i dati di traffico?') ) return;
        $.post(k2s_ajax.ajax_url, { action: 'k2s_clear_traffic', nonce: k2s_ajax.nonce },
        function () { k2s_load_traffic(); });
    });

    $(document).on('change', '#k2s-traffic-toggle', function () {
        $.post(k2s_ajax.ajax_url, { action: 'k2s_save_option', nonce: k2s_ajax.nonce, key: 'k2s_traffic_monitor_enabled', value: this.checked ? 1 : 0 });
    });

    function k2s_load_traffic() {
        var $body = $('#k2s-traffic-body');
        $('#k2s-traffic-loading').show();

        $.post(k2s_ajax.ajax_url, {
            action:      'k2s_get_traffic',
            nonce:       k2s_ajax.nonce,
            threat_only: $('#k2s-threat-only').is(':checked') ? 1 : 0,
            filter_ip:   $('#k2s-filter-ip').val()
        }, function (r) {
            $('#k2s-traffic-loading').hide();
            if ( ! r.success || ! r.data.rows.length ) {
                $body.html('<tr><td colspan="6" style="text-align:center;color:var(--k2-muted);padding:20px;">Nessuna richiesta trovata.</td></tr>');
                return;
            }
            var html = '';
            $.each(r.data.rows, function (i, row) {
                var rc = row.blocked == 1 ? 'k2s-row--critical' : (row.threat ? 'k2s-row--warning' : '');
                var threat_badge = row.blocked == 1
                    ? '<span class="k2s-badge k2s-badge--critical">BLOCCATO</span>'
                    : (row.threat ? '<span class="k2s-badge k2s-badge--warning">' + row.threat + '</span>' : '');
                html += '<tr class="' + rc + '">';
                html += '<td style="white-space:nowrap;font-family:monospace;font-size:11px;">' + row.req_time.slice(11,19) + '</td>';
                html += '<td><code>' + row.ip + '</code> ' + threat_badge + '</td>';
                html += '<td style="font-family:monospace;font-size:11px;">' + row.method + '</td>';
                html += '<td style="font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + row.uri + '">' + row.uri + '</td>';
                html += '<td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--k2-muted);">' + row.user_agent + '</td>';
                html += '<td style="font-weight:700;font-family:monospace;">' + row.status + '</td>';
                html += '</tr>';
            });
            $body.html(html);
            if ( r.data.stats ) {
                $('#stat-total').text(r.data.stats.total_24h);
                $('#stat-blocked').text(r.data.stats.blocked_24h);
                $('#stat-threats').text(r.data.stats.threats_24h);
            }
        });
    }

    // ── Core Integrity check ──────────────────────────────────────
    $(document).on('click', '#k2s-check-core', function () {
        var $btn = $(this);
        var $res = $('#k2s-core-detail-list');

        $btn.prop('disabled', true).text('Verifica in corso…');
        $('#k2s-core-notice').hide();
        $res.html('');

        $.post(k2s_ajax.ajax_url, { action: 'k2s_check_core', nonce: k2s_ajax.nonce },
        function (r) {
            $btn.prop('disabled', false).text('Verifica ora');
            if ( ! r.success ) {
                $('#k2s-core-notice').removeClass('success').addClass('error k2s-notice').text('Errore nella verifica.').show();
                return;
            }
            var d = r.data;
            $('#core-checked').text(d.summary.checked || '—');
            $('#core-threats').text(d.threats);
            var $notice = $('#k2s-core-notice');

            if ( d.threats === 0 ) {
                $notice.removeClass('error').addClass('success k2s-notice').text('Tutti i file core sono integri.').show();
            } else {
                $notice.removeClass('success').addClass('error k2s-notice').text(d.threats + ' anomalie rilevate.').show();
                var html = '<ul style="margin:12px 0;font-size:12px;font-family:monospace;line-height:1.8;">';
                $.each(d.details, function (i, det) { html += '<li>' + det + '</li>'; });
                html += '</ul>';
                $res.html(html);
            }
        });
    });

})(jQuery);
