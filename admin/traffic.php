<?php if ( ! defined( 'ABSPATH' ) ) exit;
$stats   = k2s_get_traffic_stats();
$enabled = get_option( 'k2s_traffic_monitor_enabled', 0 );
?>
<div class="k2s-wrap">
    <div class="k2s-header">
        <div class="k2s-logo">
            <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
            <div class="k2s-logo__text">
                <span class="k2s-logo__name">Traffic Monitor</span>
                <span class="k2s-logo__sub">Richieste in tempo reale</span>
            </div>
        </div>
        <div style="display:flex;gap:10px;align-items:center;">
            <label style="display:flex;align-items:center;gap:8px;font-size:13px;">
                <span class="k2s-toggle">
                    <input type="checkbox" id="k2s-traffic-toggle" <?php checked( $enabled, 1 ); ?>>
                    <span class="k2s-toggle__slider"></span>
                </span>
                Monitor attivo
            </label>
            <button id="k2s-traffic-refresh" class="k2s-btn">Aggiorna</button>
            <button id="k2s-traffic-clear" class="k2s-btn k2s-btn--danger k2s-btn--sm">Svuota</button>
        </div>
    </div>

    <!-- Stats -->
    <div class="k2s-grid-3" style="margin-bottom:20px;">
        <div class="k2s-card">
            <div class="k2s-card__icon">📊</div>
            <div class="k2s-card__label">Richieste 24h</div>
            <div class="k2s-card__value" id="stat-total"><?php echo $stats['total_24h'] ?? 0; ?></div>
        </div>
        <div class="k2s-card k2s-card--danger">
            <div class="k2s-card__icon">🚫</div>
            <div class="k2s-card__label">Bloccate 24h</div>
            <div class="k2s-card__value" id="stat-blocked"><?php echo $stats['blocked_24h'] ?? 0; ?></div>
        </div>
        <div class="k2s-card">
            <div class="k2s-card__icon"></div>
            <div class="k2s-card__label">Minacce 24h</div>
            <div class="k2s-card__value" id="stat-threats"><?php echo $stats['threats_24h'] ?? 0; ?></div>
        </div>
    </div>

    <!-- Filtri -->
    <div class="k2s-section" style="padding:14px 20px;">
        <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
            <input type="text" id="k2s-filter-ip" class="k2s-input k2s-input--sm" placeholder="Filtra per IP" style="max-width:160px;">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;">
                <input type="checkbox" id="k2s-threat-only"> Solo minacce
            </label>
            <button id="k2s-apply-filter" class="k2s-btn k2s-btn--sm">Applica filtro</button>
        </div>
    </div>

    <!-- Tabella traffico -->
    <div class="k2s-section">
        <h2 class="k2s-section__title">Ultime richieste</h2>
        <div id="k2s-traffic-loading" style="display:none;padding:20px;text-align:center;color:var(--k2-muted);font-size:13px;">
            Caricamento…
        </div>
        <div id="k2s-traffic-table-wrap">
            <table class="k2s-table" id="k2s-traffic-table">
                <thead>
                    <tr>
                        <th>Ora</th>
                        <th>IP</th>
                        <th>Metodo</th>
                        <th>URI</th>
                        <th>User Agent</th>
                        <th>Stato</th>
                    </tr>
                </thead>
                <tbody id="k2s-traffic-body">
                    <tr><td colspan="6" style="text-align:center;color:var(--k2-muted);padding:20px;">
                        <?php echo $enabled ? 'Clicca Aggiorna per caricare i dati.' : 'Abilita il monitor per registrare il traffico.'; ?>
                    </td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="k2s-footer">
        <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
        K2 Sentinel è un prodotto K2Tech
    </div>
</div>

<script>
jQuery(function($){
    function methodBadge(m){ var c=m==='GET'?'#1a6fc4':m==='POST'?'#D63B2F':'#888780'; return '<span style="background:'+c+'20;color:'+c+';padding:1px 7px;border-radius:3px;font-size:10px;font-weight:700;font-family:monospace;">'+m+'</span>'; }
    function statusBadge(s){ var c=s<300?'#1a8a3a':s<400?'#1a6fc4':s<500?'#D63B2F':'#8b1a14'; return '<span style="color:'+c+';font-weight:700;font-family:monospace;">'+s+'</span>'; }
    function threatBadge(t,b){ if(b==1||b==='1') return '<span class="k2s-badge k2s-badge--critical">BLOCCATO</span>'; if(t) return '<span class="k2s-badge k2s-badge--warning">'+t+'</span>'; return ''; }

    function loadTraffic(){
        var $body=$('#k2s-traffic-body');
        $('#k2s-traffic-loading').show();
        $.post(k2s_ajax.ajax_url,{
            action:'k2s_get_traffic',nonce:k2s_ajax.nonce,
            threat_only:$('#k2s-threat-only').is(':checked')?1:0,
            filter_ip:$('#k2s-filter-ip').val()
        },function(r){
            $('#k2s-traffic-loading').hide();
            if(!r.success||!r.data.rows.length){ $body.html('<tr><td colspan="6" style="text-align:center;color:var(--k2-muted);padding:20px;">Nessuna richiesta trovata.</td></tr>'); return; }
            var html='';
            $.each(r.data.rows,function(i,row){
                var rowClass=row.blocked==1?'k2s-row--critical':row.threat?'k2s-row--warning':'';
                html+='<tr class="'+rowClass+'">';
                html+='<td style="white-space:nowrap;font-family:monospace;font-size:11px;">'+row.req_time.slice(11,19)+'</td>';
                html+='<td><code>'+row.ip+'</code> '+threatBadge(row.threat,row.blocked)+'</td>';
                html+='<td>'+methodBadge(row.method)+'</td>';
                html+='<td style="font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="'+row.uri+'">'+row.uri+'</td>';
                html+='<td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--k2-muted);" title="'+row.user_agent+'">'+row.user_agent+'</td>';
                html+='<td>'+statusBadge(row.status)+'</td>';
                html+='</tr>';
            });
            $body.html(html);
            // Aggiorna stats
            if(r.data.stats){ $('#stat-total').text(r.data.stats.total_24h); $('#stat-blocked').text(r.data.stats.blocked_24h); $('#stat-threats').text(r.data.stats.threats_24h); }
        });
    }

    $('#k2s-traffic-refresh, #k2s-apply-filter').on('click', loadTraffic);

    $('#k2s-traffic-toggle').on('change', function(){
        $.post(k2s_ajax.ajax_url,{action:'k2s_save_option',nonce:k2s_ajax.nonce,key:'k2s_traffic_monitor_enabled',value:this.checked?1:0});
    });

    $('#k2s-traffic-clear').on('click', function(){
        if(!confirm('Svuotare tutti i dati di traffico?')) return;
        $.post(k2s_ajax.ajax_url,{action:'k2s_clear_traffic',nonce:k2s_ajax.nonce},function(){ loadTraffic(); });
    });

    // Auto-refresh ogni 30 secondi se il monitor è attivo
    <?php if ( $enabled ) : ?>
    setInterval(loadTraffic, 30000);
    loadTraffic();
    <?php endif; ?>
});
</script>
