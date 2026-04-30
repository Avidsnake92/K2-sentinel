<?php if ( ! defined( 'ABSPATH' ) ) exit;

// SVG icons
function k2s_icon($name, $size=16) {
    $s = $size;
    $icons = [
        'shield'   => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        'clock'    => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        'timer'    => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="13" r="8"/><polyline points="12 9 12 13 14 15"/><path d="M5 3l4 2M19 3l-4 2M12 3v2"/></svg>',
        'alert'    => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        'block'    => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
        'search'   => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
        'check'    => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
        'list'     => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
        'refresh'  => '<svg width="'.$s.'" height="'.$s.'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>',
    ];
    return $icons[$name] ?? '';
}
?>
<div class="k2s-wrap">
    <div class="k2s-header">
        <div class="k2s-logo">
            <img src="<?php echo K2S_URL; ?>admin/images/k2tech-logo.png" alt="K2Tech">
            <div class="k2s-logo__text">
                <span class="k2s-logo__name">K2 Sentinel</span>
                <span class="k2s-logo__sub">Antivirus &amp; Firewall</span>
            </div>
        </div>
        <div class="k2s-header-actions">
            <span class="k2s-version">v<?php echo K2_SENTINEL_VERSION; ?></span>
        </div>
    </div>

    <div class="k2s-grid-3">
        <div class="k2s-card <?php echo $fw_enabled ? 'active' : 'inactive'; ?>">
            <div class="k2s-card__icon"><?php echo k2s_icon('shield'); ?></div>
            <div class="k2s-card__label">Firewall</div>
            <div class="k2s-card__value"><?php echo $fw_enabled ? 'Attivo' : 'Inattivo'; ?></div>
        </div>

        <div class="k2s-card">
            <div class="k2s-card__icon"><?php echo k2s_icon('clock'); ?></div>
            <div class="k2s-card__label">Ultima scansione</div>
            <div class="k2s-card__value" style="font-size:15px;">
                <?php echo esc_html( $last_scan === 'Mai' ? 'Mai' : date_i18n( 'd/m/Y H:i', strtotime( $last_scan ) ) ); ?>
            </div>
        </div>

        <div class="k2s-card">
            <div class="k2s-card__icon"><?php echo k2s_icon('timer'); ?></div>
            <div class="k2s-card__label">Prossima scansione</div>
            <div class="k2s-card__value" style="font-size:15px;">
                <?php echo $next_scan ? date_i18n( 'H:i', $next_scan ) : '—'; ?>
            </div>
        </div>

        <div class="k2s-card <?php echo $last_threats > 0 ? 'k2s-card--danger' : 'k2s-card--safe'; ?>">
            <div class="k2s-card__icon"><?php echo k2s_icon('alert'); ?></div>
            <div class="k2s-card__label">Minacce rilevate</div>
            <div class="k2s-card__value"><?php echo $last_threats; ?></div>
        </div>

        <div class="k2s-card">
            <div class="k2s-card__icon"><?php echo k2s_icon('block'); ?></div>
            <div class="k2s-card__label">IP bloccati</div>
            <div class="k2s-card__value"><?php echo count( $blocked_ips ); ?></div>
        </div>

        <div class="k2s-card k2s-card--action">
            <div class="k2s-card__icon"><?php echo k2s_icon('search'); ?></div>
            <div class="k2s-card__label">Scansione manuale</div>
            <button id="k2s-scan-now" class="k2s-btn" style="margin-top:6px;">
                <?php echo k2s_icon('search', 14); ?> Avvia ora
            </button>
        </div>
    </div>

    <div id="k2s-scan-progress" style="display:none;" class="k2s-progress">
        <div class="k2s-progress__bar"><div class="k2s-progress__fill"></div></div>
        <p>Scansione in corso — potrebbe richiedere qualche secondo.</p>
    </div>

    <div id="k2s-scan-result" style="display:none;" class="k2s-result"></div>

    <div class="k2s-section">
        <h2 class="k2s-section__title">
            <?php echo k2s_icon('list'); ?>
            Ultimi eventi
        </h2>
        <?php if ( empty( $recent_logs ) ) : ?>
            <p class="k2s-empty">Nessun evento registrato. Il sito sembra pulito.</p>
        <?php else : ?>
            <table class="k2s-table">
                <thead>
                    <tr><th>Data/ora</th><th>Livello</th><th>Tipo</th><th>Dettaglio</th></tr>
                </thead>
                <tbody>
                <?php foreach ( $recent_logs as $log ) : ?>
                    <tr class="k2s-row--<?php echo esc_attr( $log->level ); ?>">
                        <td style="white-space:nowrap;font-family:var(--k2-mono);font-size:12px;"><?php echo esc_html( date_i18n( 'd/m H:i', strtotime( $log->log_time ) ) ); ?></td>
                        <td><span class="k2s-badge k2s-badge--<?php echo esc_attr( $log->level ); ?>"><?php echo esc_html( strtoupper( $log->level ) ); ?></span></td>
                        <td style="font-family:var(--k2-mono);font-size:12px;"><?php echo esc_html( $log->type ); ?></td>
                        <td style="font-size:12px;"><?php echo esc_html( $log->detail ); ?></td>
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
