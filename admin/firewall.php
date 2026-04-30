<?php if ( ! defined( 'ABSPATH' ) ) exit; ?>
<div class="k2s-wrap">
    <div class="k2s-header">
        <div class="k2s-logo">🔥 Firewall</div>
    </div>

    <form method="post">
        <?php wp_nonce_field( 'k2s_fw_nonce' ); ?>
        <div class="k2s-section">
            <h2 class="k2s-section__title">Regole Firewall</h2>
            <div class="k2s-toggle-row">
                <label class="k2s-toggle">
                    <input type="checkbox" name="fw_enabled" <?php checked( $fw_enabled, 1 ); ?>>
                    <span class="k2s-toggle__slider"></span>
                </label>
                <span>Attiva Firewall</span>
            </div>
            <div class="k2s-toggle-row">
                <label class="k2s-toggle">
                    <input type="checkbox" name="block_bots" <?php checked( $block_bots, 1 ); ?>>
                    <span class="k2s-toggle__slider"></span>
                </label>
                <span>Blocca Bot Malevoli (sqlmap, nikto, dirbuster…)</span>
            </div>
            <div class="k2s-toggle-row">
                <label class="k2s-toggle">
                    <input type="checkbox" name="block_sql" <?php checked( $block_sql, 1 ); ?>>
                    <span class="k2s-toggle__slider"></span>
                </label>
                <span>Blocca SQL Injection</span>
            </div>
            <div class="k2s-toggle-row">
                <label class="k2s-toggle">
                    <input type="checkbox" name="block_xss" <?php checked( $block_xss, 1 ); ?>>
                    <span class="k2s-toggle__slider"></span>
                </label>
                <span>Blocca XSS (Cross-Site Scripting)</span>
            </div>
        </div>

        <div class="k2s-section">
            <h2 class="k2s-section__title">Blocca IP Manualmente</h2>
            <div class="k2s-input-row">
                <input type="text" name="new_blocked_ip" placeholder="es. 192.168.1.100" class="k2s-input">
                <button type="submit" name="k2s_fw_save" class="k2s-btn">➕ Blocca IP</button>
            </div>
        </div>

        <button type="submit" name="k2s_fw_save" class="k2s-btn k2s-btn--primary">Salva Impostazioni</button>
    </form>

    <!-- IP bloccati -->
    <div class="k2s-section">
        <h2 class="k2s-section__title">IP Bloccati (<?php echo count( $blocked_ips ); ?>)</h2>
        <?php if ( empty( $blocked_ips ) ) : ?>
            <p class="k2s-empty">Nessun IP bloccato.</p>
        <?php else : ?>
            <table class="k2s-table">
                <thead>
                    <tr><th>IP</th><th>Motivo</th><th>Data Blocco</th><th>Azione</th></tr>
                </thead>
                <tbody>
                <?php foreach ( $blocked_ips as $ip => $data ) : ?>
                    <tr>
                        <td><code><?php echo esc_html( $ip ); ?></code></td>
                        <td><?php echo esc_html( $data['reason'] ); ?></td>
                        <td><?php echo esc_html( $data['blocked_at'] ); ?></td>
                        <td>
                            <a href="<?php echo wp_nonce_url( admin_url( 'admin.php?page=k2-sentinel-fw&unblock=' . urlencode( $ip ) ), 'k2s_unblock' ); ?>"
                               class="k2s-btn k2s-btn--sm k2s-btn--danger"
                               onclick="return confirm('Sbloccare <?php echo esc_js( $ip ); ?>?')">
                                Sblocca
                            </a>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>
