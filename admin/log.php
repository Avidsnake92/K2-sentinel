<?php if ( ! defined( 'ABSPATH' ) ) exit;

// Svuota log
if ( isset( $_POST['k2s_clear_log'] ) && check_admin_referer( 'k2s_clear_log_nonce' ) ) {
    k2s_clear_logs();
    $logs = [];
    echo '<div class="k2s-notice success">Log svuotato.</div>';
}
?>
<div class="k2s-wrap">
    <div class="k2s-header">
        <div class="k2s-logo">Log Minacce</div>
        <form method="post" style="margin:0">
            <?php wp_nonce_field( 'k2s_clear_log_nonce' ); ?>
            <button name="k2s_clear_log" class="k2s-btn k2s-btn--danger" onclick="return confirm('Svuotare tutti i log?')">Svuota Log</button>
        </form>
    </div>

    <?php if ( empty( $logs ) ) : ?>
        <p class="k2s-empty">Nessun evento nel log. 🎉</p>
    <?php else : ?>
        <table class="k2s-table">
            <thead>
                <tr><th>ID</th><th>Data/Ora</th><th>Livello</th><th>Tipo</th><th>Dettaglio</th></tr>
            </thead>
            <tbody>
            <?php foreach ( $logs as $log ) : ?>
                <tr class="k2s-row--<?php echo esc_attr( $log->level ); ?>">
                    <td><?php echo (int) $log->id; ?></td>
                    <td><?php echo esc_html( date_i18n( 'd/m/Y H:i:s', strtotime( $log->log_time ) ) ); ?></td>
                    <td><span class="k2s-badge k2s-badge--<?php echo esc_attr( $log->level ); ?>"><?php echo esc_html( strtoupper( $log->level ) ); ?></span></td>
                    <td><?php echo esc_html( $log->type ); ?></td>
                    <td><?php echo esc_html( $log->detail ); ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
