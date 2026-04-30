<?php
/**
 * K2 Sentinel – Two-Factor Authentication (TOTP)
 * Implementa 2FA basato su TOTP (Google Authenticator, Authy, ecc.)
 * senza dipendenze esterne — usa solo funzioni PHP native.
 */
if ( ! defined( 'ABSPATH' ) ) exit;

// ═══════════════════════════════════════════════════════════════════
//  HOOK LOGIN
// ═══════════════════════════════════════════════════════════════════
add_action( 'login_form',           'k2s_2fa_login_field' );
add_filter( 'authenticate',         'k2s_2fa_authenticate', 50, 3 );
add_action( 'show_user_profile',    'k2s_2fa_user_profile_section' );
add_action( 'edit_user_profile',    'k2s_2fa_user_profile_section' );
add_action( 'personal_options_update', 'k2s_2fa_save_user_settings' );
add_action( 'edit_user_profile_update','k2s_2fa_save_user_settings' );

// ─── Campo OTP nel form di login ─────────────────────────────────
function k2s_2fa_login_field() {
    echo '<p><label for="k2s_otp">Codice 2FA (se abilitato)<br>
    <input type="text" name="k2s_otp" id="k2s_otp" class="input" value="" size="20"
           autocomplete="one-time-code" inputmode="numeric" maxlength="6"
           pattern="[0-9]{6}" placeholder="000000">
    </label></p>';
}

// ─── Verifica OTP dopo le credenziali standard ────────────────────
function k2s_2fa_authenticate( $user, $username, $password ) {
    // Se l'autenticazione precedente è già fallita, non interferire
    if ( is_wp_error( $user ) ) return $user;
    if ( ! ( $user instanceof WP_User ) ) return $user;

    // Controlla se questo utente ha il 2FA abilitato
    $secret = get_user_meta( $user->ID, 'k2s_2fa_secret', true );
    if ( empty( $secret ) ) return $user; // 2FA non configurato → login normale

    $otp_input = sanitize_text_field( $_POST['k2s_otp'] ?? '' );

    if ( empty( $otp_input ) ) {
        return new WP_Error( 'k2s_2fa_required',
            '<strong>2FA richiesto.</strong> Inserisci il codice dalla tua app authenticator.' );
    }

    if ( ! k2s_totp_verify( $secret, $otp_input ) ) {
        // Log del tentativo fallito
        k2s_log( 'warning', '2fa_failed', "Tentativo 2FA fallito per: {$user->user_login} da " . k2s_get_client_ip() );
        return new WP_Error( 'k2s_2fa_invalid',
            '<strong>Codice 2FA non valido.</strong> Riprova.' );
    }

    k2s_log( 'info', '2fa_success', "Login 2FA riuscito: {$user->user_login}" );
    return $user;
}

// ═══════════════════════════════════════════════════════════════════
//  SEZIONE PROFILO UTENTE
// ═══════════════════════════════════════════════════════════════════
function k2s_2fa_user_profile_section( $user ) {
    if ( ! get_option( 'k2s_2fa_enabled', 0 ) ) return;
    if ( ! current_user_can( 'manage_options' ) && ! ( $user->ID === get_current_user_id() ) ) return;

    $secret  = get_user_meta( $user->ID, 'k2s_2fa_secret', true );
    $enabled = ! empty( $secret );

    // Genera segreto temporaneo per la configurazione
    if ( ! $enabled ) {
        $tmp_secret = k2s_totp_generate_secret();
        $qr_url     = k2s_totp_qr_url( $tmp_secret, $user->user_email );
    }
    ?>
    <h2>K2 Sentinel – Autenticazione a Due Fattori (2FA)</h2>
    <table class="form-table">
        <tr>
            <th>Stato 2FA</th>
            <td>
                <?php if ( $enabled ) : ?>
                    <span style="color:#1a8a3a;font-weight:600;">✅ Abilitato</span>
                    <p class="description">Il 2FA è attivo per il tuo account.</p>
                    <label>
                        <input type="checkbox" name="k2s_2fa_disable" value="1">
                        Disabilita 2FA (richiede codice attuale)
                    </label><br>
                    <input type="text" name="k2s_2fa_disable_otp" placeholder="Codice OTP corrente" maxlength="6" style="margin-top:6px;">
                <?php else : ?>
                    <span style="color:#D63B2F;font-weight:600;">❌ Non configurato</span>
                    <p class="description">Scansiona il QR con Google Authenticator, Authy o app compatibile TOTP.</p>
                    <input type="hidden" name="k2s_2fa_secret" value="<?php echo esc_attr( $tmp_secret ); ?>">
                    <div style="margin:12px 0;">
                        <img src="<?php echo esc_url( $qr_url ); ?>" alt="QR Code 2FA" style="width:180px;height:180px;border:4px solid #f0f0f0;border-radius:8px;">
                    </div>
                    <p>Oppure inserisci il codice manuale: <code><?php echo esc_html( k2s_totp_format_secret( $tmp_secret ) ); ?></code></p>
                    <label style="display:block;margin-top:8px;">
                        Verifica codice (inserisci il codice dall'app per attivare):
                        <input type="text" name="k2s_2fa_verify_otp" maxlength="6" pattern="[0-9]{6}"
                               placeholder="000000" style="margin-left:8px;width:100px;">
                    </label>
                <?php endif; ?>
            </td>
        </tr>
    </table>
    <?php
}

// ─── Salva impostazioni 2FA dal profilo ───────────────────────────
function k2s_2fa_save_user_settings( $user_id ) {
    if ( ! current_user_can( 'edit_user', $user_id ) ) return;
    if ( ! get_option( 'k2s_2fa_enabled', 0 ) ) return;

    // Attivazione 2FA
    if ( ! empty( $_POST['k2s_2fa_secret'] ) && ! empty( $_POST['k2s_2fa_verify_otp'] ) ) {
        $secret = sanitize_text_field( $_POST['k2s_2fa_secret'] );
        $otp    = sanitize_text_field( $_POST['k2s_2fa_verify_otp'] );

        if ( k2s_totp_verify( $secret, $otp ) ) {
            update_user_meta( $user_id, 'k2s_2fa_secret', $secret );
            k2s_log( 'info', '2fa_enabled', "2FA abilitato per user ID $user_id" );
        }
    }

    // Disattivazione 2FA
    if ( ! empty( $_POST['k2s_2fa_disable'] ) && ! empty( $_POST['k2s_2fa_disable_otp'] ) ) {
        $secret = get_user_meta( $user_id, 'k2s_2fa_secret', true );
        $otp    = sanitize_text_field( $_POST['k2s_2fa_disable_otp'] );

        if ( $secret && k2s_totp_verify( $secret, $otp ) ) {
            delete_user_meta( $user_id, 'k2s_2fa_secret' );
            k2s_log( 'info', '2fa_disabled', "2FA disabilitato per user ID $user_id" );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  MOTORE TOTP (RFC 6238) – nessuna dipendenza esterna
// ═══════════════════════════════════════════════════════════════════

function k2s_totp_generate_secret( $length = 16 ) {
    $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 alphabet
    $secret = '';
    $bytes  = random_bytes( $length );
    for ( $i = 0; $i < $length; $i++ ) {
        $secret .= $chars[ ord( $bytes[ $i ] ) % 32 ];
    }
    return $secret;
}

function k2s_totp_format_secret( $secret ) {
    return implode( ' ', str_split( $secret, 4 ) );
}

function k2s_totp_verify( $secret, $otp, $window = 1 ) {
    $otp      = preg_replace( '/\D/', '', $otp );
    $time     = (int) floor( time() / 30 );

    for ( $i = -$window; $i <= $window; $i++ ) {
        if ( k2s_totp_generate( $secret, $time + $i ) === $otp ) {
            return true;
        }
    }
    return false;
}

function k2s_totp_generate( $secret, $time = null ) {
    if ( $time === null ) $time = (int) floor( time() / 30 );

    // Decodifica Base32 del segreto
    $decoded = k2s_base32_decode( $secret );
    if ( ! $decoded ) return '';

    // Pack time come 8 byte big-endian
    $time_bytes = pack( 'N*', 0, $time );

    // HMAC-SHA1
    $hash = hash_hmac( 'sha1', $time_bytes, $decoded, true );

    // Dynamic truncation
    $offset = ord( $hash[19] ) & 0x0F;
    $code   = (
        ( ( ord( $hash[ $offset ] )     & 0x7F ) << 24 ) |
        ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
        ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8  ) |
        ( ( ord( $hash[ $offset + 3 ] ) & 0xFF )       )
    ) % 1000000;

    return str_pad( (string) $code, 6, '0', STR_PAD_LEFT );
}

function k2s_base32_decode( $input ) {
    $map    = array_flip( str_split( 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' ) );
    $input  = strtoupper( preg_replace( '/\s+/', '', $input ) );
    $output = '';
    $buffer = 0;
    $bits   = 0;

    foreach ( str_split( $input ) as $char ) {
        if ( ! isset( $map[ $char ] ) ) continue;
        $buffer = ( $buffer << 5 ) | $map[ $char ];
        $bits  += 5;
        if ( $bits >= 8 ) {
            $bits   -= 8;
            $output .= chr( ( $buffer >> $bits ) & 0xFF );
        }
    }
    return $output ?: false;
}

function k2s_totp_qr_url( $secret, $email ) {
    $site  = rawurlencode( get_bloginfo( 'name' ) );
    $email = rawurlencode( $email );
    $data  = rawurlencode( "otpauth://totp/{$site}:{$email}?secret={$secret}&issuer={$site}&algorithm=SHA1&digits=6&period=30" );
    // Usa API QR esterna (chart.googleapis.com) — fallback: mostra codice testo
    return "https://chart.googleapis.com/chart?chs=180x180&chld=M|0&cht=qr&chl={$data}";
}
