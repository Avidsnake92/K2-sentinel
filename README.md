# K2 Sentinel – Antivirus & Firewall

**Plugin WordPress per la sicurezza** sviluppato da [K2Tech](https://k2tech.it).

---

## Funzionalità

| Modulo | Descrizione |
|--------|-------------|
| **Antivirus** | Scanner file PHP, HTML, JS, .htaccess — aggiornamento definizioni da GitHub ogni 24h |
| **Firewall** | Blocco SQL Injection, XSS, bad bot, gestione IP in tempo reale |
| **Core Integrity** | Confronto file WordPress con checksum ufficiali wordpress.org |
| **Traffic Monitor** | Log richieste HTTP in tempo reale con filtri e statistiche 24h |
| **Bonifica automatica** | File infetti → quarantena · DB → backup + pulizia pattern |
| **Hardening** | 12 misure di sicurezza attivabili (XML-RPC, REST API, brute force, header HTTP…) |
| **2FA (TOTP)** | Autenticazione a due fattori compatibile Google Authenticator / Authy |
| **Auto-update** | Aggiornamenti automatici tramite GitHub Releases — nessuno zip manuale |

---

## Requisiti

- WordPress 5.8+
- PHP 7.4+
- Accesso in scrittura a `wp-content/` (per quarantena)

---

## Installazione

1. Vai su **Releases** → scarica l'ultimo `k2-sentinel.zip`
2. WordPress Admin → Plugin → Aggiungi nuovo → Carica plugin
3. Attiva — il plugin si configura automaticamente all'attivazione

Gli aggiornamenti futuri appariranno direttamente nel pannello WordPress (**Dashboard → Aggiornamenti**) come qualsiasi altro plugin.

---

## Rilasciare un aggiornamento

1. Modifica il codice
2. Aggiorna `Version:` nell'header di `k2-sentinel.php` e `K2_SENTINEL_VERSION`
3. Crea una **GitHub Release** con tag `v1.x.x` (es. `v1.3.0`)
4. Allega lo ZIP del plugin alla release oppure usa il zipball automatico di GitHub
5. I siti installati riceveranno la notifica di aggiornamento entro 12 ore

---

## Struttura

```
k2-sentinel/
├── k2-sentinel.php          # File principale
├── definitions.json         # Definizioni pattern (da copiare in wp-sentinel-definitions)
├── includes/
│   ├── scanner.php          # Scanner AV file + DB
│   ├── firewall.php         # Firewall real-time
│   ├── integrity.php        # Core integrity checker
│   ├── remediation.php      # Bonifica automatica + quarantena
│   ├── hardening.php        # Misure di sicurezza base
│   ├── traffic.php          # Traffic monitor
│   ├── two-factor.php       # 2FA TOTP
│   ├── definitions.php      # Aggiornamento definizioni remote
│   ├── notifications.php    # Email digest + alert critici
│   ├── updater.php          # Auto-update da GitHub Releases
│   └── logger.php           # Log DB
└── admin/
    ├── dashboard.php
    ├── firewall.php
    ├── traffic.php
    ├── integrity.php
    ├── hardening.php
    ├── quarantine.php
    ├── log.php
    ├── settings.php
    ├── css/style.css
    ├── js/script.js
    └── images/k2tech-logo.png
```

---

## Definizioni pattern

Le definizioni di rilevamento malware vengono aggiornate separatamente nel repo [`wp-sentinel-definitions`](https://github.com/Avidsnake92/wp-sentinel-definitions). Il plugin le scarica automaticamente ogni 24 ore.

---

*K2 Sentinel — by K2Tech*
