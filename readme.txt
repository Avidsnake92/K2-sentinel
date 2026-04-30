=== K2 Sentinel – Antivirus & Firewall ===
Versione: 1.0.0
Richiede WordPress: 5.8+
Richiede PHP: 7.4+
Licenza: GPL-2.0+

== Descrizione ==

K2 Sentinel protegge il tuo sito WordPress con due moduli principali:

**🦠 Antivirus – Scanner automatico (ogni ora)**
- Scansiona tutti i file PHP modificati di recente alla ricerca di:
  eval(base64_decode), shell_exec, backdoor, codice offuscato, ecc.
- Scansiona il database (post, meta, opzioni, commenti) cercando:
  iframe injection, script injection, link phishing, spam keyword, ecc.

**🔥 Firewall in tempo reale**
- Blocca automaticamente bot malevoli (sqlmap, nikto, dirbuster…)
- Protezione SQL Injection su GET, POST e cookie
- Protezione XSS su input
- Blocco manuale e automatico degli IP
- Log completo di tutte le minacce rilevate

== Installazione ==

1. Carica la cartella `k2-sentinel` in `/wp-content/plugins/`
2. Attiva il plugin dal pannello "Plugin" di WordPress
3. Vai su **K2 Sentinel > Dashboard** per vedere lo stato

== Struttura file ==

k2-sentinel/
├── k2-sentinel.php          ← File principale del plugin
├── includes/
│   ├── scanner.php          ← Logica scanner AV
│   ├── firewall.php         ← Logica firewall
│   └── logger.php           ← Database log
├── admin/
│   ├── dashboard.php        ← Pagina principale
│   ├── log.php              ← Pagina log
│   ├── firewall.php         ← Pagina firewall
│   ├── settings.php         ← Pagina impostazioni
│   ├── css/style.css        ← Stili admin (tema dark)
│   └── js/script.js         ← AJAX scan manuale

== FAQ ==

Q: La scansione rallenta il sito?
A: No. Il cron di WordPress esegue lo scanner in background ogni ora,
   solo sui file modificati dall'ultima scansione.

Q: Il firewall blocca visitatori legittimi?
A: Il firewall analizza solo pattern chiaramente malevoli.
   Puoi sbloccare manualmente qualsiasi IP dalla pagina Firewall.

== Changelog ==

= 1.0.0 =
* Prima versione pubblica
