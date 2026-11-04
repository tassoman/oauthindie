<?php
/**
 * Italian language file for the oauthindie plugin.
 */
$lang['label'] = 'Accedi con IndieAuth';
$lang['color'] = 'Colore del pulsante di accesso';
$lang['scopes'] = 'Scope da richiedere (separati da spazi; predefinito: read:account)';
$lang['profileurl'] = 'Endpoint del profilo autenticato (opzionale; predefinito: Misskey /api/i)';
$lang['identitylabel'] = 'Il tuo sito o URL di identità IndieAuth';
$lang['identityplaceholder'] = 'https://example.com/';
$lang['identityrequired'] = 'Inserisci l’URL del tuo sito per continuare.';
$lang['identityinvalid'] = 'Inserisci un URL valido con un hostname.';
$lang['privatehost'] = 'Questo URL risolve a un indirizzo di rete privato o riservato e non può essere usato.';
$lang['discoveryfailed'] = 'Impossibile recuperare la pagina di identità (stato HTTP %d).';
$lang['noauthorizationendpoint'] = 'Nessun authorization_endpoint IndieAuth trovato nella pagina di identità.';
$lang['endpointmustbehttps'] = 'Gli endpoint IndieAuth scoperti devono usare HTTPS.';
$lang['loginbutton'] = 'Continua con IndieAuth';
