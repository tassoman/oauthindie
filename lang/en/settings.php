<?php
/**
 * English language file for the oauthindie plugin.
 */
$lang['label'] = 'Login with IndieAuth';
$lang['color'] = 'Color of the login button';
$lang['scopes'] = 'Scopes to request (space-separated; default: read:account)';
$lang['profileurl'] = 'Authenticated account profile endpoint (optional; defaults to Misskey /api/i)';
$lang['identitylabel'] = 'Your website or IndieAuth identity URL';
$lang['identityplaceholder'] = 'https://example.com/';
$lang['identityrequired'] = 'Enter your website URL to continue.';
$lang['identityinvalid'] = 'Enter a valid website URL with a hostname.';
$lang['privatehost'] = 'This identity URL resolves to a private or reserved network address and cannot be used.';
$lang['discoveryfailed'] = 'Could not retrieve the identity page (HTTP status %d).';
$lang['noauthorizationendpoint'] = 'No IndieAuth authorization_endpoint was found on this identity page.';
$lang['endpointmustbehttps'] = 'Discovered IndieAuth endpoints must use HTTPS.';
$lang['loginbutton'] = 'Continue with IndieAuth';
