<?php
require_once __DIR__ . '/lib/oauthindie_helpers.php';

// POST parameter: url (user's site)
if($_SERVER['REQUEST_METHOD'] !== 'POST'){
    echo "Send POST with 'url' form field to start the IndieAuth flow.";
    exit;
}

$me = isset($_POST['url']) ? oauthindie_normalize_url($_POST['url']) : null;
if(!$me){
    echo "Invalid url";
    exit;
}

$endpoints = oauthindie_discover_endpoints($me);
oauthindie_log("start: normalized me={$me}");
oauthindie_log("start: discovered endpoints=".print_r($endpoints, true));
if(empty($endpoints['authorization_endpoint'])){
    echo "Could not find authorization_endpoint at $me";
    exit;
}

$state = bin2hex(random_bytes(16));
$verifier = oauthindie_generate_code_verifier();
$challenge = oauthindie_code_challenge($verifier);

// store in session
$_SESSION[DOKU_COOKIE ?? 'oauthindie'] = array_merge($_SESSION[DOKU_COOKIE ?? 'oauthindie'] ?? [], [
    'state' => $state,
    'verifier' => $verifier,
    'me' => $me,
    'auth_endpoint' => $endpoints['authorization_endpoint'],
    'token_endpoint' => $endpoints['token_endpoint'] ?? null
]);

// Build client_id and redirect_uri. Prefer DokuWiki's configured base URL when available.
$base = null;
if(defined('DOKU_INC') && isset($conf) && !empty($conf['baseurl'])){
    $base = rtrim($conf['baseurl'], '/');
} else {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $base = $scheme.'://'.$host;
}
$redirect_uri = $base.rtrim(dirname($_SERVER['PHP_SELF']), '/').'/callback.php';
$client_id = $base; // recommend customizing if site has a canonical homepage URL

$params = [
    'response_type' => 'code',
    'client_id' => $client_id,
    'redirect_uri' => $redirect_uri,
    'state' => $state,
    'code_challenge' => $challenge,
    'code_challenge_method' => 'S256',
    'me' => $me,
    'scope' => 'profile email'
];

$location = $endpoints['authorization_endpoint'] . (strpos($endpoints['authorization_endpoint'], '?') === false ? '?' : '&') . http_build_query($params);
oauthindie_log("start: redirecting to authorization endpoint: $location");
header('Location: ' . $location);
exit;
