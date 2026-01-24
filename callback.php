<?php
require_once __DIR__ . '/lib/oauthindie_helpers.php';

// Expecting ?code=...&state=...
$code = $_GET['code'] ?? null;
$state = $_GET['state'] ?? null;

$sess = $_SESSION[DOKU_COOKIE ?? 'oauthindie'] ?? null;
if(!$code || !$state || !$sess || !isset($sess['state']) || $state !== $sess['state']){
    oauthindie_log("callback: invalid or missing state/code; code=".var_export($code, true)." state=".var_export($state, true));
    http_response_code(400);
    echo "Invalid or missing state/code";
    exit;
}

$token_endpoint = $sess['token_endpoint'] ?? null;
$auth_endpoint = $sess['auth_endpoint'] ?? null;
$me = $sess['me'] ?? null;

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
$client_id = $base;

if(!$token_endpoint){
    // try discovering token endpoint from original me URL
    $disc = oauthindie_discover_endpoints($me);
    $token_endpoint = $disc['token_endpoint'] ?? null;
}

if(!$token_endpoint){
    oauthindie_log("callback: no token_endpoint available for me={$me}");
    http_response_code(400);
    echo "No token_endpoint available";
    exit;
}

$post = [
    'grant_type' => 'authorization_code',
    'code' => $code,
    'client_id' => $client_id,
    'redirect_uri' => $redirect_uri,
    'code_verifier' => $sess['verifier'] ?? ''
];

list($c, $resp) = oauthindie_post($token_endpoint, $post);
if($c < 200 || $c >= 400){
    oauthindie_log("callback: token endpoint HTTP $c response: ".substr($resp,0,1000));
    http_response_code(500);
    echo "Token endpoint returned HTTP $c: $resp";
    exit;
}

// parse JSON or urlencoded
$data = json_decode($resp, true);
if(!$data) parse_str($resp, $data);

// Normalize returned me and redact sensitive tokens before logging
$me_returned = $data['me'] ?? null;
$profile = $data['profile'] ?? [];
$log_data = $data;
foreach(['access_token','refresh_token','id_token'] as $t){ if(isset($log_data[$t])) $log_data[$t] = '[REDACTED]'; }
oauthindie_log('callback: token response parsed (redacted): '.print_r($log_data, true));

if(!$me_returned){
    http_response_code(400);
    echo "Token response missing 'me'";
    exit;
}

// Normalize `me` URLs before verification and re-discover auth endpoint
$me_norm = oauthindie_normalize_url($me);
$me_returned_norm = oauthindie_normalize_url($me_returned);
$disc2 = oauthindie_discover_endpoints($me_returned_norm);
$auth2 = $disc2['authorization_endpoint'] ?? null;
if($auth_endpoint && $auth2 && rtrim($auth_endpoint, '/') !== rtrim($auth2, '/')){
    oauthindie_log("callback: authorization endpoint mismatch: initial={$auth_endpoint} returned={$auth2}");
    http_response_code(400);
    echo "Authorization endpoint mismatch";
    exit;
}

// Build DokuWiki USERINFO and session entries
global $USERINFO;
$USERINFO = [
    'name' => $profile['name'] ?? ($me_returned),
    'mail' => $profile['email'] ?? '',
    'grps' => ['user']
];

// Try to set DokuWiki session format if available
if(defined('DOKU_COOKIE')){
    $_SESSION[DOKU_COOKIE]['auth']['user'] = $me_returned;
    $_SESSION[DOKU_COOKIE]['auth']['pass'] = bin2hex(random_bytes(12));
    $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
    $_SERVER['REMOTE_USER'] = $me_returned;
} else {
    // fallback storage for standalone testing
    $_SESSION['oauthindie_auth'] = [
        'user' => $me_returned,
        'info' => $USERINFO
    ];
}

echo "Authentication succeeded for: " . htmlspecialchars($me_returned);
echo "\nProfile: ";
echo htmlspecialchars(print_r($profile, true));
exit;
