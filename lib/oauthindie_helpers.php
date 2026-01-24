<?php
// Minimal helpers for oauthindie IndieAuth flow
session_start();

function oauthindie_normalize_url($url){
    $url = trim($url);
    if(!$url) return false;
    if(!preg_match('#^https?://#', $url)) $url = 'https://'.$url;
    return rtrim($url, '/');
}

function oauthindie_fetch($url){
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'oauthindie/1.0');
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$code, $res];
}

function oauthindie_discover_endpoints($url){
    list($code, $html) = oauthindie_fetch($url);
    if($code < 200 || $code >= 400 || !$html) return [];
    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    $dom->loadHTML($html);
    $links = $dom->getElementsByTagName('link');
    $ret = [];
    foreach($links as $link){
        $rel = $link->getAttribute('rel');
        $href = $link->getAttribute('href');
        if(!$rel || !$href) continue;
        // resolve relative URLs against the discovery URL
        $resolved = oauthindie_resolve_url($url, $href);
        if(strpos($rel, 'authorization_endpoint') !== false){
            $ret['authorization_endpoint'] = $resolved;
        }
        if(strpos($rel, 'token_endpoint') !== false){
            $ret['token_endpoint'] = $resolved;
        }
    }
    return $ret;
}

function oauthindie_resolve_url($base, $href){
    // absolute URL
    if(preg_match('#^https?://#i', $href)) return $href;
    // scheme-relative
    if(strpos($href, '//') === 0){
        $p = parse_url($base);
        return $p['scheme'].':'.$href;
    }
    // relative path
    $p = parse_url($base);
    $scheme = $p['scheme'] ?? 'https';
    $host = $p['host'] ?? '';
    $port = isset($p['port']) ? ':' . $p['port'] : '';
    $path = $p['path'] ?? '/';
    // remove filename from path
    $baseDir = preg_replace('#/[^/]*$#', '/', $path);
    // if href starts with '/', it's root-relative
    if(strpos($href, '/') === 0){
        $path = $href;
    } else {
        $path = $baseDir . $href;
    }
    // normalize // and /./ segments
    $abs = $scheme.'://'.$host.$port.'/'.$path;
    $abs = preg_replace('#/+#','/',$abs);
    // remove '/.' and resolve '/../'
    $parts = explode('/', $abs);
    $out = [];
    foreach($parts as $part){
        if($part === '..') { array_pop($out); continue; }
        if($part === '.') continue;
        $out[] = $part;
    }
    return implode('/', $out);
}

function oauthindie_generate_code_verifier(){
    return bin2hex(random_bytes(32));
}

function oauthindie_code_challenge($verifier){
    $hash = hash('sha256', $verifier, true);
    $b64 = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    return $b64;
}

function oauthindie_post($url, $data){
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_USERAGENT, 'oauthindie/1.0');
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$code, $res];
}

function oauthindie_log($msg){
    if(is_array($msg) || is_object($msg)) $msg = print_r($msg, true);
    // prefer DokuWiki debug log if available
    if(function_exists('dbglog')){
        dbglog('[oauthindie] '.$msg);
    } else {
        error_log('[oauthindie] '.$msg);
    }
}
