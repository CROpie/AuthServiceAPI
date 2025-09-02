<?php
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64UrlDecode($data) {

    $base64 = strtr($data, '-_', '+/');

    $padding = strlen($base64) % 4;
    
    if ($padding > 0) $base64 .= str_repeat('=', 4 - $padding);

    return base64_decode($base64);
}

?>