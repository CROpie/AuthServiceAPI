<?php

// either this or env variable to determine whether testing locally or deployed
$isProd = ($_SERVER['HTTP_HOST'] === 'auth.cropie.online');

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

// Handle preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Headers: Content-Type");
    header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
    exit(0);
}

$allowedOrigins = $isProd
    ? ['https://lobby.cropie.online', 'https://hangman.cropie.online']
    : ['http://localhost:1234', 'http://localhost:4000'];

if (in_array($origin, $allowedOrigins)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
}

require_once("./utils.php");

$uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

$response = [];

// have to pass into functions due to PHP function scope
$fp = stream_socket_client("tcp://localhost:12345", $errno, $errstr, 5);

if (!$fp) {
    error_log("Failed to connect to db\n", 3, "./error.log");
    die("Connection failed: $errstr ($errno)");
}

$uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

$response = [];

try {

    switch ($method | $uri) {
        case($method == 'POST' && $uri == '/api/token'):

            $response = handleObtainToken($response, $fp);

            break;
        case($method == 'GET' && $uri == '/api/authenticate'):

            $response = handleAuthentication($response, $fp);

            break;
        case($method == 'GET' && $uri == '/api/logout'):

            $response = handleLogOut($response, $fp);

            break;
        default:
            throw new Exception("Invalid URL", 404);
            break;
    }

} catch (Exception $e) {
    http_response_code($e->getCode());
    $response['error'] = $e->getMessage();
}

header('Content-Type: application/json');
echo json_encode($response);

function generateJWT($username) {
    // generate a JWT: header, payload, signature
    $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];

    // note: expiry is UNIX time
    $payload = [
        'username' => $username,
        'expiry' => time() + 24 * 60 * 60
    ];

    $headerEncoded = base64UrlEncode(json_encode($header));
    $payloadEncoded = base64UrlEncode(json_encode($payload));

    $secret = "not_safe_for_production";

    $signature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", $secret, true);
    $signatureEncoded = base64UrlEncode($signature);

    return "$headerEncoded.$payloadEncoded.$signatureEncoded";
}

function getStoredPassword($username, $fp) {

    // update using WHERE
    fwrite($fp, "SELECT * FROM auth;\n");
    $res = fread($fp, 1024);
    $users = json_decode($res, true);

    $found = false;
    $hashedPassword;

    foreach ($users as $user) {
        if ($user['username'] === $username) {
            $found = true;
            $hashedPassword = $user['hashedPassword'];
            break;
        }
    }

    if (!$found) throw new Exception("cannot find user in database", 401);

    return $hashedPassword;

    // $hash = password_hash($password, PASSWORD_DEFAULT);
}

function handleObtainToken($response, $fp) {
    $username = sanitize_input($_POST["username"]);
    $password = sanitize_input($_POST["password"]);

    if (empty($username)) throw new Exception("username field was left empty", 400);
    if (empty($password)) throw new Exception("password field was left empty", 400);

    $hashedPassword = getStoredPassword($username, $fp);

    if (!password_verify($password, $hashedPassword)) throw new Exception("incorrect password", 401);

    $jwt = generateJWT($username);

    $isProd = ($_SERVER['HTTP_HOST'] === 'auth.cropie.online');

    setcookie(
        "token",
        $jwt,
        [
            'expires' => time() + 60 * 60 * 24,
            'path' => '/',
            'domain' => $isProd ? '.cropie.online' : '', // share across subdomains (blank for localhost)
            'secure' => $isProd, // HTTPS only (prod only)
            'httponly' => true, // JS cannot read
            'samesite' => $isProd ? 'None' : 'Lax' // required for cross-site
        ]
    );

    $response['data'] = $jwt;

    return $response;
}

function getJWTFromHeader() {
    $headers = getallheaders();

    if (!isset($headers['Authorization'])) throw new Exception("Authorization header missing", 401);

    $authHeader = $headers['Authorization'];

    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) throw new Exception("Invalid Authorization header format", 400);

    return $matches[1];
}

function validateAndExtractPayloadFromJWT($jwt) {
    // "header.payload.signature";

    $parts = explode('.', $jwt);

    if (count($parts) != 3) throw new Exception("Incorrect formatting of JWT", 400);

    $secret = "not_safe_for_production";

    $signature = hash_hmac('sha256', "$parts[0].$parts[1]", $secret, true);
    $signatureEncoded = base64UrlEncode($signature);

    if ($signatureEncoded != $parts[2]) throw new Exception("Token has been tampered with", 400);

    // note: json_decode will return PHP object instead of associate array unless 2nd arg is "true"
    $decodedPayload = json_decode(base64UrlDecode($parts[1]), true);

    return $decodedPayload;
}

function isTokenExpired($payload) {
    return $payload['expiry'] < time();
}

// Function to verify a token that is sent via Authorization -> Bearer (currently disabled)
function handleClientAuthentication($response) {
    $jwt = getJWTFromHeader();

    $payload = validateAndExtractPayloadFromJWT($jwt);

    if (isTokenExpired($payload)) throw new Exception("Token has expired", 400);

    $response['data'] = $payload;
    return $response;
}

function getJWTFromCookieHeader() {
    if (!isset($_COOKIE['token'])) throw new Exception("Unauthorized", 401);

    return $_COOKIE['token'];
}

function handleAuthentication($response) {

    // $jwt = getJWTFromCookieHeader();
    $jwt = $_COOKIE['token'];

    if (!$jwt) throw new Exception("No token", 400);

    $payload = validateAndExtractPayloadFromJWT($jwt);

    if (isTokenExpired($payload)) throw new Exception("Token has expired", 400);

    $response['data'] = $payload;

    return $response;
}

function handleLogOut($reponse) {

    $isProd = ($_SERVER['HTTP_HOST'] === 'auth.cropie.online');
    
    setcookie(
        "token",
        '',
        [
            'expires' => time() - 3600,
            'path' => '/',
            'domain' => $isProd ? '.cropie.online' : '',
            'secure' => $isProd,
            'httponly' => true,
            'samesite' => $isProd ? 'None' : 'Lax'
        ]
    );
}