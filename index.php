<?php
// Allow CORS for all requests
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

// Handle preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
    exit(0);
}

// Normal GET/POST handling
header("Access-Control-Allow-Origin: *");

require_once("./utils.php");

$uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

$response = [];

try {

    switch ($method | $uri) {
        case($method == 'POST' && $uri == '/api/token'):

            $response = handleObtainToken($response);

            break;
        case($method == 'GET' && $uri == '/api/authenticate'):

            $response = handleAuthentication($response);

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

function getStoredPassword($username) {
    // swap with query database
    $data = file_get_contents('database.json');
    $users = json_decode($data, true);

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
    // password: $2y$10$Gt.cydTq3ArEsbPLxQ.mHOGuCgfC.0wh8PHueVA7DanEjsOABTtAO
    // secret: $2y$10$19anRQcaFNkHt6XYjvu5deK7iJZvW8J1.o/45P./EbhCD2fG2.mOO

}

function handleObtainToken($response) {
    $username = sanitize_input($_POST["username"]);
    $password = sanitize_input($_POST["password"]);

    if (empty($username)) throw new Exception("username field was left empty", 400);
    if (empty($password)) throw new Exception("password field was left empty", 400);

    $hashedPassword = getStoredPassword($username);

    /* manual hash password */
    // $response['hash'] = password_hash($password, PASSWORD_DEFAULT);
    // return $response;

    if (!password_verify($password, $hashedPassword)) throw new Exception("incorrect password", 401);

    $jwt = generateJWT($username);

    $response['data'] = $jwt;

    return $response;
}

function getJWTFromHeader() {
    $headers = getallheaders();

    if (!isset($headers['Authorization'])) throw new Error("Authorization header missing", 401);

    $authHeader = $headers['Authorization'];

    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) throw new Error("Invalid Authorization header format", 400);

    return $matches[1];
}

function validateAndExtractPayloadFromJWT($jwt) {
    // "header.payload.signature";

    $parts = explode('.', $jwt);

    if (count($parts) != 3) throw new Error("Incorrect formatting of JWT", 400);

    $secret = "not_safe_for_production";

    $signature = hash_hmac('sha256', "$parts[0].$parts[1]", $secret, true);
    $signatureEncoded = base64UrlEncode($signature);

    if ($signatureEncoded != $parts[2]) throw new Error("Token has been tampered with", 400);

    // note: json_decode will return PHP object instead of associate array unless 2nd arg is "true"
    $decodedPayload = json_decode(base64UrlDecode($parts[1]), true);

    return $decodedPayload;
}

function isTokenExpired($payload) {
    return $payload['expiry'] < time();
}

function handleAuthentication($response) {
    $jwt = getJWTFromHeader();

    $payload = validateAndExtractPayloadFromJWT($jwt);

    if (isTokenExpired($payload)) throw new Error("Token has expired", 400);

    $response['data'] = $payload;
    return $response;
}