<?php

require_once("./utils.php");

$uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

$response = [];

try {

    switch ($method | $uri) {
        case($method == 'POST' && $uri == '/api/token'):

            $response = handleObtainToken($response);

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

    if (!password_verify($password, $hashedPassword)) throw new Exception("incorrect password", 401);

    $jwt = generateJWT($username);

    $response['data'] = $jwt;

    return $response;
}