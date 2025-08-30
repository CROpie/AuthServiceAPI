<?php

require_once("./sanitizeinput.php");

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

function handleObtainToken($response) {
    $username = sanitize_input($_POST["username"]);
    $password = sanitize_input($_POST["password"]);

    if (empty($username)) throw new Exception("username field was left empty", 404);

    // swap with query database
    $data = file_get_contents('database.json');
    $users = json_decode($data, true);

    $found = false;
    $hashedPassword;

    foreach ($users as $user) {
        if ($user['username'] === $username) {
            $found = true;
            $hashedPassword = $user['hashedPassword'];
        }
    }

    if (!$found) throw new Exception("cannot find user", 404);

    // $hash = password_hash($password, PASSWORD_DEFAULT);
    // password: $2y$10$Gt.cydTq3ArEsbPLxQ.mHOGuCgfC.0wh8PHueVA7DanEjsOABTtAO
    // secret: $2y$10$19anRQcaFNkHt6XYjvu5deK7iJZvW8J1.o/45P./EbhCD2fG2.mOO

    if (!password_verify($password, $hashedPassword)) throw new Exception("incorrect password", 404);

    $response['data'] = "successfully authenticated";
    return $response;
}