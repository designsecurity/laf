<?php

$client = new GuzzleHttp\Client([
    'base_uri' => 'https://localhost',
    'http_errors' => false,
    'protocols' => ["https"],
    'verify' => false
]);


$response = $client->get('https://localhost/index.html');

$data = $response->getBody()->getContents();


