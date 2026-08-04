<?php
    $body = str_replace('$password', $password, $body);
    $body = str_replace('$username', $user['User']['email'], $body);
    $body = str_replace('\n', PHP_EOL, $body);
    $resolveVars = [
        '$contact' => 'MISP.contact',
        '$org' => 'MISP.org',
        '$misp' => 'MISP.baseurl'
    ];
    foreach ($resolveVars as $k => $v) {
        $v = Configure::read($v);
        $body= str_replace($k, $v, $body);
    }
    echo $body;
