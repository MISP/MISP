<?php
$response = array();
// remove password to output and Server
$response['User'][]['email'] = $user['User']['email'];
$response['User'][]['authkey'] = $user['User']['authkey'];
$response['Organisation'] = $user['Organisation'];
$response['Role'] = $user['Role'];
echo (json_encode($response));
