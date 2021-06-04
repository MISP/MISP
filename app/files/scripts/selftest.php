<?php
$results = ['phpversion' => phpversion()];
foreach (json_decode($argv[1], true) as $extension) {
    $results['extensions'][$extension] = phpversion($extension);
}
echo json_encode($results);
