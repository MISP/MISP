<?php
    if (!isset($data['requirement']) || $data['requirement']) {
        echo $data['html'] ?? 'No HTML passed';
    }
?>
