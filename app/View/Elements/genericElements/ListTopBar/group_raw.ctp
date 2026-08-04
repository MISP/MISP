<?php
    $html = '';
    if (!isset($data['requirement']) || $data['requirement']) {
        foreach ($data['children'] as $child) {
            $html .= empty($child['html']) ? '' : $child['html'];  // this has to be sanitised beforehand!
        }
    }
    echo $html;
?>
