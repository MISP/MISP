<?php
$jsonArray = array();
foreach ($results as $k => $v) {
    unset(
            $results[$k]['Event'],
            $results[$k]['Attribute']['value1'],
            $results[$k]['Attribute']['value2']
    );
    $jsonArray['response']['Attribute'][] = $results[$k]['Attribute'];
}
echo json_encode($jsonArray);
