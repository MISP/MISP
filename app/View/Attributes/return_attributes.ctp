<?php
$xmlArray = array();
foreach ($results as $k => $v) {
    unset(
            $results[$k]['value1'],
            $results[$k]['value2']
    );
    $xmlArray['response']['Attribute'][] = $results[$k];
}
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
