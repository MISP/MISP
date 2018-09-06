<?php
$xmlArray = array();
foreach ($results as $k => $v) {
    unset(
            $results[$k]['Event'],
            $results[$k]['Attribute']['value1'],
            $results[$k]['Attribute']['value2']
    );
    $xmlArray['response']['Attribute'][] = $results[$k]['Attribute'];
}
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
