<?php
$xmlArray = array();
foreach ($results as $result) {
	$xmlArray['MISP']['Attribute'][] = $result['Attribute'];
}

$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
