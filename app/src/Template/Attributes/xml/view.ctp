<?php
App::uses('Xml', 'Utility');
$xmlObject = Xml::fromArray($response, array('format' => 'tags'));
echo($xmlObject->asXml());
