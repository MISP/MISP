<?php
$xmlArray = array();

// cleanup the array from things we do not want to expose
// remove value1 and value2 from the output
unset($attribute['Attribute']['value1']);
unset($attribute['Attribute']['value2']);

// hide the private fields is we are not in sync mode
if ('true' != Configure::read('CyDefSIG.sync')) {
	unset($attribute['Attribute']['private']);
	unset($attribute['Attribute']['cluster']);
	unset($attribute['Attribute']['communitie']);
	unset($attribute['Attribute']['category_order']);
}
// hide the org field is we are not in showorg mode
if ('true' != Configure::read('CyDefSIG.showorg') && !$isAdmin) {
	unset($attribute['Attribute']['org']);
}

// display the XML to the user
$xmlArray['response']['Attribute'][] = $attribute['Attribute'];
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
