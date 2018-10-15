<?php
$xmlArray = array();
foreach ($attributes as $key => $attribute) {
    // rearrange things to be compatible with the Xml::fromArray()
    $attributes[$key] = $attributes[$key]['Attribute'];

    // cleanup the array from things we do not want to expose
    unset($attributes[$key]['Event']);
    unset($attributes[$key]['value1']);
    unset($attributes[$key]['value2']);
}

// display the XML to the user
$xmlArray['response']['Attribute'] = $attributes;
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
?><!--
Please note that this XML page is a representation of the /attributes/index page.
Because the /attributes/index page is paginated you will have a limited number of results.

You can for example ask: /attributes/index/limit:999.xml to get the 999 first records.
(A maximum has been set to 9999)


To export all the attributes at once, with their events, use the export functionality.
 -->
