<?php
$xmlArray = array();
//
// cleanup the array from things we do not want to expose
//
if (isset($proposal['ShadowAttribute']['id'])) {
    $temp = $proposal['ShadowAttribute'];
    unset($proposal['ShadowAttribute']);
    $proposal['ShadowAttribute'][0] = $temp;
    unset($temp);
}
$xmlArray['response']['ShadowAttribute'] = array();
foreach ($proposal as &$temp) {
    unset($temp['ShadowAttribute']['email']);
    unset($temp['ShadowAttribute']['value1']);
    unset($temp['ShadowAttribute']['value2']);
    $temp['ShadowAttribute']['Org'] = $temp['Org'];
    $temp['ShadowAttribute']['EventOrg'] = $temp['EventOrg'];
    // hide the org field is we are not in showorg mode
    unset($temp['ShadowAttribute']['org_id']);
    unset($temp['ShadowAttribute']['org']);
    unset($temp['ShadowAttribute']['event_org_id']);
    if (!Configure::read('MISP.showorg') && !$isAdmin) {
        unset($temp['ShadowAttribute']['Org']);
        unset($temp['ShadowAttribute']['EventOrg']);
    }
    $xmlArray['response']['ShadowAttribute'][] = $temp['ShadowAttribute'];
}

// display the XML to the user
$xmlObject = Xml::fromArray($xmlArray, array('format' => 'tags'));
echo $xmlObject->asXML();
