<?php
$xmlArray = array();
//
// cleanup the array from things we do not want to expose
//
$jsonArray['ShadowAttribute'] = array();
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
    $jsonArray['ShadowAttribute'][] = $temp['ShadowAttribute'];
}

echo json_encode($jsonArray);
