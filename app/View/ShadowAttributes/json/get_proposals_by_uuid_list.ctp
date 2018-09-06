<?php

foreach ($result as &$temp) {
    unset($temp['ShadowAttribute']['id']);
    unset($temp['ShadowAttribute']['email']);
    unset($temp['ShadowAttribute']['value1']);
    unset($temp['ShadowAttribute']['value2']);
    $temp['ShadowAttribute']['Org'] = $temp['Org'];
    $temp['ShadowAttribute']['EventOrg'] = $temp['EventOrg'];
    // hide the org field is we are not in showorg mode
    if (!Configure::read('MISP.showorg') && !$isAdmin) {
        unset($temp['ShadowAttribute']['Org']);
        unset($temp['ShadowAttribute']['EventOrg']);
    }
    $temp = array('ShadowAttribute' => $temp['ShadowAttribute']);
}
echo json_encode($result);
