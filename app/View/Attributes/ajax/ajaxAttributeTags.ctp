<?php
    $mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id']));
    echo $this->element(
        'ajaxTags',
        array(
            'attributeId' => $attributeId,
            'tags' => $attributeTags,
            'tagAccess' => ($isSiteAdmin || $mayModify),
            'localTagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id'] || (int)$me['org_id'] === Configure::read('MISP.host_org_id')),
            'scope' => 'attribute'
        )
    );
?>
