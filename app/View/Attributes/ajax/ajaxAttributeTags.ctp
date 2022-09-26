<?php
echo $this->element('ajaxTags', [
    'attributeId' => $attributeId,
    'tags' => $attributeTags,
    'tagAccess' => ($isSiteAdmin || $mayModify),
    'localTagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id'] || (int)$me['org_id'] === Configure::read('MISP.host_org_id')),
    'scope' => 'attribute'
]);

