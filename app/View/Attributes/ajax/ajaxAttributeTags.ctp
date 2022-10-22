<?php
echo $this->element('ajaxTags', [
    'attributeId' => $attributeId,
    'tags' => $attributeTags,
    'tagAccess' => $isSiteAdmin || $mayModify,
    'localTagAccess' => $isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['org_id'] || $hostOrgUser,
    'scope' => 'attribute'
]);

