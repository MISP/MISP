<?php

$attribute = Hash::extract($row, 'Attribute');
$event = Hash::extract($row, 'Event');
$mayModify = ($isSiteAdmin || ($isAclModify && $event['user_id'] == $me['id'] && $event['org_id'] == $me['org_id']) || ($isAclModifyOrg && $event['orgc_id'] == $me['org_id']));
echo $this->element('galaxyQuickViewNew', array(
    'mayModify' => $mayModify,
    'isAclTagger' => $isAclTagger,
    'data' => (!empty($attribute['Galaxy']) ? $attribute['Galaxy'] : array()),
    'event' => ['Event' => $event],
    'target_id' => $attribute['id'],
    'target_type' => 'attribute',
));
